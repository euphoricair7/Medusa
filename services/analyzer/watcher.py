from __future__ import annotations
import logging
from pathlib import Path
import os
import json
import subprocess
import time
import argparse
import httpx
from datetime import datetime, timezone
from kubernetes import client, config
from ledger import Ledger, sha256_file


logger = logging.getLogger("medusa-analyzer")

# wait for the file to stop growing before processing it
STABLE_SECONDS = 2.0
STABLE_POLL = 0.25

# how often the watcher scans the checkpoint directory
POLL_SECONDS = 5.0
CHECKPOINTCTL_TIMEOUT_SECONDS = 300.0

# CR constants
FSC_GROUP = "criu.org"
FSC_VERSION = "v1"
FSC_PLURAL = "forensicsnapshotchains"
MEDUSA_MANAGED_SELECTOR = "medusa.criu.org/managed=true"
FORENSIC_EVENT_LABEL = "medusa.criu.org/forensic-event-id"

def check_stable_size(path: Path, stable_seconds: float = STABLE_SECONDS) -> bool:
    """
    Return True if the file size has stopped growing for stable_seconds.
    Return False in other cases
    """

    try: 
        if not path.is_file():
            return False
        last_size= path.stat().st_size
    except OSError:
        return False

    last_change = time.monotonic()
    while True:
        time.sleep(STABLE_POLL)
        try:
            if not path.is_file():
                return False
            size = path.stat().st_size
        except OSError:
            return False

        now = time.monotonic()
        if size !=last_size:
            last_size = size
            last_change = now
            continue
        if (now - last_change) >= stable_seconds:
            return True

def check_file_name(path: Path) -> bool:
    name = path.name
    if name.startswith("."):
        return False
    if not name.endswith(".tar"):
        return False
    return True

def list_tar_directory(watch_dir:Path)-> list[Path]:
    """Returns .tar paths in watch_dir (non-recursive)"""
    if not watch_dir.is_dir():
        return []
    return sorted(
        p for p in watch_dir.iterdir() 
        if p.is_file() and check_file_name(p)
    )

def normalize_to_host_path(
    container_path: Path,
    container_prefix: str,
    host_prefix: str,
) -> str:
    """
    /checkpoints/foo.tar → /var/lib/kubelet/checkpoints/foo.tar
    (used later when matching CR checkpointPath)
    """
    raw = str(container_path.resolve())
    prefix = container_prefix.rstrip("/")
    host = host_prefix.rstrip("/")
    if raw == prefix or raw.startswith(prefix + "/"):
        return host + raw[len(prefix) :]
    return raw

def get_event_id_for_checkpoint(
    host_path: str,
    *,
    namespace: str = "default",
    ) -> str | None:
    kubeconfig = os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))
    if os.path.isfile(kubeconfig):
        config.load_kube_config(config_file=kubeconfig)
    else:
        config.load_incluster_config()
    custom_objects = client.CustomObjectsApi()

    fsc_chains = custom_objects.list_namespaced_custom_object(
        group=FSC_GROUP,
        version=FSC_VERSION,
        plural=FSC_PLURAL,
        namespace=namespace,
        label_selector=MEDUSA_MANAGED_SELECTOR,
    )
    items = fsc_chains.get("items", [])
    for chain in items:
        status = chain.get("status") or {}
        phase = status.get("phase")
        if phase != "Completed":
            continue

        records = status.get("snapshotChainRecords", [])
        for record in records:
            checkpoint_path = record.get("checkpointPath")
            if checkpoint_path is not None and checkpoint_path == host_path:
                labels = (chain.get("metadata") or {}).get("labels") or {}
                return labels.get(FORENSIC_EVENT_LABEL)    
    return None

def post_analysis(
    *,
    medusa_api_url: str,
    event_id: str,
    host_path: str,
    report: dict,
    node_name: str | None,
    post_timeout_seconds: float,
) -> None:
    """
    Posts analysis to Medusa API
    """
    api_url = f"{medusa_api_url.rstrip('/')}/forensic-checkpoint/{event_id}/analysis"
    body = {
        "checkpoint_path": host_path,
        "node_name": node_name,
        "analyzer": "checkpointctl",
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "report": report,
    }
    logger.info("POST %s (path=%s)", api_url, host_path)
    try:
        with httpx.Client(timeout=post_timeout_seconds) as client:
            resp = client.post(api_url, json=body)
    except httpx.HTTPError as e:
        raise RuntimeError(f"POST failed: {e}") from e

    if resp.status_code < 200 or resp.status_code >= 300:
        raise RuntimeError(
            f"POST failed status={resp.status_code} body={resp.text[:500]}"
        )


def inspect_checkpoint(
    checkpoint_artifact_path: Path,
    *,
    checkpointctl_bin: str,
    timeout_seconds: float = CHECKPOINTCTL_TIMEOUT_SECONDS,
) -> dict:
    """Run checkpointctl inspect; return JSON. Raise RuntimeError on failure."""
    cmd = [
        checkpointctl_bin,
        "inspect",
        "--format", "json",
        "--ps-tree-cmd",
        "--files",
        "--sockets",
        "--stats",
        "--mounts",
        "--metadata",
        str(checkpoint_artifact_path),
    ]
    logger.info("running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if result.returncode !=0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"checkpointctl inspect failed (exit code {result.returncode}): {err}")

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError("checkpointctl inspect returned empty output")
    try:
        parsed_result=json.loads(stdout)
    except json.JSONDecodeError as e:
        return {"raw":stdout}
    
    if isinstance(parsed_result, dict):
        return parsed_result
    
    return {"inspect":parsed_result}

def process_stable_checkpoint(
    path: Path,
    *,
    ledger: Ledger,
    host_path: str,
    event_id: str | None,
    checkpointctl_bin: str,
    medusa_api_url: str,
    node_name: str | None,
    post_timeout_seconds: float,
    content_sha: str,
)-> None:
    state = ledger.ensure_entry(
        content_sha256=content_sha,
        host_path=host_path,
        container_path=str(path.resolve()),
        event_id=event_id,
    )

    if state == "done":
        logger.debug("ledger: already done %s", content_sha[:12])
        return

    if state == "failed":
        logger.info("ledger: previously failed %s, skipping", content_sha[:12])
        return

    if state == "pending_inspect":
        try:
            report = inspect_checkpoint(path, checkpointctl_bin=checkpointctl_bin)
        except (RuntimeError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error("inspect failed for %s: %s", path, e)
            ledger.set_state(content_sha, "failed")
            return
        ledger.write_report(content_sha, report)
        ledger.set_state(content_sha, "pending_post")
        logger.info("ledger: inspect done -> pending_post %s", content_sha[:12])
        state = "pending_post"

    if state == "pending_post":
        if not event_id:
            #with --require-cr flag this won't happen, without it, we should flag it out
            logger.errot("pending_post but there is no event_id for the name %s", host_path)
            return
        
        report = ledger.read_report(content_sha)
        try:
            post_analysis(
                medusa_api_url=medusa_api_url,
                event_id=event_id,
                host_path=host_path,
                report=report,
                node_name=node_name,
                post_timeout_seconds=post_timeout_seconds,
            )
        except (RuntimeError, httpx.HTTPError) as e:
            logger.error("post failed sha=%s: %s (will retry)", content_sha[:12], e)
            return

        ledger.set_state(content_sha, "done")
        logger.info("ledger: marked done %s", content_sha[:12])



def run_poll_loop(
    watch_dir: Path,
    *,
    poll_seconds: float,
    stable_seconds: float,
    container_prefix: str,
    host_prefix: str,
    require_cr: bool,
    ledger: Ledger,
    fsc_namespace: str,
    checkpointctl_bin: str,
    medusa_api_url: str,
    node_name: str | None,
    post_timeout_seconds: float,
) -> None:
    global STABLE_SECONDS
    STABLE_SECONDS = stable_seconds 
    logger.info(
        "polling %s every %.1fs (stable=%.1fs, require_cr=%s)",
        watch_dir,
        poll_seconds,
        stable_seconds,
        require_cr,
    )
    while True:
        for path in list_tar_directory(watch_dir):
            host_path = normalize_to_host_path(path, container_prefix, host_prefix)
            event_id = None
            if require_cr:
                event_id = get_event_id_for_checkpoint(host_path, namespace=fsc_namespace)
                if event_id is None:
                    logger.info("no Completed CR yet for %s, skipping (no ledger write)", host_path)
                    continue

            # Skip finished work before the stable-size wait.
            content_sha = sha256_file(path)
            state = ledger.get_state(content_sha)
            if state in ("done", "failed"):
                logger.debug("skip %s (%s) sha=%s", path, state, content_sha[:12])
                continue

            logger.info("candidate: %s, waiting for stable size", path)
            if not check_stable_size(path, stable_seconds=stable_seconds):
                logger.info("skipped (unstable or vanished): %s", path)
                continue

            process_stable_checkpoint(
                path,
                ledger=ledger,
                host_path=host_path,
                event_id=event_id,
                checkpointctl_bin=checkpointctl_bin,
                medusa_api_url=medusa_api_url,
                node_name=node_name,
                post_timeout_seconds=post_timeout_seconds,
                content_sha=content_sha,
            )
        time.sleep(poll_seconds)

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Medusa analyzer watcher (poll + stable gate)")
    p.add_argument(
        "--watch-dir",
        default=os.environ.get("CHECKPOINT_DIR", "/tmp/checkpoints"),
    )
    p.add_argument(
        "--poll-seconds",
        type=float,
        default=float(os.environ.get("POLL_SECONDS", POLL_SECONDS)),
    )
    p.add_argument(
        "--stable-seconds",
        type=float,
        default=float(os.environ.get("STABLE_SECONDS", STABLE_SECONDS)),
    )
    p.add_argument(
        "--container-prefix",
        default=os.environ.get("CHECKPOINT_CONTAINER_PATH", "/checkpoints"),
        help="Mount path inside the analyzer container",
    )
    p.add_argument(
        "--host-prefix",
        default=os.environ.get(
            "CHECKPOINT_HOST_PREFIX",
            "/var/lib/kubelet/checkpoints",
        ),
        help="Node path as stored on ForensicSnapshotChain status",
    )
    p.add_argument(
        "--require-cr",
        action="store_true",
        help="Only emit when a Completed CR references the host path (needs K8s later)",
    )
    p.add_argument(
        "--ledger-dir",
        default=os.environ.get("LEDGER_DIR", "/var/lib/medusa-analyzer"),
        help="Ledger root",
    )
    p.add_argument(
    "--fsc-namespace",
    default=os.environ.get("FSC_CR_NAMESPACE", "default"),
    help="Namespace of ForensicSnapshotChain CRs",
    )
    p.add_argument(
        "--checkpointctl",
        default=os.environ.get("CHECKPOINTCTL_BIN", "checkpointctl"),
        help="checkpointctl binary path or name on PATH",
    )
    p.add_argument(
    "--medusa-api-url",
    default=os.environ.get("MEDUSA_API_URL", "http://127.0.0.1:8000"),
    help="Base URL of Medusa API (no trailing slash)",
    )
    p.add_argument(
        "--node-name",
        default=os.environ.get("NODE_NAME") or os.environ.get("HOSTNAME"),
        help="Kubernetes node name sent in analysis POST",
    )
    p.add_argument(
        "--post-timeout-seconds",
        type=float,
        default=float(os.environ.get("POST_TIMEOUT_SECONDS", "30")),
    )

    return p.parse_args()

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = parse_args()
    ledger = Ledger(Path(args.ledger_dir))
    watch_dir = Path(args.watch_dir)
    watch_dir.mkdir(parents=True, exist_ok=True)
    try:
        run_poll_loop(
            watch_dir,
            ledger=ledger,
            poll_seconds=args.poll_seconds,
            stable_seconds=args.stable_seconds,
            container_prefix=args.container_prefix,
            host_prefix=args.host_prefix,
            require_cr=args.require_cr,
            fsc_namespace=args.fsc_namespace,
            checkpointctl_bin=args.checkpointctl,
            medusa_api_url=args.medusa_api_url,
            node_name=args.node_name,
            post_timeout_seconds=args.post_timeout_seconds,
        )
    except KeyboardInterrupt:
        logger.info("shutting down")

if __name__ == "__main__":
    main()