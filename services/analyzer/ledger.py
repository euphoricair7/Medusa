from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("medusa-analyzer")

"""
pending_inspect -> run checkpointctl later -> pending_post -> done | failed
"""
STATES = frozenset({"pending_inspect", "pending_post", "done", "failed"})

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class Ledger:
    """
    Ledger tracks the analyzer work flow and saves in the 
    directory /var/lib/medusa-analyzer.

    The layout of the ledger is as follows:
      <ledger_root>/<sha256>/
        meta.json
        report.json     
        state          
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def entry_dir(self, content_sha256: str) -> Path:
        return self.root / content_sha256

    def state_path(self, content_sha256: str) -> Path:
        return self.entry_dir(content_sha256) / "state"

    def meta_path(self, content_sha256: str) -> Path:
        return self.entry_dir(content_sha256) / "meta.json"

    def report_path(self, content_sha256: str) -> Path:
        return self.entry_dir(content_sha256) / "report.json"

    def get_state(self, content_sha256: str) -> str | None:
        p = self.state_path(content_sha256)
        if not p.is_file():
            return None
        return p.read_text(encoding="utf-8").strip()

    def set_state(self, content_sha256: str, state: str) -> None:
        if state not in STATES:
            raise ValueError(f"invalid state: {state}")
        d = self.entry_dir(content_sha256)
        d.mkdir(parents=True, exist_ok=True)
        self.state_path(content_sha256).write_text(state + "\n", encoding="utf-8")

    def write_meta(self, content_sha256: str, meta: dict[str, Any]) -> None:
        d = self.entry_dir(content_sha256)
        d.mkdir(parents=True, exist_ok=True)
        self.meta_path(content_sha256).write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def read_meta(self, content_sha256: str) -> dict[str, Any]:
        return json.loads(self.meta_path(content_sha256).read_text(encoding="utf-8"))

    def write_report(self, content_sha256: str, report: dict[str, Any]) -> None:
        d = self.entry_dir(content_sha256)
        d.mkdir(parents=True, exist_ok=True)
        self.report_path(content_sha256).write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )

    def read_report(self, content_sha256: str) -> dict[str, Any]:
        return json.loads(self.report_path(content_sha256).read_text(encoding="utf-8"))

    def ensure_entry(
        self,
        *,
        content_sha256: str,
        host_path: str,
        container_path: str,
        event_id: str | None = None,
    ) -> str:
        """
        Create entry if missing. Return current state.
        New entries start at pending_inspect.
        """
        state = self.get_state(content_sha256)
        if state is not None:
            return state

        now = datetime.now(timezone.utc).isoformat()
        self.write_meta(
            content_sha256,
            {
                "sha256": content_sha256,
                "host_path": host_path,
                "container_path": container_path,
                "event_id": event_id,
                "created_at": now,
                "updated_at": now,
            },
        )
        self.set_state(content_sha256, "pending_inspect")
        logger.info("ledger: new entry %s → pending_inspect", content_sha256[:12])
        return "pending_inspect"