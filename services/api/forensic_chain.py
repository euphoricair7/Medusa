import hashlib
import re
from kubernetes.client.rest import ApiException
from k8s.client import get_k8s_client, FSC_GROUP, FSC_VERSION, MEDUSA_MANAGED_LABEL, MEDUSA_MANAGED_VALUE
from config import settings
import uuid

def _sanitize_cr_name(event_id: str, rule: str) -> str:
    suffix = event_id.replace("-", "")[:8]
    rule_bit = re.sub(r"[^a-z0-9-]", "-", rule.lower())[:20].strip("-")
    return f"fsc-{rule_bit}-{suffix}"[:63]


def _build_selector_for_pod(namespace: str, pod_name: str) -> dict:
    k8s = get_k8s_client()
    pod = k8s.get_pod(namespace, pod_name)
    labels = pod.metadata.labels or {}
    if "app" in labels:
        return {"matchLabels": {"app": labels["app"]}}
    if labels:
        k, v = next(iter(labels.items()))
        return {"matchLabels": {k: v}}
      
    """
    Incase of Label-less pods, k8s automatically handles
    pod name generation.
    """
    return {"matchLabels": {"kubernetes.io/metadata.name": pod_name}}


def build_forensic_snapshot_chain_body(
    *,
    cr_name: str,
    target_namespace: str,
    pod_name: str,
    container_name: str | None,
    forensic_event_id: str,
    burst: bool = False,
) -> dict:
  max_snapshots = 5 if burst else settings.fsc_default_max_snapshots

  body = {
    "apiVersion": f"{FSC_GROUP}/{FSC_VERSION}",
    "kind": "ForensicSnapshotChain",
    "metadata": {
      "name": cr_name,
      "namespace": settings.fsc_cr_namespace,
      "labels": {
        "medusa.criu.org/forensic-event-id": str(forensic_event_id),
        MEDUSA_MANAGED_LABEL: MEDUSA_MANAGED_VALUE,
      },
    },
    "spec": {
      "namespace": target_namespace,
      "selector": _build_selector_for_pod(target_namespace, pod_name),
      "capture": {
        "interval": settings.fsc_default_interval,
        "maxSnapshots": max_snapshots,
        "maxDuration": settings.fsc_default_max_duration,
      },
      "integrity": {
        "hashAlgorithm": settings.fsc_integrity_algorithm,
      },
      "postSnapshotAction": "None",
    },
  }
  if container_name:
    body["spec"]["containerNames"] = [container_name]
  return body

def create_forensic_snapshot_chain(body: dict) -> str:
    k8s = get_k8s_client()
    ns = body["metadata"]["namespace"]
    created = k8s.create_forensic_snapshot_chain(ns, body)
    return created["metadata"]["name"]

def make_idempotency_key(alert_id: uuid.UUID, namespace: str, pod_name: str, container_name: str | None,) -> str:
    raw = f"{alert_id}:{namespace}:{pod_name}:{container_name or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()

def forensic_snapshot_chain_exists(namespace: str, chain_cr_name: str) -> bool:
  k8s = get_k8s_client()
  try:
    k8s.get_forensic_snapshot_chain(namespace, chain_cr_name)
    return True
  except ApiException as e:
    if e.status == 404:
      return False
    raise