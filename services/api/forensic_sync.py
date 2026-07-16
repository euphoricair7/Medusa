import asyncio
import logging
import uuid
from datetime import datetime, timezone
from kubernetes import watch
from kubernetes.client.rest import ApiException
from sqlalchemy import select
from config import settings
from db.session import SessionLocal
from k8s.client import get_k8s_client, FSC_GROUP, FSC_VERSION, FSC_PLURAL, FORENSIC_EVENT_LABEL
from models.forensic import ForensicEvent, ForensicCheckpointStatus

logger = logging.getLogger(__name__)

#mapping of operator phase to medusa phase
OPERATOR_TO_MEDUSA = {
    "Pending": ForensicCheckpointStatus.queued.value,
    "Running": ForensicCheckpointStatus.in_progress.value,
    "Completed": ForensicCheckpointStatus.success.value,
    "Failed": ForensicCheckpointStatus.failed.value,
}

#build raw report from forensic snapshot chain
def _build_raw_report(fsc: dict) -> dict:
    """Persist operator status; include manifest/signature fields."""
    report = {
        "operator_phase": fsc.get("status"),
        "snapshot_count": status.get("snapshotCount"),
        "snapshot_chain_records": status.get("snapshotChainRecords", []),
        "conditions": status.get("conditions", []),
        "error_message": status.get("errorMessage"),
        "start_time": status.get("startTime"),
        "completion_time": status.get("completionTime"),
    }
    
    #checking for signed manifest and signature
    if "signedManifest" in status:
        report["signed_manifest"] = status["signedManifest"]
    if "manifestSignature" in status:
        report["manifest_signature"] = status["manifestSignature"]
    return report

#get checkpoint location from snapshot chain
def _get_checkpoint_location(records: list) -> str | None:
    if not records:
        return None
    # use latest snapshot in the chain
    last = records[-1]
    return last.get("checkpointPath")

#sync CR to database
async def sync_cr_to_db(cr: dict) -> None:
    metadata = cr.get("metadata") or {}
    labels = metadata.get("labels") or {}
    event_id_str = labels.get(FORENSIC_EVENT_LABEL)
    if not event_id_str:
        return
    status = cr.get("status") or {}
    operator_phase = status.get("phase")
    if not operator_phase:
        return
    medusa_phase = OPERATOR_TO_MEDUSA.get(operator_phase, operator_phase.lower())
    records = status.get("snapshotChainRecords") or []
    checkpoint_location = _get_checkpoint_location(records)
    raw_report = _build_raw_report(cr)
    async with SessionLocal() as session:
        result = await session.execute(
            select(ForensicEvent).where(ForensicEvent.id == uuid.UUID(event_id_str))
        )
        event = result.scalars().first()
        if not event:
            logger.warning("CR references unknown forensic event %s", event_id_str)
            return
        event.phase = medusa_phase
        event.updated_at = datetime.now(timezone.utc)
        if checkpoint_location:
            event.checkpoint_location = checkpoint_location
        event.raw_report = raw_report
        if metadata.get("name"):
            event.operator_cr_name = metadata["name"]
        await session.commit()
        logger.info(
            "Synced forensic event %s → phase=%s cr=%s",
            event_id_str, medusa_phase, metadata.get("name"),
        )

#reconcile all Forensic Snapshot Chains (FSCs) on startup
async def reconcile_all_fscs() -> None:
    api = get_k8s_client()
    ns = settings.fsc_cr_namespace
    try:
        resp = k8s.list_forensic_snapshot_chains(ns, label_selector=f"{FORENSIC_EVENT_LABEL}")
    except ApiException as e:
        logger.error("Failed to list FSCs for reconcile: %s", e)
        return
    for item in resp.get("items", []):
        await sync_cr_to_db(item)

#watch forensic snapshot chains blocking
def _watch_forensic_snapshot_chains_blocking() -> None:
    """Runs in a thread — kubernetes Watch is blocking."""
    api = get_custom_objects_api()
    w = watch.Watch()
    ns = settings.fsc_cr_namespace
    while True:
        try:
            for event in w.stream(
                api.list_namespaced_custom_object,
                group=FSC_GROUP,
                version=FSC_VERSION,
                namespace=ns,
                plural=FSC_PLURAL,
                label_selector=FORENSIC_EVENT_LABEL,  # label exists on object
                timeout_seconds=60,
            ):
                cr = event["object"]
                asyncio.run(sync_cr_to_db(cr))  # see note below
        except ApiException as e:
            logger.error("Watch error: %s", e)
        except Exception as e:
            logger.error("Watch loop error: %s", e)

#run forensic sync
async def run_forensic_sync(stop_event: asyncio.Event) -> None:
    api = get_custom_objects_api()
    ns = settings.fsc_cr_namespace
    await reconcile_all_fscs()

    while not stop_event.is_set():
        try:
            resp = k8s.list_forensic_snapshot_chains(
                ns, 
                label_selector=f"{FORENSIC_EVENT_LABEL}"
            )
            for item in resp.get("items", []):
                await sync_cr_to_db(item)
        except Exception as e:
            logger.error("Poll error: %s", e)
        await asyncio.sleep(5)

