import asyncio
import logging
import uuid
from datetime import datetime, timezone
from kubernetes.client.rest import ApiException
from sqlalchemy import select
from config import settings
from db.session import SessionLocal
from k8s.client import get_k8s_client, FORENSIC_EVENT_LABEL, MEDUSA_FSC_LABEL_SELECTOR
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
def _build_operator_raw_report(fsc: dict) -> dict:
    """Persist operator status; include manifest/signature fields."""
    status = fsc.get("status") or {}
    report = {
        "operator_phase": status.get("phase"),
        "snapshot_count": status.get("snapshotCount"),
        "snapshot_chain_records": status.get("snapshotChainRecords", []),
        "conditions": status.get("conditions", []),
        "error_message": status.get("errorMessage"),
        "start_time": status.get("startTime"),
        "completion_time": status.get("completionTime"),
    }
    
    #checking for signed manifest and signature
    if signed_manifest := status.get("signedManifest"):
        report["signed_manifest"] = signed_manifest
    if manifest_signature := status.get("manifestSignature"):
        report["manifest_signature"] = manifest_signature
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
    records = status.get("snapshotChainRecords") or []
    checkpoint_location = _get_checkpoint_location(records)
    operator_raw_report = _build_operator_raw_report(cr)
    async with SessionLocal() as session:
        result = await session.execute(
            select(ForensicEvent).where(ForensicEvent.id == uuid.UUID(event_id_str))
        )
        event = result.scalars().first()
        if not event:
            logger.warning("CR references unknown forensic event %s", event_id_str)
            return
        if operator_phase:
            event.phase = OPERATOR_TO_MEDUSA.get(operator_phase, operator_phase.lower())
        event.updated_at = datetime.now(timezone.utc)
        if checkpoint_location:
            event.checkpoint_location = checkpoint_location
        rr = dict(event.raw_report) if isinstance(event.raw_report, dict) else {}
        rr["operator"] = operator_raw_report
        event.raw_report = rr
        if metadata.get("name"):
            event.operator_cr_name = metadata["name"]
        await session.commit()
        logger.info(
            "Synced forensic event %s → phase=%s cr=%s",
            event_id_str, event.phase, metadata.get("name"),
        )


#iterate over all Medusa FSCs in the namespace
def _iter_medusa_fscs(api, namespace: str):
    resp = api.list_forensic_snapshot_chains(
        namespace=namespace,
        label_selector=MEDUSA_FSC_LABEL_SELECTOR,
    )
    items = resp.get("items", [])
    if not items:
        # CRs created before managed label was added
        resp = api.list_forensic_snapshot_chains(namespace=namespace)
        items = [
            item for item in resp.get("items", [])
            if FORENSIC_EVENT_LABEL
            in ((item.get("metadata") or {}).get("labels") or {})
        ]
    for item in items:
        yield item
            

#reconcile all Forensic Snapshot Chains (FSCs) on startup
async def reconcile_all_fscs() -> None:
    api = get_k8s_client()
    ns = settings.fsc_cr_namespace
    try:
        for item in _iter_medusa_fscs(api, ns):
            await sync_cr_to_db(item)
    except ApiException as e:
        logger.error("Failed to list FSCs for reconcile: %s", e)

#run forensic sync
async def run_forensic_sync(stop_event: asyncio.Event) -> None:
    api = get_k8s_client()
    ns = settings.fsc_cr_namespace
    await reconcile_all_fscs()
    while not stop_event.is_set():
        try:
            for item in _iter_medusa_fscs(api, ns):
                await sync_cr_to_db(item)
        except Exception as e:
            logger.error("Poll error: %s", e)
        await asyncio.sleep(5)

