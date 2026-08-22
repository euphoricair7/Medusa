from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from kubernetes.client.rest import ApiException
from models.forensic import ForensicEvent, ForensicCheckpointStatus
from forensic_chain import (
    build_forensic_snapshot_chain_body,
    create_forensic_snapshot_chain,
    make_idempotency_key,
    _sanitize_cr_name,
    forensic_snapshot_chain_exists,
)
from config import settings
import logging

logger = logging.getLogger(__name__)

ALERT_PRIORITY = ["critical", "error", "warning", "notice", "info", "debug"]

def priority_ok(priority: str) -> bool:
    p = priority.lower()
    return p in ALERT_PRIORITY and ALERT_PRIORITY.index(p) <= ALERT_PRIORITY.index(settings.min_alert_priority)

def extract_k8s_context(raw_alert: dict) -> tuple[str, str, str | None]:
    fields = raw_alert.get("output_fields") or {}
    namespace = fields.get("k8s.ns.name") or fields.get("namespace") or "default"
    pod_name = fields.get("k8s.pod.name") or fields.get("pod.name")
    container_name = fields.get("container.name") or fields.get("k8s.container.name")
    if not pod_name:
        raise ValueError("missing k8s.pod.name in Falco output_fields")
    return namespace, pod_name, container_name

async def find_by_idempotency_key(session: AsyncSession, key: str) -> ForensicEvent | None:
    result = await session.execute(
        select(ForensicEvent).where(ForensicEvent.idempotency_key == key)
    )
    return result.scalars().first()

#Submit the forensic snapshot chain CR
#for a new or existing event
async def _submit_forensic_snapshot_chain_cr(
    session: AsyncSession,
    *,
    event: ForensicEvent,
    namespace: str,
    pod_name: str,
    container_name: str,
    rule: str,
    priority: str,
) -> ForensicEvent:
    cr_name = _sanitize_cr_name(str(event.id), rule)
    burst = priority.lower() in ("critical", "error")

    body = build_forensic_snapshot_chain_body(
        cr_name=cr_name,
        target_namespace=namespace,
        pod_name=pod_name,
        container_name=container_name,
        forensic_event_id=str(event.id),
        burst=burst,
    )
    try:
        created_name = create_forensic_snapshot_chain(body)
        event.operator_cr_name = created_name
        event.phase = ForensicCheckpointStatus.queued.value
        if isinstance(event.raw_report, dict) and "cr_create_error" in event.raw_report:
            event.raw_report = None
    except ApiException as exc:
        event.phase = ForensicCheckpointStatus.failed.value
        event.raw_report = {"cr_create_error": str(exc)}
        logger.error("Failed to create forensic snapshot chain: %s", event.id)
        await session.commit()
        raise
    except Exception as exc:
        event.phase = ForensicCheckpointStatus.failed.value
        event.raw_report = {"cr_create_error": str(exc)}
        raise

    await session.commit()
    await session.refresh(event)
    return event

async def process_trigger_forensic(
    session: AsyncSession,
    *,
    alert_id= None,
    rule: str,
    priority: str,
    raw_alert: dict | None = None,
    trigger_source: str | None = None,
    # manual overrides — used when raw_alert has no output_fields
    namespace: str | None = None,
    pod_name: str | None = None,
    container_name: str | None = None,
) -> ForensicEvent | None:
    if trigger_source != "manual" and not priority_ok(priority):
        return None
    
    #Required for forensic idempotency
    if alert_id is None:
        raise ValueError("alert_id is required")

    if namespace and pod_name:
        namespace, pod_name, container_name = namespace, pod_name, container_name
    elif raw_alert:
        namespace, pod_name, container_name = extract_k8s_context(raw_alert)
    else:
        raise ValueError("missing kubernetes context")

    idem_key = make_idempotency_key(alert_id, namespace, pod_name, container_name)

    existing = await find_by_idempotency_key(session, idem_key)
    if existing:
        cr_name = existing.operator_cr_name
        cr_exists = (bool(cr_name) and forensic_snapshot_chain_exists(settings.fsc_cr_namespace, cr_name))

        status_check  = existing.phase in (
            ForensicCheckpointStatus.queued.value, 
            ForensicCheckpointStatus.in_progress.value,
            ForensicCheckpointStatus.success.value,
        )
        
        if status_check and cr_exists:
            return existing

        #Reset checkpoint location to allow for new CR creation
        existing.checkpoint_location = None

        #CR missing -> create CR on same row
        return await _submit_forensic_snapshot_chain_cr(
            session,
            event=existing,
            namespace=namespace,
            pod_name=pod_name,
            container_name=container_name,
            rule=rule,
            priority=priority,
        )
        
    event = ForensicEvent(
        alert_id=alert_id,
        pod_name=pod_name,
        namespace=namespace,
        container_name=container_name,
        phase=ForensicCheckpointStatus.pending.value,
        trigger_source=trigger_source,
        triggered_rule=rule,
        triggered_priority=priority,
        raw_alert=raw_alert,
        idempotency_key=idem_key,
    )
    session.add(event)
    await session.flush()  # get event.id before CR create

    return await _submit_forensic_snapshot_chain_cr(
        session,
        event=event,
        namespace=namespace,
        pod_name=pod_name,
        container_name=container_name,
        rule=rule,
        priority=priority,
    )



