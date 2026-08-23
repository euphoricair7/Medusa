import uuid
import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, Depends
from kubernetes.client.rest import ApiException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.session import get_db
from forensic_service import (
    MissingK8sContextError,
    process_trigger_forensic,
    extract_k8s_context,
)
from models.alert import Alert, AlertOut
from models.forensic import (
    ForensicCheckpointManualRequest,
    ForensicCheckpointResponse,
    ForensicEvent,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _k8s_fields_from_falco(alert: dict) -> tuple[str | None, str | None]:
    try:
        namespace, pod_name, _ = extract_k8s_context(alert)
        return namespace, pod_name
    except ValueError:
        return None, None


async def _ingest_alert(
    session: AsyncSession,
    *,
    trigger_source: str,
    rule: str,
    priority: str,
    raw_alert: dict,
    namespace: str | None = None,
    pod_name: str | None = None,
    container_name: str | None = None,
    existing_alert_id: uuid.UUID | None = None,
    new_alert: Alert | None = None,
) -> tuple[Alert, ForensicEvent | None]:
    if existing_alert_id is not None:
        result = await session.execute(
            select(Alert).where(Alert.id == existing_alert_id)
        )
        alert = result.scalars().first()
        if alert is None:
            raise HTTPException(
                status_code=404,
                detail=f"No alert found with alert_id: {existing_alert_id}",
            )
    else:
        session.add(new_alert)
        await session.commit()
        await session.refresh(new_alert)
        alert = new_alert

    event = await process_trigger_forensic(
        session,
        alert_id=alert.id,
        rule=rule,
        priority=priority,
        raw_alert=raw_alert,
        trigger_source=trigger_source,
        namespace=namespace,
        pod_name=pod_name,
        container_name=container_name,
    )
    return alert, event


@router.get(
    "/",
    response_model=list[AlertOut],
    summary="List persisted alerts",
    description="Returns all Falco alerts stored in PostgreSQL.",
    response_description="Array of normalized alert records.",
)
async def get_alerts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Alert).order_by(Alert.received_at.desc())
    )
    alerts = result.scalars().all()
    return alerts


@router.post(
    "/falco",
    summary="Ingest a Falco webhook alert",
    description=(
        "Receives the raw JSON payload from Falco's HTTP output, "
        "normalizes key fields, and persists the alert to PostgreSQL."
    ),
    response_description="Acknowledgement that the alert was accepted and stored.",
    responses={200: {"description": "Alert successfully ingested."}},
)
async def create_falco_alert(alert: dict, db: AsyncSession = Depends(get_db)):
    fields = alert.get("output_fields") or {}
    namespace, pod_name = _k8s_fields_from_falco(alert)

    new_alert = Alert(
        received_at=datetime.utcnow(),
        rule=alert.get("rule", ""),
        priority=alert.get("priority", ""),
        output=alert.get("output", ""),
        container_name=alert.get("output_fields", {}).get("container.name"),
        namespace=namespace,
        pod_name=pod_name,
        image=alert.get("output_fields", {}).get("container.image.repository"),
        tags=alert.get("tags"),
        raw_event=alert,
    )

    try:
        tags = alert.get("tags") or []
        if "medusa" not in tags:
            db.add(new_alert)
            await db.commit()
            await db.refresh(new_alert)
            logger.info(
                "Falco alert saved (id=%s) forensic skipped, not a medusa-tagged alert",
                new_alert.id,
            )
            return {"status": "ok"}
        saved_alert, event = await _ingest_alert(
            db,
            trigger_source="falco",
            rule=new_alert.rule,
            priority=new_alert.priority,
            raw_alert=alert,
            new_alert=new_alert,
        )
    except MissingK8sContextError as e:
        logger.error(
            "Falco alert saved (id=%s) but missing Kubernetes context: %s",
            new_alert.id,
            e,
        )
        return {"status": "ok"}
    except ValueError as e:
        logger.warning(
            "Falco alert saved (id=%s) forensic skipped: %s",
            new_alert.id,
            e,
        )
        return {"status": "ok"}
    except ApiException as e:
        logger.error(
            "Falco alert saved (id=%s) but forensic CR creation failed: status=%s reason=%s",
            new_alert.id,
            e.status,
            e.reason,
        )
        return {"status": "ok"}
    except Exception:
        logger.exception(
            "Falco alert saved (id=%s) but forensic trigger failed",
            new_alert.id,
        )
        return {"status": "ok"}

    if event is None:
        logger.info(
            "Falco alert saved (id=%s) forensic skipped, priority %r below threshold",
            saved_alert.id,
            saved_alert.priority,
        )
    elif event.alert_id != saved_alert.id:
        logger.info(
        "Falco alert saved (id=%s) forensic pod-dedup — reusing event_id=%s "
        "(owned by alert_id=%s) phase=%s operator_cr=%s",
        saved_alert.id,
        event.id,
        event.alert_id,
        event.phase,
        event.operator_cr_name,
        )
    elif _forensic_event_is_reused(event):
        logger.info(
            "Falco alert saved (id=%s) forensic alert-dedup, reusing event_id=%s phase=%s operator_cr=%s",
            saved_alert.id,
            event.id,
            event.phase,
            event.operator_cr_name,
        )
    else:
        logger.info(
            "Falco alert saved (id=%s) forensic queued event_id=%s operator_cr=%s",
            saved_alert.id,
            event.id,
            event.operator_cr_name,
        )

    return {"status": "ok"}


def _forensic_event_is_reused(event: ForensicEvent) -> bool:
    """True when the event row predates this request (idempotency reuse)."""
    if event.created_at is None:
        return False
    created = event.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - created > timedelta(seconds=2)


@router.post(
    "/manual",
    response_model=ForensicCheckpointResponse,
    summary="Manually trigger a forensic checkpoint",
    description=(
        "Analyst-initiated flow with explicit Kubernetes context "
        "(`pod_name`, `namespace`, `container_name`). Creates or links an alert, "
        "then queues a forensic checkpoint via the shared trigger pipeline."
    ),
    response_description="The created or deduplicated forensic checkpoint event.",
    responses={
        404: {"description": "Referenced alert_id does not exist."},
        422: {"description": "Invalid request or missing Kubernetes context."},
        502: {"description": "Kubernetes CR creation failed."},
        500: {"description": "Failed to create forensic checkpoint."},
    },
)
async def create_manual_alert(
    request: ForensicCheckpointManualRequest,
    db: AsyncSession = Depends(get_db),
):
    raw_alert = {
        "output_fields": {
            "k8s.ns.name": request.namespace,
            "k8s.pod.name": request.pod_name,
            "container.name": request.container_name,
        }
    }

    trigger_kwargs = {
        "trigger_source": "manual",
        "rule": "manual",
        "priority": "Critical",
        "raw_alert": raw_alert,
        "namespace": request.namespace,
        "pod_name": request.pod_name,
        "container_name": request.container_name,
    }

    try:
        if request.alert_id:
            _, event = await _ingest_alert(
                db,
                **trigger_kwargs,
                existing_alert_id=request.alert_id,
            )
        else:
            new_alert = Alert(
                rule="manual",
                priority="Critical",
                output=(
                    f"Manual checkpoint: {request.namespace}/"
                    f"{request.pod_name}/{request.container_name}"
                ),
                namespace=request.namespace,
                pod_name=request.pod_name,
                container_name=request.container_name,
                raw_event={**request.model_dump(mode="json"), "source": "manual"},
            )
            _, event = await _ingest_alert(
                db,
                **trigger_kwargs,
                new_alert=new_alert,
            )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except ApiException as e:
        raise HTTPException(
            status_code=502,
            detail=f"Kubernetes CR creation failed: {e.reason}",
        )
    except Exception as e:
        logger.exception("manual forensic trigger failed")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create forensic checkpoint: {e}",
        )

    if event is None:
        raise HTTPException(
            status_code=500,
            detail="Forensic trigger returned no event",
        )
    return event


@router.put(
    "/{alert_id}",
    response_model=AlertOut,
    summary="Update an existing alert",
    description="Updates fields on a stored alert identified by UUID.",
    response_description="The updated alert record.",
    responses={404: {"description": "No alert exists with the given ID."}},
)
async def update_alert(alert_id: uuid.UUID, alert_update: AlertOut, db: AsyncSession = Depends(get_db)):
    query = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(query)
    stored_alert = result.scalars().first()

    if not stored_alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    update_data = alert_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(stored_alert, key, value)

    db.add(stored_alert)
    await db.commit()
    await db.refresh(stored_alert)
    return stored_alert