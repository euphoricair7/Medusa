import uuid
import logging
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends
from kubernetes.client.rest import ApiException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.session import get_db
from forensic_service import process_trigger_forensic
from models.alert import Alert, AlertOut
from models.forensic import (
    ForensicCheckpointManualRequest,
    ForensicCheckpointResponse,
    ForensicEvent,
)

logger = logging.getLogger(__name__)

router = APIRouter()


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
    result = await db.execute(select(Alert))
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

    # storing in the db
    new_alert = Alert(
        received_at=datetime.utcnow(),
        rule=alert.get("rule", ""),
        priority=alert.get("priority", ""),
        output=alert.get("output", ""),
        container_name=alert.get("output_fields", {}).get("container.name"),
        image=alert.get("output_fields", {}).get("container.image.repository"),
        tags=alert.get("tags"),
        raw_event=alert
    )
    db.add(new_alert)
    print("committing")
    await db.commit()
    print("committed")
    await db.refresh(new_alert)

    try:
        await process_trigger_forensic(
            db,
            alert_id=new_alert.id,
            rule=new_alert.rule,
            priority=new_alert.priority,
            raw_event=alert,
        )
    except ValueError:
        pass  # no k8s context, alert saved, no CR
    except Exception as e:
        # log but dont fail alert ingestions
        print(f"Error triggering forensic: {e}")

    print(f"Received Falco alert: {alert}")

    return {"status": "ok"}


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