import uuid

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from db.session import SessionLocal
from models.forensic import (
    ForensicEvent,
    ForensicCheckpointStatus,
    ForensicCheckpointAlertRequest,
    ForensicCheckpointResponse,
)

router = APIRouter()

ALERT_PRIORITY = ["critical", "error", "warning", "notice", "info", "debug"]
MIN_PRIORITY = "warning"  # Only process alerts with priority "warning" or higher


@router.post(
    "/falco_alert",
    response_model=ForensicCheckpointResponse,
    summary="Create forensic event from Falco alert",
    description=(
        "Automatic flow triggered by a Falco webhook. Validates alert priority, "
        "creates a forensic event in `pending` phase, and optionally links to an "
        "existing alert via `alert_id`."
    ),
    response_description="The newly created forensic checkpoint event.",
    responses={
        422: {"description": "Alert priority is below the configured threshold."},
        500: {"description": "Failed to persist the forensic event."},
    },
)
async def create_falco_alert(alert: ForensicCheckpointAlertRequest):

    # filtering alerts based on priority

    # convert to lowercase
    priority_cased = alert.priority.lower()

    if priority_cased not in ALERT_PRIORITY:
        raise HTTPException(status_code=422, detail="priority below threshold")

    if ALERT_PRIORITY.index(priority_cased) > ALERT_PRIORITY.index(MIN_PRIORITY):
        raise HTTPException(
            status_code=422,
            detail=(
                f"Alert priority '{alert.priority}' is below the minimum "
                f"threshold '{MIN_PRIORITY}'."
            ),
        )

    """
    Ultimately,
    pull the alert from db, if exists, to link with the forensic event,
    else create a new alert entry and link it with that

    TODO: Alert correlation
    Add a better way to link the alert and forensic event,
    currently we are matching the alert based on the alert_id and received_at timestamp,
    which is not very reliable, need to find a better way to link them,
    maybe by using a unique identifier in the alert that can be used to link with the forensic event
    """

    async with SessionLocal() as session:

        # linked_alert_id=None

        # if alert_matched:
        #     existing_alert= await session.execute(
        #         select(ForensicEvent)
        #         .where(ForensicEvent.alert_id == alert_matched.alert_id)
        #     )
        #     if existing_alert.scalars().first():
        #         linked_alert_id= alert_matched.alert_id
        #         print(f"Duplicate alert, already queued forensic event for alert_id: {linked_alert_id}")

        event = ForensicEvent(
            alert_id=alert.alert_id if alert.alert_id else None,
            pod_name=None,
            namespace=None,
            container_name=None,
            phase=ForensicCheckpointStatus.pending.value,
            trigger_source="falco",
            triggered_rule=alert.rule,
            triggered_priority=alert.priority,
            raw_alert=alert.model_dump(),
        )
        try:
            session.add(event)
            await session.commit()
            print(
                f"Created forensic event with id: {event.id} "
                f"linked to alert_id: {event.alert_id}"
            )
            await session.refresh(event)
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create forensic event: {str(e)}",
            )

    return event


@router.get(
    "/{event_id}",
    response_model=ForensicCheckpointResponse,
    summary="Retrieve a forensic event",
    description="Returns the current state of a forensic checkpoint event by its UUID.",
    response_description="Forensic event record including phase and checkpoint location.",
    responses={404: {"description": "No forensic event exists with the given ID."}},
)
async def get_forensic_event(event_id: uuid.UUID):
    async with SessionLocal() as session:
        result = await session.execute(
            select(ForensicEvent).where(ForensicEvent.id == event_id)
        )
        event = result.scalars().first()
        if not event:
            raise HTTPException(
                status_code=404,
                detail=f"No forensic event found with event_id: {event_id}.",
            )
        return event