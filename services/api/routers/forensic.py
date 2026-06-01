from fastapi import APIRouter
from sqlalchemy import select
from models.forensic import (
    ForensicEvent,
    ForensicCheckpointStatus,
    ForensicCheckpointManualRequest,
    ForensicCheckpointAlertRequest,
    ForensicCheckpointResponse,
)
from models.alert import Alert
from db.session import SessionLocal as AsyncSessionLocal
import uuid
from fastapi import HTTPException

router = APIRouter()

ALERT_PRIORITY = ["critical", "error", "warning", "notice", "info", "debug"]
MIN_PRIORITY = "warning"  # Only process alerts with priority "warning" or higher

@router.post("/falco_alert", response_model=ForensicCheckpointResponse)
async def create_falco_alert(alert: ForensicCheckpointAlertRequest):
    
    """
    Automatic flow: called by Falco webhook.
    No k8s context yet. Initial checkpoint status right now as: pending
    """

    #filtering alerts based on priority

    #convert to lowercase
    priority_cased= alert.priority.lower()

    if priority_cased not in ALERT_PRIORITY:
       raise HTTPException(status_code=422, detail="priority below threshold")
    
    if ALERT_PRIORITY.index(priority_cased) > ALERT_PRIORITY.index(MIN_PRIORITY):
        raise HTTPException(status_code=422, detail=f"Alert priority '{alert.priority}' is below the minimum threshold '{MIN_PRIORITY}'.")

    
    """
    Ultimately, 
    pull the  alert from db, if exists, to link with the forensic event,
    else create a new alert entry and link it with that

    TODO: Alert correlation
    Add a better way to link the alert and forensic event, 
    currently we are matching the alert based on the alert_id and received_at timestamp, 
    which is not very reliable, need to find a better way to link them, 
    maybe by using a unique identifier in the alert that can be used to link with the forensic event
    """

    async with AsyncSessionLocal() as session:
        
        # linked_alert_id=None

        # if alert_matched:
        #     existing_alert= await session.execute(
        #         select(ForensicEvent)
        #         .where(ForensicEvent.alert_id == alert_matched.alert_id)
        #     )
        #     if existing_alert.scalars().first():
        #         linked_alert_id= alert_matched.alert_id
        #         print(f"Duplicate alert, already queued forensic event for alert_id: {linked_alert_id}")

    
        event= ForensicEvent(
            alert_id= alert.alert_id if alert.alert_id else None, # to link with the alert in db, if exists
            pod_name=None,
            namespace=None,
            container_name=None,
            phase=ForensicCheckpointStatus.pending.value,
            trigger_source="falco",
            triggered_rule=alert.rule,
            triggered_priority=alert.priority,
            raw_alert= alert.model_dump(),
        )
        try:
            session.add(event)
            await session.commit()
            print(f"Created forensic event with id: {event.id} linked to alert_id: {event.alert_id}")
            await session.refresh(event)
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=500, detail=f"Failed to create forensic event: {str(e)}")

    return event

    

@router.post("/manual_alert", response_model=ForensicCheckpointResponse)
async def create_manual_alert(request: ForensicCheckpointManualRequest):
    print("MANUAL ROUTE HIT")
    """
    Manual flow: called by user.
    k8s context provided. Initial checkpoint status right now as: pending
    """

    
    #pull the  alert from db, if exists, to link with the forensic event
    #else create a new alert entry and link it with that

    async with AsyncSessionLocal() as session:
        if request.alert_id:
            result = await session.execute(
                select(Alert)
                .where(Alert.id==request.alert_id)
            )
            if not result.scalars().first():
                raise HTTPException(status_code=404, detail=f"No alert found with alert_id: {request.alert_id}")


        event = ForensicEvent(
            alert_id= request.alert_id if request.alert_id else None,
            pod_name=request.pod_name,
            namespace=request.namespace,
            container_name=request.container_name,
            phase=ForensicCheckpointStatus.pending.value,
            trigger_source="manual",
            checkpoint_location=None, # to be updated later by the user after checkpointing is done
        )
        try: 
            session.add(event)
            await session.commit()
            await session.refresh(event)

        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=500, detail=f"Failed to create forensic event: {str(e)}")


    return event

@router.get("/{event_id}", response_model=ForensicCheckpointResponse)
async def get_forensic_event(event_id: uuid.UUID):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ForensicEvent)
            .where(ForensicEvent.id == event_id)
        )
        event = result.scalars().first()
        if not event:
            raise HTTPException(status_code=404, detail=f"No forensic event found with event_id: {event_id}.")
        return event

    