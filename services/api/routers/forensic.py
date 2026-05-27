from fastapi import APIRouter
from models.forensic import ForensicCheckpointRequest, ForensicCheckpointResponse
import uuid

router = APIRouter()

ALERT_PRIORITY = ["critical", "error", "warning", "notice", "info", "debug"]
MIN_PRIORITY = "warning"  # Only process alerts with priority "warning" or higher

@router.post("/forensic-checkpoint", response_model=ForensicCheckpointResponse)
async def create_falco_alert(alert: ForensicCheckpointRequest):
    
    #filtering alerts based on priority


    #convert to lowercase
    priority_cased= alert.priority.lower()
    if ALERT_PRIORITY.index(priority_cased) > ALERT_PRIORITY.index(MIN_PRIORITY):
        return ForensicCheckpointResponse(
            status="ignored",
            forensic_checkpoint_id="",
            message=f"Alert priority '{alert.priority}' is below the minimum threshold '{MIN_PRIORITY}'."
        )
    
    event_id = str(uuid.uuid4())

    #Todo: integrate the Forensic checkpointing crd logic from the operator
    #TOdo: add logic to take the container name, pod name and namespace as input 
    #Todo: Register the forensic events in the db and apply deduplication in db

    print(f"Received Falco alert for forensic checkpointing: {alert.rule} event_id: {event_id}")

    return ForensicCheckpointResponse(
        status="accepted",
        forensic_checkpoint_id=event_id,
        message="Forensic checkpoint queued for creation."
    )