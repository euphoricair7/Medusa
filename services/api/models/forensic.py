from sqlalchemy import Column, Text, DateTime, func, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Optional
import uuid
import enum

from db.session import Base

#Enum to track the checkpoint status
class ForensicCheckpointStatus(enum.Enum):
    #for now this is a temporary meaning for pending, until k8s integration
    pending = "pending" # alert recieved, no k8s context yet
    queued = "queued" # alert with k8s context, queued for checkpointing
    in_progress = "in_progress" # checkpointing in progress by the operator
    success = "success"
    failed = "failed"
    ignored = "ignored" # alert ignored due to low priority or other reasons


#SQLAlchemy ORM Model
class ForensicEvent(Base):
    __tablename__ = "forensic_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    #to link the forensic event eith the alert
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True)

    #k8s context
    pod_name = Column(Text)
    namespace = Column(Text)
    container_name = Column(Text)

    #checkpointing status
    phase = Column(Text, nullable=False, default=ForensicCheckpointStatus.pending.value)
    trigger_source      = Column(Text)         # "falco" or "manual"
    triggered_rule = Column(Text)
    triggered_priority = Column(Text)

    #info given by operator
    checkpoint_location = Column(Text) # where the checkpoint is stored, can be path where snapshots are stored


    #store raw payloads also for reference
    raw_alert           = Column(JSONB)        # original Falco alert JSON
    raw_report          = Column(JSONB)        # checkpointctl analysis output


"""
Manual schema for now, until we have the logic to link the alert and 
forensic event in db, we can take the alert_id as optional input from the user, 
along with the k8s context to create the forensic checkpointing event

Might remove this later and automate this
"""
class ForensicCheckpointManualRequest(BaseModel):
    """
    Recieved from databse + k8s context given by the user, for now due to the container plugin issue, 
    let's take the container_name, pod_name and namespace as input, unless we fix it in future
    """
    alert_id: Optional[uuid.UUID] = None 
    pod_name: str
    namespace: str = "default"
    container_name: str

"""
Automated forensic checkpointing request, 
raw Falco alert, no k8s context yet.
Reuses same payload structure Falco sends.

Added for current testing, will remove later 
and automate the k8s context extraction and linking with the alert in db
"""

class ForensicCheckpointAlertRequest(BaseModel):
    alert_id: Optional[uuid.UUID] = None # to link with the alert in db, if exists
    rule:     str
    priority: str
    output:   str
    output_fields: Optional[dict] = None
    tags:     Optional[list[str]] = None
    
"""
Response Schema 
"""
class ForensicCheckpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    forensic_checkpoint_id: uuid.UUID = Field(alias="id")
    created_at: datetime
    alert_id: Optional[uuid.UUID] = None
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    container_name: Optional[str] = None
    phase: str
    trigger_source: Optional[str] = None
    triggered_rule: Optional[str] = None
    triggered_priority: Optional[str] = None
    checkpoint_location: Optional[str] = None
    message: Optional[str] = None




