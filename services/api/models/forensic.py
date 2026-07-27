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

    #idempotency key
    idempotency_key = Column(Text, unique=True, nullable=True)
    operator_cr_name = Column(Text)


"""
Manual schema for now, until we have the logic to link the alert and 
forensic event in db, we can take the alert_id as optional input from the user, 
along with the k8s context to create the forensic checkpointing event

"""
class ForensicCheckpointManualRequest(BaseModel):
    """
    Payload for manually triggering a forensic checkpoint.
    Currently requires explicit Kubernetes context due to container plugin limitations.
    """
    alert_id: Optional[uuid.UUID] = Field(
        default=None, 
        description="Optional ID of an existing alert to link this manual checkpoint to."
    )
    pod_name: str = Field(
        description="Name of the Kubernetes pod hosting the compromised container.",
        json_schema_extra={"example": "medusa-target-deploy"}
    )
    namespace: str = Field(
        default="default", 
        description="Kubernetes namespace of the target pod."
    )
    container_name: str = Field(
        description="Specific container name within the pod to target for the CRIU snapshot.",
        json_schema_extra={"example": "vulnerable-target-container"}
    )
    
"""
Response Schema 
"""
class ForensicCheckpointResponse(BaseModel):
    """
    Standardized response returning the state of a forensic event.
    """

    model_config = ConfigDict(from_attributes=True)

    forensic_checkpoint_id: uuid.UUID = Field(
        alias="id", 
        description="Unique identifier for this forensic checkpointing event."
    )
    created_at: datetime = Field( 
        description="Timestamp of when the event was registered."
    )
    alert_id: Optional[uuid.UUID] = Field(
        default=None, 
        description="Linked Falco alert ID, if applicable."
    )
    pod_name: Optional[str] = Field(
        default=None, 
        description="Target Kubernetes pod."
    )
    namespace: Optional[str] = Field(
        default=None, 
        description="Target Kubernetes namespace."
    )
    container_name: Optional[str] = Field(
        default=None, 
        description="Target container."
    )
    phase: str = Field(
        description="Current phase/status of the forensic checkpointing process.",
        json_schema_extra={"example": "pending, queued, in_progress, success, failed, ignored"}
    )
    trigger_source: Optional[str] = Field(
        default=None, 
        description="Source that triggered the checkpointing (e.g., 'falco', 'manual')."
    )
    triggered_rule: Optional[str] = Field(
        default=None, 
        description="The specific Falco rule that was triggered."
    )
    triggered_priority: Optional[str] = Field(
        default=None, 
        description="Severity level of the alert."
    )
    checkpoint_location: Optional[str] = Field(
        default=None, 
        description="Filepath or storage URI where the generated CRIU memory artifact is stored."
    )
    message: Optional[str] = Field(
        default=None, 
        description="Additional message or details about the forensic checkpoint or event status."
    )
    operator_cr_name: Optional[str] = Field(
        default=None,
        description="Name of the operator CR that triggered the forensic checkpointing."
    )




