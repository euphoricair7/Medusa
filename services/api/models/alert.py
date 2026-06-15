from sqlalchemy import Column, Text, ARRAY, DateTime, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Optional
import uuid

from db.session import Base


# --- SQLAlchemy ORM model ---

class Alert(Base):
    __tablename__ = "alerts"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    received_at    = Column(DateTime(timezone=True), server_default=func.now())
    rule           = Column(Text, nullable=False)
    priority       = Column(Text, nullable=False)
    output         = Column(Text, nullable=False)
    container_name = Column(Text)
    image          = Column(Text)
    tags           = Column(ARRAY(Text))
    raw_event      = Column(JSONB, nullable=False)


# --- Pydantic schemas ---

class AlertFalcoInput(BaseModel):
    """Schema of the payload thant Falco sends directly via http_output."""
    rule:     str = Field(description="The Falco rule that triggered this alert")
    priority: str = Field(description="The priority of the alert")
    output:   str = Field(description="The output message of the alert")
    output_fields: Optional[dict] = Field(default=None, description="The output_fields dictionary from the Falco alert, which may contain additional structured information")
    tags:     Optional[list[str]] = Field(default=None, description="The list of tags associated with the triggered rule in Falco")


class AlertOut(BaseModel):
    """
    Standardized response returning the details of a persisted Falco alert.
    """
    model_config = ConfigDict(from_attributes=True)

    alert_id: uuid.UUID = Field(alias="id",description="The unique identifier of the alert")
    received_at:    datetime = Field(description="The timestamp when the alert was received")
    rule:           str = Field(description="The Falco rule that triggered this alert")
    priority:       str = Field(description="The priority of the alert")
    output:         str = Field(description="The output message of the alert")
    container_name: Optional[str] = Field(default=None, description="The name of the container where the alert was triggered")
    image:          Optional[str] = Field(default=None, description="The image of the container where the alert was triggered")
    tags:           Optional[list[str]] = Field(default=None, description="The list of tags associated with the triggered rule in Falco")