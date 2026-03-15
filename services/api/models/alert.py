from sqlalchemy import Column, Text, ARRAY, DateTime, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from pydantic import BaseModel, ConfigDict
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
    rule:     str
    priority: str
    output:   str
    output_fields: Optional[dict] = None
    tags:     Optional[list[str]] = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id:             uuid.UUID
    received_at:    datetime
    rule:           str
    priority:       str
    output:         str
    container_name: Optional[str]
    image:          Optional[str]
    tags:           Optional[list[str]]