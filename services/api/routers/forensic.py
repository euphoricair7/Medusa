import uuid

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from db.session import SessionLocal
from models.forensic import (
    ForensicEvent,
    ForensicCheckpointResponse,
)

router = APIRouter()

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