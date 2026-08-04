import uuid
from datetime import datetime,timezone
from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from db.session import SessionLocal
from models.forensic import (
    ForensicEvent,
    ForensicCheckpointResponse,
    ForensicAnalysisRequest,
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

@router.post(
    "/{event_id}/analysis",
    response_model=ForensicCheckpointResponse,
    summary="Attach checkpointctl analysis to a forensic event",
    description=(
        "Used by DaemonSet analyzer. Merges into raw_report.checkpointctl "
        "without removing raw_report.operator written by forensic_sync. "
        "Does not run checkpointctl itself."
    ),
    responses={404: {"description": "No forensic event exists with the given ID."}},
)
async def attach_checkpointctl_analysis(event_id: uuid.UUID, body: ForensicAnalysisRequest):
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
        analyzed_at = body.analyzed_at or datetime.now(timezone.utc)
        checkpointctl_analysis = {
            "checkpoint_path": body.checkpoint_path,
            "node_name": body.node_name,
            "analyzer": body.analyzer or "checkpointctl",
            "analyzed_at": analyzed_at.isoformat(),
            "report": body.report,
        }
        rr = dict(event.raw_report) if isinstance(event.raw_report, dict) else {}
        rr["checkpointctl"] = checkpointctl_analysis
        event.raw_report = rr
        event.updated_at = analyzed_at
        await session.commit()
        await session.refresh(event)
        return event