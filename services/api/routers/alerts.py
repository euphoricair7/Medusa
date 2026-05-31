from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models.alert import Alert, AlertOut
from db.session import get_db
from datetime import datetime
import uuid

router = APIRouter()

@router.get("/", response_model=list[AlertOut])
async def get_alerts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert))
    alerts = result.scalars().all()
    return alerts

@router.post("/falco")
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

    print(f"Received Falco alert: {alert}")
    
    return {"status": "ok"}

@router.put("/{alert_id}", response_model=AlertOut)
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
