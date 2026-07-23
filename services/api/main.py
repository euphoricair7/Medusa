from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import logging 

from forensic_sync import run_forensic_sync
from db.session import engine, Base, SessionLocal
from routers import alerts,forensic

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        # await conn.run_sync(Base.metadata.drop_all) # drop all tables
        await conn.run_sync(Base.metadata.create_all)

    stop_event = asyncio.Event()
    sync_task = asyncio.create_task(run_forensic_sync(stop_event))

    yield
    
    stop_event.set()
    sync_task.cancel()
    try:
        await sync_task
    except asyncio.CancelledError:
        logger.info("Forensic sync task cancelled")
    except Exception as e:
        logger.error("Forensic sync task error: %s", e)
    await engine.dispose()


app = FastAPI(
    title="Medusa API",
    description=(
        "REST API for the Medusa container forensics framework. "
        "Receives Falco runtime alerts, persists them to PostgreSQL, "
        "and manages forensic checkpoint events triggered automatically or manually."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Dependency to get a DB session
async def get_db():
    async with SessionLocal() as session:
        yield session

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
app.include_router(forensic.router, prefix="/forensic-checkpoint", tags=["forensic"])


@app.get(
    "/health",
    summary="Service health check",
    description="Returns the current health status of the Medusa API service.",
    response_description="Health status payload with service identifier.",
    tags=["health"],
)
async def health():
    return {"status": "ok", "service": "medusa-api-v1"}


