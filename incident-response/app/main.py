import logging
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import queue
from app.queue.manager import queue_manager
from app.processor.worker import start_worker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background worker on startup, cancel on shutdown."""
    logger.info("Starting incident processor worker...")
    worker_task = asyncio.create_task(start_worker(queue_manager))
    yield
    logger.info("Shutting down worker...")
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="Incident Response API",
    version="2.0.0",
    description="Incident RCA processing service — Docker/FastAPI edition",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(queue.router, prefix="/queue", tags=["Queue"])


@app.get("/health", tags=["Health"])
async def health():
    stats = queue_manager.stats()
    return {"status": "ok", "queue": stats}
