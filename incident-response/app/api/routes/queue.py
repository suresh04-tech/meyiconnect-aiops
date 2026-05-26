"""
api/routes/queue.py
───────────────────
Public /queue endpoints.

POST /queue/enqueue
    The frontend team calls this directly to trigger process_incident
    for an already-created incident (or any payload they compose).

GET /queue/stats
    Observability.
"""

import logging
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any

from app.queue.manager import queue_manager

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Request schema ─────────────────────────────────────────────────────────────

class EnqueueRequest(BaseModel):
    incident_id:            str


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/enqueue", status_code=202)
async def enqueue(body: EnqueueRequest):
    """
    Enqueue an incident for background RCA processing.

    The frontend team can call this endpoint directly after creating an
    incident on their side. The background worker will pick it up,
    run EC2 + CloudWatch + Bedrock analysis, and store results in the DB.
    """
    payload = {
        "incident_id": body.incident_id
    }
    await queue_manager.enqueue(payload)
    logger.info(f"[/queue/enqueue] incident_id={body.incident_id} accepted")
    return {
        "accepted": True,
        "incident_id": body.incident_id,
        "queue_position": queue_manager.size,
        "message": "Incident queued for RCA processing.",
    }


@router.get("/stats")
async def stats():
    """Return queue depth and counters."""
    return queue_manager.stats()
