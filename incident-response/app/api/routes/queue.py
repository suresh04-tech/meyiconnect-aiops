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
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Any

from app.queue.manager import queue_manager

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Request schema ─────────────────────────────────────────────────────────────

class EnqueueRequest(BaseModel):
    event_id:            str
    instance_id:         str
    issue:               str
    severity:            str
    incident_start_time: str  = Field(..., description="ISO 8601")
    incident_end_time:   str  = Field(..., description="ISO 8601")
    log_group_name:      str
    region:              str  = "ap-south-1"
    dependency_context:  dict[str, Any] = {}
    incident_down_time:  str | None = None  # optional; defaults to incident_start_time


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/enqueue", status_code=202)
async def enqueue(body: EnqueueRequest):
    """
    Enqueue an incident for background RCA processing.

    The frontend team can call this endpoint directly after creating an
    incident on their side. The background worker will pick it up,
    run EC2 + CloudWatch + Bedrock analysis, and store results in the DB.
    """
    payload = body.model_dump()
    await queue_manager.enqueue(payload)
    logger.info(f"[/queue/enqueue] event_id={body.event_id} accepted")
    return {
        "accepted": True,
        "event_id": body.event_id,
        "queue_position": queue_manager.size,
        "message": "Incident queued for RCA processing.",
    }


@router.get("/stats")
async def stats():
    """Return queue depth and counters."""
    return queue_manager.stats()
