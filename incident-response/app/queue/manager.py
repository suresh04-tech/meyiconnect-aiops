"""
queue/manager.py
────────────────
In-process queue that replaces AWS SQS.

Design:
  • asyncio.Queue for async-safe put/get
  • Each message is a plain dict (same shape as the old SQS payload)
  • Exposes /queue/enqueue  → called by create_incident
  • Exposes /queue/stats    → observability
  • The background worker (processor/worker.py) calls manager.get() in a loop
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class QueueManager:
    def __init__(self, maxsize: int = 0):
        self._q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self._enqueued: int = 0
        self._processed: int = 0
        self._failed: int = 0

    # ── Producer (called by create_incident route) ─────────────────────────

    async def enqueue(self, payload: dict[str, Any]) -> None:
        payload["_enqueued_at"] = datetime.now(timezone.utc).isoformat()
        await self._q.put(payload)
        self._enqueued += 1
        logger.info(
            f"[Queue] Enqueued incident_id={payload.get('incident_id')} | "
            f"queue_size={self._q.qsize()}"
        )

    # ── Consumer (called by worker) ────────────────────────────────────────

    async def get(self) -> dict[str, Any]:
        return await self._q.get()

    def task_done(self) -> None:
        self._q.task_done()

    def mark_processed(self) -> None:
        self._processed += 1

    def mark_failed(self) -> None:
        self._failed += 1

    # ── Observability ──────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "pending":   self._q.qsize(),
            "enqueued":  self._enqueued,
            "processed": self._processed,
            "failed":    self._failed,
        }

    @property
    def size(self) -> int:
        return self._q.qsize()


# Singleton — imported everywhere
queue_manager = QueueManager()
