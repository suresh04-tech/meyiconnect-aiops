"""
processor/worker.py
───────────────────
Async background worker — replaces the Lambda SQS trigger.

Runs as a long-lived asyncio task inside the FastAPI process.
Picks up payloads from QueueManager and calls process_incident()
in a thread pool so blocking boto3 / DB calls don't block the event loop.
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

from app.queue.manager import QueueManager
from app.processor.process_incident import process_incident

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="incident-worker")


async def start_worker(manager: QueueManager) -> None:
    """
    Infinite loop: wait for a message → run processor in thread → repeat.
    CancelledError is the normal shutdown path.
    """
    logger.info("[Worker] Incident processor worker started.")

    while True:
        payload = await manager.get()
        incident_id = payload.get("incident_id", "unknown")
        logger.info(f"[Worker] Picked up incident_id={incident_id}")

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(_executor, process_incident, payload)
            manager.mark_processed()
            logger.info(f"[Worker] Completed incident_id={incident_id}")
        except Exception:
            manager.mark_failed()
            logger.exception(f"[Worker] Failed incident_id={incident_id}")
        finally:
            manager.task_done()
