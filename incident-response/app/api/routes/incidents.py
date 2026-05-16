"""
api/routes/incidents.py
───────────────────────
FastAPI routes replacing the three Lambda handlers:
  POST   /incidents          → create_incident  (also enqueues to internal queue)
  GET    /incidents          → list_incidents
  GET    /incidents/{event_id} → get_incident
"""

import logging
import json
import re
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.utils.db import get_db
from app.queue.manager import queue_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# ── Constants ──────────────────────────────────────────────────────────────────

VALID_SEVERITIES = {"low", "medium", "high", "critical"}

STATUS_LABELS = {
    "queued":        "Queued — waiting to process",
    "fetching_data": "Fetching EC2 & log data",
    "finding_rca":   "AI is analysing root cause",
    "completed":     "RCA Ready",
    "failed":        "Processing Failed",
}

STATUS_PROGRESS = {
    "queued":        5,
    "fetching_data": 35,
    "finding_rca":   70,
    "completed":     100,
    "failed":        0,
}

PRIORITY_MAP = {
    "critical": "P0",
    "high":     "P1",
    "medium":   "P2",
    "low":      "P3",
}

ERROR_PATTERN = re.compile(
    r"error|exception|fatal|critical|fail|traceback|panic",
    re.IGNORECASE,
)


# ── Pydantic models ────────────────────────────────────────────────────────────

class CreateIncidentRequest(BaseModel):
    instance_id: str
    severity: str = "low"
    incident_down_time: str = Field(..., description="ISO 8601")
    log_group_name: list[str] = Field(
        ...,
        min_length=1,
        description="Minimum one CloudWatch log group required"
    )
    region: str = "ap-south-1"
    dependency_context: dict[str, Any] | None = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _validate_create(body: CreateIncidentRequest) -> str | None:
    if not body.instance_id.strip():
        return "instance_id is required"
    if body.severity not in VALID_SEVERITIES:
        return f"severity must be one of: {', '.join(VALID_SEVERITIES)}"
    try:
        datetime.fromisoformat(
            body.incident_down_time.replace("Z", "+00:00")
        )
    except (ValueError, AttributeError):
        return "incident_down_time must be valid ISO 8601"
    if not body.log_group_name:
        return "At least one log group is required"
    for log_group in body.log_group_name:
        if not log_group.strip():
            return "Invalid log group name"
    return None


def _format_bytes(value) -> str | None:
    if value is None:
        return None
    value = float(value)
    if value < 1024:
        return f"{value:.0f} B"
    if value < 1024 ** 2:
        return f"{value / 1024:.2f} KB"
    return f"{value / (1024 ** 2):.2f} MB"


def _confidence_label(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 0.8:
        return "High Confidence"
    if score >= 0.5:
        return "Medium Confidence"
    return "Low Confidence"


def _extract_errors(raw_logs, limit: int = 15) -> list:
    if isinstance(raw_logs, dict):
        all_lines = raw_logs.get("before", []) + raw_logs.get("after", []) + raw_logs.get("recent", [])
    elif isinstance(raw_logs, list):
        all_lines = raw_logs
    else:
        all_lines = []
    return [line for line in all_lines if ERROR_PATTERN.search(line)][:limit]


# ── POST /incidents ────────────────────────────────────────────────────────────

@router.post("", status_code=201)
async def create_incident(body: CreateIncidentRequest):
    logger.info("========== CREATE INCIDENT ==========")

    error = _validate_create(body)
    if error:
        raise HTTPException(status_code=400, detail=error)

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO meyiconnect.incidents (
                        instance_id,
                        severity,
                        incident_down_time,
                        region,
                        log_group_name,
                        dependency_context,
                        status
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, 'queued')
                    RETURNING event_id, created_at
                    """,
                    (
                        body.instance_id.strip(),
                        body.severity,
                        body.incident_down_time,
                        body.region.strip() or "ap-south-1",
                        body.log_group_name,
                        json.dumps(body.dependency_context or {}),
                    ),
                )
                row = cur.fetchone()

        event_id   = str(row["event_id"])
        created_at = row["created_at"]
        logger.info(f"Stored incident: {event_id}")

        # ── Enqueue to internal queue (replaces SQS send_message) ─────────────
        queue_payload = {
            "event_id": event_id,
            "instance_id": body.instance_id.strip(),
            "severity": body.severity,
            "incident_down_time": body.incident_down_time,
            "region": body.region.strip() or "ap-south-1",
            "log_group_name": body.log_group_name,
            "dependency_context": body.dependency_context or {},
        }
        await queue_manager.enqueue(queue_payload)
        logger.info(f"Enqueued to internal queue: {event_id}")

        return {
            "event_id":   event_id,
            "status":     "queued",
            "message":    "Incident received. RCA analysis has started.",
            "created_at": str(created_at),
            "tracking": {
                "list_url":   "/incidents",
                "detail_url": f"/incidents/{event_id}",
            },
        }

    except HTTPException:
        raise
    except Exception:
        logger.exception("Create incident error")
        raise HTTPException(status_code=500, detail="Failed to create incident. Please try again.")


# ── GET /incidents ─────────────────────────────────────────────────────────────

@router.get("")
async def list_incidents(
    page:  int = Query(1,  ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    logger.info("========== LIST INCIDENTS ==========")
    offset = (page - 1) * limit

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END)                         as queued_count,
                        SUM(CASE WHEN status IN ('fetching_data', 'finding_rca') THEN 1 ELSE 0 END) as processing_count,
                        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END)                       as completed_count,
                        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)                          as failed_count,
                        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END)                      as critical_count,
                        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END)                          as high_count,
                        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END)                        as medium_count,
                        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END)                           as low_count
                    FROM meyiconnect.incidents
                    """
                )
                summary_row = cur.fetchone()

                cur.execute(
                    """
                    SELECT
                        i.event_id, i.instance_id, i.severity, i.status,
                        i.incident_down_time, i.created_at, i.updated_at,
                        r.processing_status AS rca_processing_status,
                        r.confidence_score, r.ai_model_used,
                        r.generated_at      AS rca_generated_at
                    FROM meyiconnect.incidents i
                    LEFT JOIN meyiconnect.incident_rca r ON i.event_id = r.event_id
                    ORDER BY i.created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (limit, offset),
                )
                rows = cur.fetchall()

        incidents = []
        for row in rows:
            title = f"Incident detected on {row['instance_id']}"
            score = row["confidence_score"]
            incidents.append({
                "event_id":            str(row["event_id"]),
                "title":               title,
                "instance_id":         row["instance_id"],
                "severity":            row["severity"],
                "priority":            PRIORITY_MAP.get(row["severity"], "P3"),
                "status":              row["status"],
                "status_label":        STATUS_LABELS.get(row["status"], row["status"]),
                "incident_start_time": str(row["incident_start_time"]),
                "created_at":          str(row["created_at"]),
                "updated_at":          str(row["updated_at"]),
                "rca": {
                    "status":             row["rca_processing_status"] or "pending",
                    "confidence_score":   float(score) if score is not None else None,
                    "confidence_percent": f"{round(float(score) * 100)}%" if score else None,
                    "confidence_label":   _confidence_label(float(score) if score else None),
                    "ai_model_used":      row["ai_model_used"],
                    "generated_at":       str(row["rca_generated_at"]) if row["rca_generated_at"] else None,
                },
            })

        total       = summary_row["total"] or 0
        total_pages = (total + limit - 1) // limit

        return {
            "summary": {
                "total": total,
                "by_status": {
                    "queued":     int(summary_row["queued_count"] or 0),
                    "processing": int(summary_row["processing_count"] or 0),
                    "completed":  int(summary_row["completed_count"] or 0),
                    "failed":     int(summary_row["failed_count"] or 0),
                },
                "by_severity": {
                    "critical": int(summary_row["critical_count"] or 0),
                    "high":     int(summary_row["high_count"] or 0),
                    "medium":   int(summary_row["medium_count"] or 0),
                    "low":      int(summary_row["low_count"] or 0),
                },
            },
            "pagination": {
                "page":        page,
                "limit":       limit,
                "total_items": total,
                "total_pages": total_pages,
            },
            "incidents": incidents,
        }

    except Exception:
        logger.exception("List incidents error")
        raise HTTPException(status_code=500, detail="Failed to fetch incidents list.")


# ── GET /incidents/{event_id} ──────────────────────────────────────────────────

@router.get("/{event_id}")
async def get_incident(event_id: str):
    logger.info("========== INCIDENT DETAIL ==========")
    logger.info(f"Fetching detail for event: {event_id}")

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM meyiconnect.incidents WHERE event_id = %s LIMIT 1",
                    (event_id,),
                )
                incident = cur.fetchone()
                if not incident:
                    raise HTTPException(status_code=404, detail=f"Incident not found for event_id: {event_id}")

                cur.execute(
                    "SELECT * FROM meyiconnect.incident_logs WHERE event_id = %s LIMIT 1",
                    (event_id,),
                )
                log_record = cur.fetchone()

                cur.execute(
                    "SELECT * FROM meyiconnect.incident_rca WHERE event_id = %s LIMIT 1",
                    (event_id,),
                )
                rca_record = cur.fetchone()

        status = incident["status"]

        # EC2
        ec2_section = None
        if log_record:
            ec2_section = {
                "details":       log_record["ec2_details"],
                "status_checks": log_record["ec2_status_checks"],
            }

        # Metrics
        metrics_section = None
        if log_record and log_record.get("cloudwatch_metrics"):
            m = log_record["cloudwatch_metrics"]
            cpu     = m.get("cpu_percent")
            net_in  = m.get("network_in_bytes")
            net_out = m.get("network_out_bytes")
            sf      = m.get("status_check_failed")
            metrics_section = {
                "cpu_percent":         cpu,
                "cpu_label":           f"{float(cpu):.1f}%" if cpu is not None else None,
                "network_in_bytes":    net_in,
                "network_in_label":    _format_bytes(net_in),
                "network_out_bytes":   net_out,
                "network_out_label":   _format_bytes(net_out),
                "disk_read_ops":       m.get("disk_read_ops"),
                "disk_write_ops":      m.get("disk_write_ops"),
                "status_check_failed": sf,
                "status_check_ok":     sf == 0 if sf is not None else None,
            }

        # Logs
        logs_section = None
        if log_record and log_record.get("raw_logs"):
            raw = log_record["raw_logs"]
            if isinstance(raw, dict):
                all_logs = raw.get("before", []) + raw.get("after", []) + raw.get("recent", [])
            elif isinstance(raw, list):
                all_logs = raw
            else:
                all_logs = []
            logs_section = {
                "counts":    {"total": log_record.get("logs_count") or len(all_logs)},
                "recent":    all_logs[:50],
                "top_errors": _extract_errors(all_logs),
                "fetched_at": str(log_record["fetched_at"]) if log_record.get("fetched_at") else None,
            }

        # RCA
        rca_section = None
        if rca_record:
            score   = rca_record.get("confidence_score")
            score_f = float(score) if score is not None else None
            rca_section = {
                "processing_status":     rca_record["processing_status"],
                "root_cause_report":     rca_record["rca_report"],
                "remediation_steps":     rca_record["remediation_steps"],
                "confidence_score":      score_f,
                "confidence_percent":    f"{round(score_f * 100)}%" if score_f is not None else None,
                "confidence_label":      _confidence_label(score_f),
                "impacted_dependencies": rca_record["impacted_dependencies"],
                "ai_model_used":         rca_record["ai_model_used"],
                "generated_at":          str(rca_record["generated_at"]) if rca_record.get("generated_at") else None,
            }

        return {
            "event_id":            str(incident["event_id"]),
            "instance_id":         incident["instance_id"],
            "issue":               incident["issue"],
            "severity":            incident["severity"],
            "priority":            PRIORITY_MAP.get(incident["severity"], "P3"),
            "incident_start_time": str(incident["incident_start_time"]),
            "log_group_name":      incident["log_group_name"],
            "dependency_context":  incident["dependency_context"],
            "status":              status,
            "status_label":        STATUS_LABELS.get(status, status),
            "progress_percent":    STATUS_PROGRESS.get(status, 0),
            "created_at":          str(incident["created_at"]),
            "updated_at":          str(incident["updated_at"]),
            "ec2":                 ec2_section,
            "metrics":             metrics_section,
            "logs":                logs_section,
            "rca":                 rca_section,
            "is_complete":         status == "completed",
            "is_failed":           status == "failed",
            "retry_after_seconds": 10 if status in ("queued", "fetching_data", "finding_rca") else None,
        }

    except HTTPException:
        raise
    except Exception:
        logger.exception("Incident detail error")
        raise HTTPException(status_code=500, detail="Failed to fetch incident detail.")
