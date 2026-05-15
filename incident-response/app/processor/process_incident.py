"""
processor/process_incident.py
─────────────────────────────
Core RCA processing logic — adapted from the original Lambda handler.

Key changes from Lambda version:
  • No SQS record wrapping — payload is the dict directly
  • Runs synchronously (called from thread pool via worker.py)
  • All boto3 / DB calls unchanged
"""

import os
import json
import boto3
import logging
import re
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.utils.db import get_db

logger = logging.getLogger(__name__)

# ─── Config ────────────────────────────────────────────────────────────────────

REGION                    = os.environ.get("AWS_REGION", "ap-south-1")
BEDROCK_MODEL             = os.environ.get("BEDROCK_MODEL_ID", "meta.llama3-8b-instruct-v1:0")
LOG_FETCH_LIMIT           = int(os.environ.get("LOG_FETCH_LIMIT", "100"))
ERROR_SCAN_WINDOW_MINUTES = int(os.environ.get("ERROR_SCAN_WINDOW_MINUTES", "30"))
AI_LOG_LINE_LIMIT         = int(os.environ.get("AI_LOG_LINE_LIMIT", "200"))

ERROR_PATTERN = re.compile(
    r"error|exception|fatal|critical|fail|traceback|panic",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════
# SECTION 1 — CloudWatch Metrics
# ═══════════════════════════════════════════════════════════════

def _get_metric(cw_client, namespace, metric_name, instance_id,
                stat="Average", window_minutes=15):
    try:
        end_time   = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=window_minutes)
        resp = cw_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=[stat],
        )
        points = resp.get("Datapoints", [])
        if not points:
            return None
        latest = sorted(points, key=lambda x: x["Timestamp"], reverse=True)[0]
        return latest.get(stat)
    except Exception as e:
        logger.warning(f"Metric {metric_name} fetch failed: {e}")
        return None


def get_all_metrics(cw_client, instance_id: str) -> dict:
    logger.info(f"Fetching CloudWatch metrics for: {instance_id}")
    metric_defs = [
        ("AWS/EC2", "CPUUtilization",    "Average", "cpu_percent"),
        ("AWS/EC2", "NetworkIn",         "Average", "network_in_bytes"),
        ("AWS/EC2", "NetworkOut",        "Average", "network_out_bytes"),
        ("AWS/EC2", "DiskReadOps",       "Average", "disk_read_ops"),
        ("AWS/EC2", "DiskWriteOps",      "Average", "disk_write_ops"),
        ("AWS/EC2", "StatusCheckFailed", "Sum",     "status_check_failed"),
    ]
    results = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            pool.submit(_get_metric, cw_client, ns, name, instance_id, stat): key
            for ns, name, stat, key in metric_defs
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception:
                results[key] = None
    logger.info(f"Metrics collected: {results}")
    return results


# ═══════════════════════════════════════════════════════════════
# SECTION 2 — EC2 Details
# ═══════════════════════════════════════════════════════════════

def get_ec2_details(ec2_client, instance_id: str) -> dict:
    logger.info(f"Fetching EC2 details for: {instance_id}")
    details, status_checks = {}, {}

    try:
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if reservations:
            inst = reservations[0]["Instances"][0]
            details = {
                "instance_id":       inst.get("InstanceId"),
                "instance_type":     inst.get("InstanceType"),
                "state":             inst.get("State", {}).get("Name"),
                "private_ip":        inst.get("PrivateIpAddress"),
                "public_ip":         inst.get("PublicIpAddress"),
                "vpc_id":            inst.get("VpcId"),
                "subnet_id":         inst.get("SubnetId"),
                "availability_zone": inst.get("Placement", {}).get("AvailabilityZone"),
                "launch_time":       str(inst.get("LaunchTime", "")),
                "ami_id":            inst.get("ImageId"),
                "key_name":          inst.get("KeyName"),
                "security_groups": [
                    {"id": sg.get("GroupId"), "name": sg.get("GroupName")}
                    for sg in inst.get("SecurityGroups", [])
                ],
                "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
            }
    except Exception as e:
        logger.warning(f"describe_instances failed: {e}")

    try:
        resp = ec2_client.describe_instance_status(
            InstanceIds=[instance_id], IncludeAllInstances=True
        )
        statuses = resp.get("InstanceStatuses", [])
        if statuses:
            s = statuses[0]
            status_checks = {
                "instance_status": s.get("InstanceStatus", {}).get("Status"),
                "system_status":   s.get("SystemStatus", {}).get("Status"),
                "instance_status_details": [
                    {"name": d.get("Name"), "status": d.get("Status")}
                    for d in s.get("InstanceStatus", {}).get("Details", [])
                ],
                "system_status_details": [
                    {"name": d.get("Name"), "status": d.get("Status")}
                    for d in s.get("SystemStatus", {}).get("Details", [])
                ],
            }
    except Exception as e:
        logger.warning(f"describe_instance_status failed: {e}")

    return {"details": details, "status_checks": status_checks}


# ═══════════════════════════════════════════════════════════════
# SECTION 3 — CloudWatch Logs (Two-Phase Strategy)
# ═══════════════════════════════════════════════════════════════

def _fetch_raw_events(logs_client, log_group, start_ms, end_ms, limit=LOG_FETCH_LIMIT):
    try:
        resp = logs_client.filter_log_events(
            logGroupName=log_group,
            startTime=start_ms,
            endTime=end_ms,
            limit=limit,
        )
        return [
            {"ts": e["timestamp"], "message": e["message"]}
            for e in resp.get("events", [])
            if e.get("message")
        ]
    except Exception as e:
        logger.warning(f"Log fetch failed for {log_group}: {e}")
        return []


def discover_errors_around_downtime(logs_client, log_group, incident_down_time,
                                    window_minutes=ERROR_SCAN_WINDOW_MINUTES):
    scan_start = incident_down_time - timedelta(minutes=window_minutes)
    scan_end   = incident_down_time + timedelta(minutes=window_minutes)
    logger.info(f"[Phase-A] Scanning [{scan_start.isoformat()} — {scan_end.isoformat()}]")
    events = _fetch_raw_events(
        logs_client, log_group,
        int(scan_start.timestamp() * 1000),
        int(scan_end.timestamp() * 1000),
        limit=500,
    )
    error_events = [e for e in events if ERROR_PATTERN.search(e["message"])]
    logger.info(f"[Phase-A] Found {len(error_events)} error events out of {len(events)} total")
    return error_events


def fetch_context_logs_for_errors(logs_client, log_group, error_events, incident_start,
                                  context_buffer_minutes=5, ai_line_limit=AI_LOG_LINE_LIMIT):
    if not error_events:
        logger.info("[Phase-B] No error events — skipping context expansion")
        return []

    context_start_ms = int(incident_start.timestamp() * 1000)
    seen:    set  = set()
    ordered: list = []

    for err in sorted(error_events, key=lambda e: e["ts"]):
        context_end_ms = err["ts"] + int(context_buffer_minutes * 60 * 1000)
        events = _fetch_raw_events(logs_client, log_group, context_start_ms, context_end_ms, limit=300)
        for ev in events:
            msg = ev["message"]
            if msg not in seen:
                seen.add(msg)
                ordered.append(msg)
        if len(ordered) >= ai_line_limit:
            break

    result = ordered[:ai_line_limit]
    logger.info(f"[Phase-B] Final context log lines: {len(result)}")
    return result


def get_incident_logs_optimized(logs_client, log_group, incident_start,
                                incident_end, incident_down_time):
    error_events = discover_errors_around_downtime(logs_client, log_group, incident_down_time)

    if error_events:
        context_logs = fetch_context_logs_for_errors(
            logs_client, log_group, error_events, incident_start
        )
    else:
        logger.info("[Fallback] No Phase-A errors; fetching full incident window")
        events = _fetch_raw_events(
            logs_client, log_group,
            int(incident_start.timestamp() * 1000),
            int(incident_end.timestamp() * 1000),
            limit=LOG_FETCH_LIMIT,
        )
        context_logs = [e["message"] for e in events]

    top_errors = [e["message"] for e in error_events if ERROR_PATTERN.search(e["message"])][:10]

    return {
        "error_events": error_events,
        "context_logs": context_logs,
        "top_errors":   top_errors,
    }


# ═══════════════════════════════════════════════════════════════
# SECTION 4 — Stack Detection
# ═══════════════════════════════════════════════════════════════

def detect_stack(ai_context: dict) -> list:
    combined = (
        json.dumps(ai_context.get("dependency_context", {})).lower()
        + ai_context.get("incident", {}).get("issue", "").lower()
        + " ".join(ai_context.get("logs", {}).get("top_errors", [])).lower()
    )
    checks = [
        (["docker", "container", "image", "dockerfile", "compose"],        "Docker"),
        (["nginx", "apache", "httpd"],                                     "Nginx/Apache"),
        (["redis", "elasticache", "cache"],                                "Redis"),
        (["rds", "postgres", "postgresql", "mysql", "database", " db "],   "Database (RDS/Postgres/MySQL)"),
        (["memory", "oom", "out of memory", "heap", "swap"],               "Memory/OOM"),
        (["disk", "storage", "iops", "ebs", "no space"],                   "Disk/EBS"),
        (["cpu", "utilization", "load average"],                            "CPU/Load"),
        (["network", "timeout", "connection", "alb", "elb", "502", "503"], "Network/ALB"),
        (["node", "npm", "javascript", "nodejs"],                           "Node.js"),
        (["python", "pip", "django", "flask", "gunicorn"],                 "Python"),
        (["java", "jvm", "spring", "heap space", "gc overhead"],           "Java/JVM"),
        (["ssl", "tls", "certificate", "cert"],                            "SSL/TLS"),
        (["cron", "scheduled", "lambda"],                                   "Scheduled Jobs"),
    ]
    detected = [label for keywords, label in checks if any(kw in combined for kw in keywords)]
    return detected if detected else ["General Linux/AWS"]


# ═══════════════════════════════════════════════════════════════
# SECTION 5 — Bedrock Prompt Builder
# ═══════════════════════════════════════════════════════════════

def _build_prompt(ai_context: dict, stack_hints: list) -> str:
    stack_str = ", ".join(stack_hints)
    stack_cli_hints = []
    if "Docker" in stack_hints:
        stack_cli_hints.append("docker ps -a, docker logs --tail 300 <container>, docker stats --no-stream")
    if "Network/ALB" in stack_hints:
        stack_cli_hints.append("netstat -tulnp, curl localhost health check, aws elbv2 describe-target-health")
    if "Database (RDS/Postgres/MySQL)" in stack_hints:
        stack_cli_hints.append("pg_stat_activity queries, slow query analysis, aws rds describe-db-instances")
    cli_hint_block = "\n".join(stack_cli_hints)

    return f"""
You are a Principal AWS Site Reliability Engineer with deep expertise in:
- AWS infrastructure, EC2 troubleshooting, Docker, ALB / networking
- Linux production debugging, distributed systems, root cause analysis

Analyze the following production incident carefully.

Detected stack:
{stack_str}

Relevant troubleshooting commands:
{cli_hint_block}

Incident telemetry:
{json.dumps(ai_context, indent=2, default=str)}

IMPORTANT RESPONSE RULES:
1. Return ONLY valid JSON
2. Do NOT use markdown code fences or triple backticks
3. rca_report must be plain text
4. remediation_steps must be plain text
5. Keep all content inside JSON strings
6. Never return invalid JSON

Return EXACTLY this schema:

{{
  "root_cause": "technical root cause",
  "confidence_score": 0.95,
  "impacted_dependencies": ["service1", "service2"],
  "prevention_recommendations": "detailed prevention recommendations",
  "rca_report": "DETAILED RCA REPORT AS SINGLE STRING",
  "remediation_steps": "DETAILED REMEDIATION STEPS AS SINGLE STRING"
}}

The rca_report should include: incident summary, metrics analysis, log analysis,
EC2 analysis, dependency analysis, detailed technical root cause, contributing
factors, timeline.

The remediation_steps should include: immediate actions, CLI commands,
verification steps, rollback steps, prevention checklist.
"""


# ═══════════════════════════════════════════════════════════════
# SECTION 6 — Bedrock Invocation
# ═══════════════════════════════════════════════════════════════

def invoke_bedrock_rca(ai_context: dict) -> dict:
    logger.info(f"Invoking Bedrock model: {BEDROCK_MODEL}")
    stack_hints = detect_stack(ai_context)
    logger.info(f"Detected stack: {stack_hints}")
    prompt = _build_prompt(ai_context, stack_hints)

    bedrock = boto3.client("bedrock-runtime", region_name=REGION)

    body = {"prompt": prompt, "max_gen_len": 4096, "temperature": 0.2, "top_p": 0.9}
    resp = bedrock.invoke_model(
        modelId=BEDROCK_MODEL,
        body=json.dumps(body),
        contentType="application/json",
        accept="application/json",
    )
    raw  = json.loads(resp["body"].read())
    text = raw.get("generation", raw.get("content", [{}])[0].get("text", ""))
    logger.info("Bedrock response received — parsing...")

    cleaned = re.sub(r"```json|```", "", text).strip()
    start   = cleaned.find("{")
    if start == -1:
        logger.warning("No JSON object found in Bedrock response")
        return _fallback_response(text)
    cleaned = cleaned[start:]

    try:
        decoder = json.JSONDecoder(strict=False)
        parsed, _ = decoder.raw_decode(cleaned)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse failed: {e}")
        return _fallback_response(text)

    logger.info(f"RCA parsed — confidence: {parsed.get('confidence_score')}")
    return parsed


def _fallback_response(raw_text: str) -> dict:
    return {
        "root_cause":                 "AI response parsing failed",
        "confidence_score":           0.3,
        "impacted_dependencies":      [],
        "prevention_recommendations": "Manual review required.",
        "rca_report":                 raw_text[:3000],
        "remediation_steps": (
            "1. Check EC2 health\n"
            "2. Review Docker container logs\n"
            "3. Verify application connectivity\n"
            "4. Check CloudWatch logs"
        ),
    }


# ═══════════════════════════════════════════════════════════════
# SECTION 7 — DB Status Helper
# ═══════════════════════════════════════════════════════════════

def update_status(event_id: str, status: str):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE meyiconnect.incidents
                SET status = %s, updated_at = NOW()
                WHERE event_id = %s
                """,
                (status, event_id),
            )
    logger.info(f"Status updated to '{status}' for event: {event_id}")


# ═══════════════════════════════════════════════════════════════
# SECTION 8 — Main Entry Point (called by worker)
# ═══════════════════════════════════════════════════════════════

def process_incident(payload: dict) -> None:
    """
    Process a single incident payload (equivalent to one SQS record).
    Runs synchronously in a thread pool worker.
    """
    logger.info("========== INCIDENT PROCESSOR STARTED ==========")
    logger.info(f"Payload keys: {list(payload.keys())}")

    event_id = payload.get("event_id", "unknown")

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM meyiconnect.incidents WHERE event_id = %s LIMIT 1",
                    (event_id,)
                )
                incident = cur.fetchone()

        if not incident:
            logger.error(f"Incident not found in DB for event_id: {event_id}")
            return

        instance_id    = incident["instance_id"]
        issue          = incident["issue"]
        severity       = incident["severity"]
        log_group_name = incident["log_group_name"]
        region         = incident.get("region") or "ap-south-1"

        dependency_ctx = incident.get("dependency_context") or {}
        if isinstance(dependency_ctx, str):
            try:
                dependency_ctx = json.loads(dependency_ctx)
            except Exception:
                dependency_ctx = {}

        def _parse_time(dt_val):
            if not dt_val:
                return None
            if isinstance(dt_val, str):
                return datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
            if dt_val.tzinfo is None:
                return dt_val.replace(tzinfo=timezone.utc)
            return dt_val

        incident_start = _parse_time(incident["incident_start_time"])
        incident_end = _parse_time(incident["incident_end_time"])
        incident_down_time = _parse_time(incident.get("incident_down_time")) or incident_start

        logger.info(
            f"Processing event: {event_id} | instance: {instance_id} | "
            f"region: {region} | down_time: {incident_down_time.isoformat()}"
        )

        local_ec2_client  = boto3.client("ec2",        region_name=region)
        local_cw_client   = boto3.client("cloudwatch", region_name=region)
        local_logs_client = boto3.client("logs",       region_name=region)

        # ── Phase 1: Fetch data in parallel ───────────────────────────────────
        update_status(event_id, "fetching_data")

        with ThreadPoolExecutor(max_workers=3) as pool:
            f_ec2     = pool.submit(get_ec2_details,  local_ec2_client,  instance_id)
            f_metrics = pool.submit(get_all_metrics,  local_cw_client,   instance_id)
            f_logs    = pool.submit(
                get_incident_logs_optimized,
                local_logs_client,
                log_group_name,
                incident_start,
                incident_end,
                incident_down_time,
            )
            ec2      = f_ec2.result()
            metrics  = f_metrics.result()
            log_data = f_logs.result()

        context_logs = log_data["context_logs"]
        top_errors   = log_data["top_errors"]
        error_events = log_data["error_events"]

        logger.info(
            f"All data fetched — "
            f"error_events={len(error_events)}, "
            f"context_logs={len(context_logs)}, "
            f"top_errors={len(top_errors)}"
        )

        # ── Store raw fetched data ─────────────────────────────────────────────
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO meyiconnect.incident_logs (
                        event_id, ec2_details, ec2_status_checks,
                        cloudwatch_metrics, raw_logs, logs_count
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        event_id,
                        json.dumps(ec2["details"]),
                        json.dumps(ec2["status_checks"]),
                        json.dumps(metrics),
                        json.dumps(context_logs),
                        len(context_logs),
                    ),
                )
                log_id = cur.fetchone()["id"]

        logger.info(f"Raw data stored, log record id: {log_id}")

        # ── Phase 2: Build AI context ──────────────────────────────────────────
        update_status(event_id, "finding_rca")

        ai_context = {
            "incident": {
                "event_id":            event_id,
                "issue":               issue,
                "severity":            severity,
                "incident_start_time": incident_start.isoformat() if incident_start else None,
                "incident_end_time":   incident_end.isoformat() if incident_end else None,
                "incident_down_time":  incident_down_time.isoformat() if incident_down_time else None,
            },
            "ec2": {
                "details":       ec2["details"],
                "status_checks": ec2["status_checks"],
            },
            "metrics": {
                "cpu_percent":         metrics.get("cpu_percent"),
                "network_in_bytes":    metrics.get("network_in_bytes"),
                "network_out_bytes":   metrics.get("network_out_bytes"),
                "disk_read_ops":       metrics.get("disk_read_ops"),
                "disk_write_ops":      metrics.get("disk_write_ops"),
                "status_check_failed": metrics.get("status_check_failed"),
            },
            "logs": {
                "total_count": len(context_logs),
                "error_count": len(error_events),
                "top_errors":  top_errors,
                "logs":        context_logs,
            },
            "dependency_context": {
                **dependency_ctx,
                "log_group_name": log_group_name,
            },
        }

        # ── Phase 3: Call Bedrock ──────────────────────────────────────────────
        rca = invoke_bedrock_rca(ai_context)

        # ── Store RCA ──────────────────────────────────────────────────────────
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO meyiconnect.incident_rca (
                        event_id, rca_report, remediation_steps,
                        confidence_score, ai_model_used,
                        impacted_dependencies, processing_status
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, 'completed')
                    """,
                    (
                        event_id,
                        rca.get("rca_report", ""),
                        rca.get("remediation_steps", ""),
                        float(rca.get("confidence_score", 0.5)),
                        BEDROCK_MODEL,
                        json.dumps(rca.get("impacted_dependencies", [])),
                    ),
                )

        update_status(event_id, "completed")
        logger.info(f"========== EVENT COMPLETED: {event_id} ==========")

    except Exception as e:
        logger.exception(f"Processing failed for event: {event_id}")
        try:
            update_status(event_id, "failed")
        except Exception:
            logger.exception("Failed to update status to failed")
        raise
