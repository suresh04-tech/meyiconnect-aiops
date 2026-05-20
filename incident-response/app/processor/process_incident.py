"""
processor/process_incident.py
─────────────────────────────
Core RCA processing logic — called by the worker thread pool.

What's changed from previous version
──────────────────────────────────────
• Only incident_down_time is required from DB.  incident_start_time and
  incident_end_time are no longer used — the log_processor derives smarter
  windows automatically using adaptive lookback + first-error anchoring.

• severity and issue are forwarded to log_processor so the adaptive window
  calculator can decide the correct lookback (e.g. 60 min for critical/OOM).

• The Bedrock prompt is now stage-aware: it shows the three-stage labelled
  timeline (buildup / failure / impact) so the model can reason about when
  the problem started vs when it was detected.

• Multi-log-group support: log_group_names column (JSON array, CSV, or single
  value) is parsed and all groups are processed in parallel.
"""

import os
import json
import boto3
import logging
import re
from botocore.config import Config
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.utils.db import get_db
from app.processor.log_processor import fetch_and_compress_logs
from botocore.config import Config

logger = logging.getLogger(__name__)

# ─── Config ────────────────────────────────────────────────────────────────────
REGION        = os.environ.get("AWS_REGION", "ap-south-1")
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL_ID", "meta.llama3-8b-instruct-v1:0")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CloudWatch Metrics
# ═══════════════════════════════════════════════════════════════════════════════

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
        return sorted(points, key=lambda x: x["Timestamp"], reverse=True)[0].get(stat)
    except Exception as exc:
        logger.warning(f"Metric {metric_name} fetch failed: {exc}")
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


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — EC2 Details
# ═══════════════════════════════════════════════════════════════════════════════

def get_ec2_details(ec2_client, instance_id: str) -> dict:
    logger.info(f"Fetching EC2 details for: {instance_id}")
    details, status_checks = {}, {}

    try:
        resp         = ec2_client.describe_instances(InstanceIds=[instance_id])
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
    except Exception as exc:
        logger.warning(f"describe_instances failed: {exc}")

    try:
        resp     = ec2_client.describe_instance_status(
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
    except Exception as exc:
        logger.warning(f"describe_instance_status failed: {exc}")

    return {"details": details, "status_checks": status_checks}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Token-safe Prompt Builder
# ═══════════════════════════════════════════════════════════════════════════════

def _format_log_summary_for_prompt(log_data: dict) -> str:
    """
    Convert the compressed, stage-aware log_processor output into a compact,
    readable text block for the Bedrock prompt.

    Format per log group:
        ┌─ LOG GROUP: /aws/aiops-test/nginx-error ─────────────────────────────
        │ STAGE 1 — Pre-failure buildup  [09:43 – 09:48]
        │   Lines: 42 | Errors: 0 | Warnings: 3
        │   (no error/warn patterns)
        │
        │ STAGE 2 — Failure propagation  [09:48 – 10:00]
        │   Lines: 187 | Errors: 143 | Warnings: 8
        │   [x143] [ERROR] access forbidden by rule … request: "GET /pinfo.php …"
        │   [x8]   [WARN]  upstream response time 29.8 …
        │
        │ STAGE 3 — Impact / recovery  [10:00 – 10:10]
        │   Lines: 31 | Errors: 28 | Warnings: 0
        │   [x28]  [ERROR] connect() failed (111: Connection refused) …
        └──────────────────────────────────────────────────────────────────────
    """
    lines = []

    per_group = log_data.get("per_group", {})
    if not per_group:
        return "No log data available."

    stages_meta = {s["name"]: s for s in log_data.get("stages", [])}

    for group_name, group_stages in per_group.items():
        lines.append(f"\n╔═ LOG GROUP: {group_name}")

        for stage_idx, (sname, summary) in enumerate(group_stages.items(), 1):
            label  = summary.get("stage_label", sname)
            window = summary.get("window", "")
            lines.append(
                f"║ STAGE {stage_idx} — {label}  [{window}]"
            )
            lines.append(
                f"║   Lines: {summary['total_raw']} | "
                f"Errors: {summary['error_count']} | "
                f"Warnings: {summary['warn_count']}"
            )

            clusters = summary.get("clusters", [])
            if clusters:
                for c in clusters:
                    tag    = f"[x{c['count']}]" if c["count"] > 1 else "      "
                    level  = c["level"].upper()
                    sample = (c["samples"][0] if c["samples"] else c["fingerprint"])[:250]
                    lines.append(f"║   {tag} [{level}] {sample}")
            else:
                lines.append("║   (no error/warn patterns in this stage)")

            ctx = summary.get("context_lines", [])
            if ctx:
                lines.append("║   Context:")
                for cl in ctx[:5]:
                    lines.append(f"║     {cl[:180]}")

            lines.append("║")

        lines.append("╚" + "═" * 60)

    return "\n".join(lines)


def _build_prompt(
    incident_id:        str,
    issue:              str,
    severity:           str,
    down_time_iso:      str,
    ec2:                dict,
    metrics:            dict,
    log_data:           dict,
    dependency_ctx:     dict,
) -> str:
    log_summary_text = _format_log_summary_for_prompt(log_data)
    top_errors_text  = "\n".join(f"  • {e}" for e in log_data.get("top_errors", []))

    anchor = log_data.get("anchor", {})
    anchor_text = (
        f"Pulse detected outage at : {down_time_iso}\n"
        f"First error in logs      : {anchor.get('first_error_ts') or 'not found'}\n"
        f"First error group        : {anchor.get('first_error_group') or 'n/a'}\n"
        f"First error message      : {anchor.get('first_error_msg') or 'n/a'}\n"
        f"Investigation anchored to: {anchor.get('true_start')}\n"
        f"Adaptive lookback used   : {log_data.get('adaptive_window', {}).get('before_minutes')} min"
    )

    d  = ec2.get("details", {})
    sc = ec2.get("status_checks", {})
    ec2_text = (
        f"Instance : {d.get('instance_id')} ({d.get('instance_type')})  "
        f"State: {d.get('state')}  AZ: {d.get('availability_zone')}\n"
        f"Status   : instance={sc.get('instance_status')}  system={sc.get('system_status')}\n"
        f"Tags     : {json.dumps(d.get('tags', {}))}"
    )

    def _fmt(v):
        return f"{v:.2f}" if v is not None else "n/a"

    metrics_text = (
        f"CPU: {_fmt(metrics.get('cpu_percent'))}%  "
        f"NetIn: {_fmt(metrics.get('network_in_bytes'))} B  "
        f"NetOut: {_fmt(metrics.get('network_out_bytes'))} B  "
        f"DiskRd: {_fmt(metrics.get('disk_read_ops'))} ops  "
        f"DiskWr: {_fmt(metrics.get('disk_write_ops'))} ops  "
        f"StatusFailed: {_fmt(metrics.get('status_check_failed'))}"
    )

    dep_text = json.dumps(dependency_ctx, indent=2, default=str) if dependency_ctx else "none"

    return f"""You are a Principal AWS Site Reliability Engineer with deep expertise in diagnosing EC2 production incidents through causal chain analysis.

Your role is NOT to summarize logs. Your role is to reason like a senior SRE conducting a live postmortem.

═══ INCIDENT ═══
Event ID  : {incident_id}
Severity  : {severity.upper()}
Issue     : {issue}

═══ TIME ANCHOR ═══
{anchor_text}

Note: Logs are split into 3 stages for precise timeline reasoning:
  Stage 1 (buildup)  — system state BEFORE the first error. Look for degradation signals, rising latency, or resource drift.
  Stage 2 (failure)  — the active failure window. This is where the root cause manifests. Focus here.
  Stage 3 (impact)   — cascading failures AFTER health check failed. These are SYMPTOMS, not causes.

Do NOT mistake Stage 3 cascades for root cause.

═══ EC2 SNAPSHOT ═══
{ec2_text}

═══ CLOUDWATCH METRICS (last 15 min before analysis) ═══
{metrics_text}

Metrics interpretation guide:
  • Low CPU + no disk pressure + connection timeouts → dependency saturation or connection pool exhaustion, NOT host failure
  • High CPU + disk pressure → resource exhaustion on EC2 itself
  • All metrics clean → failure is external (dependency, network policy, auth)
  • StatusCheckFailed=1 → underlying host issue regardless of app logs

═══ TOP ERROR SIGNALS (global, across all log groups) ═══
{top_errors_text if top_errors_text else "  (none identified)"}

═══ DETAILED LOG ANALYSIS (per group, per stage, deduplicated) ═══
{log_summary_text}

═══ DEPENDENCY CONTEXT ═══
{dep_text}

═══ CAUSAL CHAIN REASONING FRAMEWORK ═══

You must reason through these layers IN ORDER before writing your conclusion:

LAYER 1 — SYMPTOM (what the logs report):
  What error messages appear? What HTTP codes? What timeouts?

LAYER 2 — MECHANISM (what failure mode produced those symptoms):
  WHY did those errors occur?
  - Connection pool exhausted → new requests block → timeout at connect_timeout threshold
  - Dependency saturated → all TCP slots occupied → SYN packets queued → timeout
  - Auth failure → immediate rejection, not timeout
  - Memory leak → gradual latency rise, then OOM
  - Deadlock → specific operations hang while others succeed
  - Config change → sudden onset with no buildup

LAYER 3 — TRIGGER (what caused the mechanism):
  What changed or reached a threshold right before Stage 2?
  - Traffic spike
  - Dependency service degradation (not full outage)
  - Connection leak reaching pool limit
  - Certificate expiry
  - Database max_connections reached
  - Rate limit hit

LAYER 4 — ROOT CAUSE (the single underlying operational failure):
  The most specific, actionable technical statement of what actually broke.
  NOT: "database was unavailable"
  YES: "psycopg2 connection acquisition blocked because all N connections in the pool were held by concurrent health-check requests, each waiting 9s for a saturated remote PostgreSQL instance, exhausting the pool and cascading HTTP 500s"

LAYER 5 — CASCADE PATH:
  How did the root cause propagate from Stage 2 into Stage 3?

═══ CRITICAL REASONING RULES ═══

1. EC2 metrics are your control group.
   If CPU, disk, and StatusCheck are all healthy → the EC2 host is NOT the problem.
   Do not conclude "infrastructure failure" when metrics show a healthy instance.

2. Identical repeated errors at consistent intervals indicate saturation, not outage.
   A complete outage produces immediate failure. Saturation produces timeout storms
   with consistent duration (e.g. exactly connect_timeout seconds).

3. Duration clustering is a key signal.
   If duration_ms clusters around a fixed value (e.g. 9000ms = 9s connect_timeout),
   requests are hitting the connection timeout, not failing instantly.
   This means: connections are being attempted but never completing.
   Cause: remote saturation OR local pool exhaustion.

4. Do NOT attribute failures to cloud provider infrastructure (AWS, Render, etc.)
   unless you have explicit evidence of provider-side failure.
   Connection timeouts alone are NOT evidence of provider outage.
   They are evidence of: pool exhaustion, rate limiting, or dependency saturation.

5. Differentiate these clearly:
   - root_cause       → the single underlying mechanism
   - trigger          → what pushed the system into failure
   - cascade          → downstream failures caused by root_cause
   Do NOT list cascades as root causes.

6. Remediation must directly address the root cause you identified.
   - If root cause is connection pool exhaustion → fix is connection pooling configuration
   - If root cause is dependency saturation    → fix is circuit breaker + backoff
   - If root cause is resource exhaustion       → fix is capacity/scaling
   - If root cause is application bug           → fix is the specific code path
   Never recommend generic steps like "restart the application" or "check logs"
   unless restart is the specific correct fix with a clear reason why.

7. Every remediation step must answer: "Why does THIS step fix THIS root cause?"

═══ OUTPUT INSTRUCTIONS ═══

You MUST return ONLY a valid JSON object.

Do NOT:
- add markdown
- add explanations
- add comments
- add ```json fences
- add text before or after JSON

Your ENTIRE response must start with {{ and end with }}.

Missing information → use "unknown".

The response MUST be parseable by Python json.loads().

Schema:
{{
  "root_cause": "Single precise technical statement of the underlying failure mechanism. Include: what failed, why it failed, and what evidence confirms it. 2-3 sentences max.",

  "confidence_score": 0.0-1.0,

  "actual_incident_start": "ISO timestamp of when the problem actually started (use Stage 2 onset, not Pulse detection time)",

  "impacted_services": ["list of directly affected services — not cascades"],

  "severity_assessment": "Blast radius: what was broken, what was NOT broken, scope of user impact",

  "rca_report": {{
    "summary": "2-3 sentence executive summary: what broke, why, and what the impact was",

    "timeline": {{
      "buildup": "What Stage 1 shows. Was the system healthy? Any early signals? Exact timestamps.",
      "failure": "What triggered Stage 2. The precise moment and mechanism of failure onset.",
      "impact": "How Stage 2 cascaded into Stage 3. What broke as a consequence."
    }},

    "metrics_analysis": "Explicit interpretation of each metric. State what each metric rules IN or OUT as a cause. Do not skip metrics.",

    "infra_change_analysis": "Any evidence of config, deployment, or infrastructure change before the incident. If none visible: state that explicitly.",

    "log_analysis": {{
      "application": "What the application logs reveal about failure mechanism. Include error counts, timing patterns, and what they imply about the failure type.",
      "nginx": "Nginx log findings, or 'not available' if no nginx logs present",
      "system": "System-level log findings, or 'not available'",
      "database": "Database-side log findings. If not directly available, infer from application-side DB errors."
    }},

    "root_cause_analysis": "Full causal chain: Symptom → Mechanism → Trigger → Root Cause. Explain each step with evidence from the logs. This should read like a postmortem, not a summary.",

    "contributing_factors": ["List of factors that worsened the incident but are not the root cause"],

    "blast_radius": "Specific description of what was unavailable, for how long, and what was unaffected"
  }},

  "remediation_steps": {{
    "immediate_actions": [
      "Each action must be specific and directly address the root cause.",
      "Include the exact command, config change, or operation — not a vague instruction.",
      "State WHY each action works against the identified root cause.",
      "Example format: 'Run: sudo systemctl restart <service> — this clears the exhausted connection pool so the app re-establishes fresh connections to the DB'"
    ],

    "verification_steps": [
      "Specific checks to confirm recovery. Include exact log patterns or metrics to look for.",
      "Example: 'Confirm health endpoint returns HTTP 200 within 200ms for 5 consecutive requests'"
    ],

    "rollback_steps": [
      "Only if a recent change is implicated as trigger. Otherwise state: 'No rollback applicable — failure was operational, not change-induced.'"
    ],

    "communication_template": "Plain-language status update for stakeholders. Include: what is broken, what is being done, and next update time."
  }}
}}
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Bedrock Invocation
# ═══════════════════════════════════════════════════════════════════════════════

def _invoke_bedrock(prompt: str) -> dict:

    logger.info(f"Invoking Bedrock: {BEDROCK_MODEL}")

    config = Config(
        read_timeout=300,
        retries={
            "max_attempts": 3
        }
    )
    bedrock = boto3.client("bedrock-runtime", region_name=REGION, config=config)

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 8192,
        "temperature": 0.1,
        "top_p": 0.9,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    }
    resp = bedrock.invoke_model(
        modelId=BEDROCK_MODEL,
        body=json.dumps(body),
        contentType="application/json",
        accept="application/json",
    )
    raw  = json.loads(resp["body"].read())
    text = raw["content"][0]["text"]
    logger.info("Bedrock response received — parsing...")
    logger.info(
        f"[Bedrock Raw Response]\n{text[:8000]}"
    )

    cleaned = re.sub(r"```json|```", "", text).strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        logger.warning("No JSON object in Bedrock response")
        logger.info(f"[Raw Bedrock Output]\n{text}")
        return _fallback_rca(text)

    cleaned = match.group(0)
    try:
        decoder = json.JSONDecoder(strict=False)
        parsed, _ = decoder.raw_decode(cleaned)
        logger.info(f"RCA parsed | confidence: {parsed.get('confidence_score')}")
        return parsed
    except json.JSONDecodeError as exc:
        logger.error(f"JSON parse failed: {exc} | first 500: {cleaned[:500]}")
        return _fallback_rca(text)


def _fallback_rca(raw_text: str) -> dict:
    return {
        "root_cause":                 "AI response parsing failed — manual review required",
        "confidence_score":           0.3,
        "actual_incident_start":      "unknown",
        "impacted_services":          [],
        "severity_assessment":        "Unknown",
        "rca_report":                 raw_text[:3000],
        "remediation_steps": (
            "1. Check EC2 instance health in AWS console\n"
            "2. Review all CloudWatch log groups manually\n"
            "3. Verify application process is running (systemctl / docker ps)\n"
            "4. Check disk, memory, and CPU utilisation\n"
            "5. Inspect security group and network ACL rules"
        ),
        "prevention_recommendations": {
            "monitoring": [],
            "security": [],
            "infrastructure": [],
            "application": [],  
            "operational": []
        }
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — DB Helpers
# ═══════════════════════════════════════════════════════════════════════════════

STATUS_PROGRESS = {
    "queued": 5,

    "fetching_ec2": 15,
    "fetching_metrics": 25,
    "fetching_logs": 40,

    "compressing_logs": 55,
    "building_prompt": 65,

    "finding_rca": 80,
    "storing_results": 95,

    "completed": 100,
    "failed": 0,
}

def _update_status(incident_id: str, status: str) -> None:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE meyiconnect.insight_incidents
                SET analysis_status = %s,
                    analysis_percent = %s,
                    updated_at = NOW()
                WHERE id = %s
                """,
                (status, STATUS_PROGRESS.get(status, 0), incident_id),
            )
    logger.info(f"Status → '{status}' for {incident_id}")


def _parse_time(dt_val) -> datetime | None:
    if not dt_val:
        return None
    if isinstance(dt_val, str):
        return datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
    if isinstance(dt_val, datetime):
        return dt_val if dt_val.tzinfo else dt_val.replace(tzinfo=timezone.utc)
    return None



# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def process_incident(payload: dict) -> None:
    """
    Process a single incident.  Called by the worker thread pool.

    payload requires only {"incident_id": str}.
    All other data is read from meyiconnect.insight_incidents.

    New schema uses a `dependencies` JSONB array:
      [{"instance_id": str, "region": str, "log_group_name": [str, ...]}, ...]
    """
    logger.info("========== INCIDENT PROCESSOR STARTED ==========")
    incident_id = payload.get("incident_id", "unknown")

    try:
        # ── Load incident ──────────────────────────────────────────────────────
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM meyiconnect.insight_incidents WHERE id = %s LIMIT 1",
                    (incident_id,),
                )
                incident = cur.fetchone()

        if not incident:
            logger.error(f"Incident not found in DB: {incident_id}")
            return

        # ── Validate Required Fields ───────────────────────────────────────────
        if not incident.get("incident_down_time"):
            logger.error(f"Missing incident_down_time for incident {incident_id}")
            _update_status(incident_id, "failed")
            return

        issue    = incident.get("issue")    or ""
        severity = incident.get("severity") or "medium"

        # ── Parse dependencies array ───────────────────────────────────────────
        raw_deps = incident.get("dependencies") or []
        if isinstance(raw_deps, str):
            try:
                raw_deps = json.loads(raw_deps)
            except Exception:
                raw_deps = []

        if not raw_deps:
            logger.error(f"No dependencies defined for incident {incident_id} — cannot process")
            _update_status(incident_id, "failed")
            return

        # Use the first dependency as the primary EC2 target
        dep = raw_deps[0]
        instance_id = dep.get("instance_id")
        region      = dep.get("region")
        
        if not instance_id:
            logger.error(f"Missing instance_id in dependencies for incident {incident_id}")
            _update_status(incident_id, "failed")
            return
            
        if not region:
            logger.error(f"Missing region in dependencies for incident {incident_id}")
            _update_status(incident_id, "failed")
            return

        # Collect log groups from ALL dependencies (multi-instance support)
        log_groups: list[str] = []
        for d in raw_deps:
            raw_lg = d.get("log_group_name") or d.get("log_group_names") or []
            if isinstance(raw_lg, str):
                raw_lg = [g.strip() for g in raw_lg.split(",") if g.strip()]
            log_groups.extend([g for g in raw_lg if g])

        if not log_groups:
            logger.error(f"Missing log_group_name in dependencies for incident {incident_id}")
            _update_status(incident_id, "failed")
            return

        # dependency_ctx for cascade attribution (keep as dict)
        dependency_ctx = incident.get("dependency_context") or {}
        if isinstance(dependency_ctx, str):
            try:
                dependency_ctx = json.loads(dependency_ctx)
            except Exception:
                dependency_ctx = {}

        # incident_down_time
        incident_down_time = _parse_time(incident.get("incident_down_time"))
        if not incident_down_time:
            logger.error(f"Invalid incident_down_time for {incident_id}")
            _update_status(incident_id, "failed")
            return

        logger.info(
            f"Event: {incident_id} | instance: {instance_id} | region: {region} | "
            f"severity: {severity} | down_time: {incident_down_time.isoformat()} | "
            f"log_groups: {log_groups}"
        )

        # ── AWS clients ──────────────────────────────────────────────────────────────
        boto_config = Config(max_pool_connections=50)
        ec2_client  = boto3.client("ec2",        region_name=region)
        cw_client   = boto3.client("cloudwatch", region_name=region)
        logs_client = boto3.client("logs",       region_name=region, config=boto_config)

        # ── Fetch EC2 details, metrics, and logs ────────────────────────────────
        _update_status(incident_id, "fetching_ec2")
        ec2 = get_ec2_details(ec2_client, instance_id)

        _update_status(incident_id, "fetching_metrics")
        metrics = get_all_metrics(cw_client, instance_id)

        log_data = fetch_and_compress_logs(
            logs_client,
            log_groups,
            incident_down_time,   
            severity,             
            issue,
            dependency_context=dependency_ctx,
            status_callback=lambda st: _update_status(incident_id, st)
        )

        if log_data["total_raw_lines"] == 0:
            logger.warning(
                "[RCA Warning] "
                "No CloudWatch logs retrieved for investigation window"
            )

        logger.info(
            f"Data fetched | "
            f"adaptive_window={log_data['adaptive_window']} | "
            f"anchor={log_data['anchor']} | "
            f"stages={[s['name'] for s in log_data['stages']]} | "
            f"error_events={len(log_data['error_events'])} | "
            f"total_raw={log_data['total_raw_lines']}"
        )

        # ── Store raw fetched data ─────────────────────────────────────────────
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO meyiconnect.incident_logs (
                        incident_id, ec2_details, ec2_status_checks,
                        cloudwatch_metrics, raw_logs, logs_count
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        incident_id,
                        json.dumps(ec2["details"]),
                        json.dumps(ec2["status_checks"]),
                        json.dumps(metrics),
                        json.dumps({                         # store structured summary, not raw lines
                            "anchor":    log_data["anchor"],
                            "stages":    log_data["stages"],
                            "per_group": log_data["per_group"],
                        }),
                        log_data["total_raw_lines"],
                    ),
                )
                log_id = cur.fetchone()["id"]

        logger.info(f"Data stored | log_id: {log_id}")

        # ── Build Bedrock prompt ───────────────────────────────────────────────
        _update_status(incident_id, "building_prompt")

        prompt = _build_prompt(
            incident_id    = incident_id,
            issue          = issue,
            severity       = severity,
            down_time_iso  = incident_down_time.isoformat(),
            ec2            = ec2,
            metrics        = metrics,
            log_data       = log_data,
            dependency_ctx = dependency_ctx,
        )

        # ── Invoke Bedrock ─────────────────────────────────────────────────────
        _update_status(incident_id, "finding_rca")
        estimated_tokens = len(prompt) // 4

        if estimated_tokens > 25000:
            logger.warning(
                f"[Prompt Size Warning] "
                f"Large prompt detected: ~{estimated_tokens} tokens"
            )

        logger.info(
            f"[Bedrock Prompt] "
            f"chars={len(prompt)} | "
            f"estimated_tokens={estimated_tokens} | "
            f"top_errors={len(log_data.get('top_errors', []))} | "
            f"groups={len(log_data.get('per_group', {}))}"
        )

        logger.info(
            f"[Bedrock Prompt Preview]\n{prompt[:8000]}"
        )
        rca = _invoke_bedrock(prompt)

        logger.info(
            f"[RCA Summary] "
            f"confidence={rca.get('confidence_score')} | "
            f"root_cause={rca.get('root_cause', '')[:300]}"
        )

        with get_db() as conn:
            with conn.cursor() as cur:
                confidence_percentage = round(
                    float(rca.get("confidence_score", 0.5)) * 100,
                    2
                )

                rca_report_val = rca.get("rca_report", {})
                if isinstance(rca_report_val, dict):
                    rca_report_val = json.dumps(rca_report_val)
                    
                remediation_val = rca.get("remediation_steps", {})
                if isinstance(remediation_val, dict):
                    remediation_val = json.dumps(remediation_val)

                cur.execute(
                    """
                    UPDATE meyiconnect.insight_incidents
                    SET
                        analysis_status = 'completed',
                        analysis_percent = 100,
                        analysis_result = %s,
                        remediation_steps = %s,
                        confidence_score = %s,
                        ai_model_used = %s,
                        analysis_completed_at = NOW(),
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (
                        rca_report_val,
                        remediation_val,
                        str(confidence_percentage),
                        BEDROCK_MODEL,
                        incident_id,
                    ),
                )
                
                logger.info(f"Rows updated: {cur.rowcount}")

            conn.commit()
            
        logger.info(f"========== EVENT COMPLETED: {incident_id} ==========")

    except Exception:
        logger.exception(f"Processing failed for event: {incident_id}")
        try:
            _update_status(incident_id, "failed")
        except Exception:
            logger.exception("Failed to update status to failed")
        raise