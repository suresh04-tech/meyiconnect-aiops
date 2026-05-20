"""
processor/process_incident.py
─────────────────────────────
Core RCA processing logic — called by the worker thread pool.

Architecture (HA/ALB-aware)
────────────────────────────
  Incident
    └─ DependencyResolver          ← NEW: resolves EC2 / ALB → normalized targets
         └─ [i-1, i-2, i-3, ...]  (parallel collection via ThreadPoolExecutor)
              ├─ EC2 details
              ├─ CloudWatch metrics
              └─ CloudWatch logs
         └─ CorrelationEngine      ← NEW: cross-instance comparison + scenario detection
         └─ PromptBuilder          ← updated for multi-instance matrix
         └─ Bedrock RCA

Dependency input schema (stored in DB `dependencies` JSONB column)
──────────────────────────────────────────────────────────────────
  Single EC2:
    [{"type": "ec2",
      "resource_id": "i-01cbe3e1e9e371033",
      "region": "us-east-1",
      "log_group_name": ["group-a"]}]

  ALB (DNS name):
    [{"type": "alb",
      "resource_id": "internal-api-prod-alb.us-east-1.elb.amazonaws.com",
      "region": "us-east-1",
      "log_group_name": ["group-a", "group-b"]}]
"""

import os
import json
import logging
import re
from botocore.config import Config
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.utils.db import get_db
from app.processor.log_processor import fetch_and_compress_logs
from app.processor.dependency_resolver import resolve_dependencies
from app.processor.correlation_engine import correlate_instances
from app.utils.aws_connector import AWSClientFactory

logger = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────
REGION        = os.environ.get("AWS_REGION", "ap-south-1")
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL_ID", "meta.llama3-8b-instruct-v1:0")

# Max parallel instance collectors
MAX_COLLECTOR_WORKERS = int(os.environ.get("MAX_COLLECTOR_WORKERS", "10"))


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CloudWatch Metrics (per instance)
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
    logger.info(f"Metrics collected for {instance_id}: {results}")
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
# SECTION 3 — Parallel per-instance collector
# ═══════════════════════════════════════════════════════════════════════════════

def _collect_instance(
    target: dict,
    incident_down_time: datetime,
    severity: str,
    issue: str,
    dependency_ctx: dict,
    status_callback,
    aws_factory: AWSClientFactory,
) -> dict:
    """
    Collect EC2 details, metrics, and logs for a single instance.
    Designed to be run inside a ThreadPoolExecutor.
    """
    instance_id = target["instance_id"]
    region      = target["region"]
    log_groups  = target["log_groups"]

    boto_config = Config(max_pool_connections=50)
    ec2_client  = aws_factory.get_client("ec2",        region_name=region)
    cw_client   = aws_factory.get_client("cloudwatch", region_name=region)
    logs_client = aws_factory.get_client("logs",       region_name=region, config=boto_config)

    ec2     = get_ec2_details(ec2_client, instance_id)
    metrics = get_all_metrics(cw_client, instance_id)

    log_data = {"total_raw_lines": 0, "per_group": {}, "top_errors": [],
                "anchor": {}, "stages": [], "adaptive_window": {}}

    if log_groups:
        try:
            log_data = fetch_and_compress_logs(
                logs_client,
                log_groups,
                incident_down_time,
                severity,
                issue,
                dependency_context=dependency_ctx,
                status_callback=status_callback,
            )
        except Exception as exc:
            logger.warning(f"[Collector] Log fetch failed for {instance_id}: {exc}")

    # Total error count across all stages / groups (used by correlation engine)
    total_errors = sum(
        stage.get("error_count", 0)
        for group_stages in log_data.get("per_group", {}).values()
        for stage in group_stages.values()
    )

    return {
        "instance_id":     instance_id,
        "region":          region,
        "target_health":   target.get("target_health", "unknown"),
        "target_reason":   target.get("target_reason", ""),
        "ec2":             ec2,
        "metrics":         metrics,
        "log_summary":     log_data,
        "top_errors":      log_data.get("top_errors", []),
        "total_error_count": total_errors,
    }


def collect_all_instances(
    targets: list[dict],
    incident_down_time: datetime,
    severity: str,
    issue: str,
    dependency_ctx: dict,
    status_callback,
    aws_factory: AWSClientFactory,
) -> dict:
    """
    Collect data for all resolved instances in parallel.
    Returns {instance_id: analysis_dict}.
    """
    results: dict = {}
    max_workers = min(MAX_COLLECTOR_WORKERS, len(targets))

    with ThreadPoolExecutor(max_workers=max_workers,
                            thread_name_prefix="instance-collector") as pool:
        futures = {
            pool.submit(
                _collect_instance,
                target,
                incident_down_time,
                severity,
                issue,
                dependency_ctx,
                status_callback,
                aws_factory,
            ): target["instance_id"]
            for target in targets
        }
        for future in as_completed(futures):
            iid = futures[future]
            try:
                results[iid] = future.result()
                logger.info(f"[Collector] Completed: {iid}")
            except Exception as exc:
                logger.error(f"[Collector] Failed for {iid}: {exc}")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Prompt Builder (multi-instance aware)
# ═══════════════════════════════════════════════════════════════════════════════

def _format_log_summary_for_prompt(log_data: dict) -> str:
    lines = []
    per_group = log_data.get("per_group", {})
    if not per_group:
        return "No log data available."

    for group_name, group_stages in per_group.items():
        lines.append(f"\n╔═ LOG GROUP: {group_name}")
        for stage_idx, (sname, summary) in enumerate(group_stages.items(), 1):
            label  = summary.get("stage_label", sname)
            window = summary.get("window", "")
            lines.append(f"║ STAGE {stage_idx} — {label}  [{window}]")
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
            lines.append("║")
        lines.append("╚" + "═" * 60)

    return "\n".join(lines)


def _build_instance_matrix_text(correlation: dict) -> str:
    """Format the comparison matrix for the prompt."""
    rows  = correlation.get("comparison_matrix", [])
    lines = []
    for r in rows:
        health_icon = "✗ UNHEALTHY" if r["health"] == "unhealthy" else "✓ healthy"
        lines.append(
            f"  [{health_icon}] {r['instance_id']}"
            f"  CPU={r['cpu']}%"
            f"  EC2-status={r['status_check']}"
            f"  ALB-target={r['target_health']}"
            f"  errors={r['error_count']}"
        )
        if r["target_reason"]:
            lines.append(f"    ↳ ALB reason: {r['target_reason']}")
        if r["top_errors"]:
            for e in r["top_errors"][:2]:
                lines.append(f"    ↳ {e[:150]}")
    return "\n".join(lines)


def _build_prompt_multi(
    incident_id:    str,
    issue:          str,
    severity:       str,
    down_time_iso:  str,
    instance_analyses: dict,   # {iid: analysis}
    correlation:    dict,
    alb_meta:       dict,
    dependency_ctx: dict,
    primary_instance_id: str,
) -> str:
    """
    Build Bedrock prompt for multi-instance (ALB-aware) analysis.
    Uses a compact comparison matrix to avoid token explosion.
    Primary suspect gets full log details; others get summary-only.
    """
    primary = instance_analyses.get(primary_instance_id, {})
    primary_log = primary.get("log_summary", {})

    log_summary_text = _format_log_summary_for_prompt(primary_log)
    top_errors_text  = "\n".join(
        f"  • {e}" for e in primary_log.get("top_errors", [])
    )

    anchor = primary_log.get("anchor", {})
    anchor_text = (
        f"Pulse detected outage at : {down_time_iso}\n"
        f"First error in logs      : {anchor.get('first_error_ts') or 'not found'}\n"
        f"First error group        : {anchor.get('first_error_group') or 'n/a'}\n"
        f"First error message      : {anchor.get('first_error_msg') or 'n/a'}\n"
        f"Investigation anchored to: {anchor.get('true_start')}\n"
        f"Adaptive lookback used   : {primary_log.get('adaptive_window', {}).get('before_minutes')} min"
    )

    primary_ec2 = primary.get("ec2", {})
    d  = primary_ec2.get("details", {})
    sc = primary_ec2.get("status_checks", {})
    primary_ec2_text = (
        f"Instance : {d.get('instance_id')} ({d.get('instance_type')})  "
        f"State: {d.get('state')}  AZ: {d.get('availability_zone')}\n"
        f"Status   : instance={sc.get('instance_status')}  system={sc.get('system_status')}\n"
        f"Tags     : {json.dumps(d.get('tags', {}))}"
    )

    def _fmt(v):
        return f"{v:.2f}" if v is not None else "n/a"

    m = primary.get("metrics", {})
    primary_metrics_text = (
        f"CPU: {_fmt(m.get('cpu_percent'))}%  "
        f"NetIn: {_fmt(m.get('network_in_bytes'))} B  "
        f"NetOut: {_fmt(m.get('network_out_bytes'))} B  "
        f"DiskRd: {_fmt(m.get('disk_read_ops'))} ops  "
        f"DiskWr: {_fmt(m.get('disk_write_ops'))} ops  "
        f"StatusFailed: {_fmt(m.get('status_check_failed'))}"
    )

    scenario       = correlation.get("scenario", "?")
    scenario_desc  = correlation.get("scenario_description", "")
    matrix_text    = _build_instance_matrix_text(correlation)
    common_errors  = "\n".join(f"  • {e}" for e in correlation.get("common_errors", []))
    isolated_errors_text = json.dumps(correlation.get("isolated_errors", {}), indent=2)

    alb_text = ""
    if alb_meta:
        alb_text = (
            f"ALB DNS           : {alb_meta.get('alb_dns')}\n"
            f"Total targets     : {alb_meta.get('total')}\n"
            f"Healthy targets   : {alb_meta.get('healthy')}\n"
            f"Unhealthy targets : {alb_meta.get('unhealthy')}\n"
        )

    dep_text = json.dumps(dependency_ctx, indent=2, default=str) if dependency_ctx else "none"

    return f"""You are a Principal AWS Site Reliability Engineer with deep expertise in diagnosing production incidents through causal chain analysis.

Your role is NOT to summarize logs. Your role is to reason like a senior SRE conducting a live postmortem.

═══ INCIDENT ═══
Event ID  : {incident_id}
Severity  : {severity.upper()}
Issue     : {issue}

═══ TIME ANCHOR ═══
{anchor_text}

Note: Logs are split into 3 stages for precise timeline reasoning:
  Stage 1 (buildup)  — system state BEFORE the first error.
  Stage 2 (failure)  — the active failure window. Root cause manifests here.
  Stage 3 (impact)   — cascading failures AFTER health check failed. These are SYMPTOMS, not causes.

═══ INFRASTRUCTURE OVERVIEW ═══
Total instances  : {correlation.get('total_count', 1)}
Healthy          : {correlation.get('healthy_count', 0)}
Unhealthy        : {correlation.get('unhealthy_count', 0)}
Primary suspect  : {primary_instance_id}
Scenario         : {scenario} — {scenario_desc}

{alb_text}

═══ INSTANCE COMPARISON MATRIX ═══
(All instances behind the ALB — sorted by failure severity)

{matrix_text}

Cross-instance observations:
  Errors shared by ALL instances (shared dependency signal):
{common_errors if common_errors else "  (none — errors are isolated)"}

  Errors isolated to specific instances:
{isolated_errors_text}

═══ PRIMARY SUSPECT — DEEP ANALYSIS ({primary_instance_id}) ═══

EC2 Snapshot:
{primary_ec2_text}

CloudWatch Metrics (last 15 min):
{primary_metrics_text}

Metrics interpretation guide:
  • Low CPU + no disk pressure + connection timeouts → dependency saturation or connection pool exhaustion, NOT host failure
  • High CPU + disk pressure → resource exhaustion on EC2 itself
  • All metrics clean → failure is external (dependency, network policy, auth)
  • StatusCheckFailed=1 → underlying host issue regardless of app logs

Top Error Signals (global, across all log groups):
{top_errors_text if top_errors_text else "  (none identified)"}

Detailed Log Analysis (per group, per stage, deduplicated):
{log_summary_text}

═══ DEPENDENCY CONTEXT ═══
{dep_text}

═══ CAUSAL CHAIN REASONING FRAMEWORK ═══

IMPORTANT — Use the scenario classification above to guide your reasoning:

Scenario A (single instance failing):
  → Focus on: host-level failure, application bug, OOM, disk full, stuck process
  → Other instances being healthy is key evidence AGAINST shared dependency outage

Scenario B (all instances failing):
  → Focus on: shared dependency (DB, Redis, external API, VPC/security group, DNS)
  → Host-level explanations are RULED OUT when all instances fail identically

Scenario C (ALB-level issue):
  → Focus on: health check misconfiguration, port mismatch, security group blocking health check path
  → Instance-level explanations are LESS likely when instances themselves are healthy

Scenario D (partial failure):
  → Consider: rolling deployment, AZ-specific issue, canary regression, load imbalance

You must reason through these layers IN ORDER before writing your conclusion:

LAYER 1 — SYMPTOM (what the logs report)
LAYER 2 — MECHANISM (what failure mode produced those symptoms)
LAYER 3 — TRIGGER (what caused the mechanism)
LAYER 4 — ROOT CAUSE (single underlying operational failure — most specific actionable statement)
LAYER 5 — CASCADE PATH (how root cause propagated)

═══ CRITICAL REASONING RULES ═══

1. Use the comparison matrix. If only one instance is failing, do NOT conclude shared dependency.
2. If all instances share the same error, shared dependency is the primary hypothesis.
3. EC2 metrics are your control group — healthy metrics = EC2 host is NOT the problem.
4. Duration clustering (e.g. all timeouts at exactly 9000ms) = saturation, not outage.
5. Do NOT attribute failures to cloud provider infrastructure unless you have explicit evidence.
6. Differentiate: root_cause vs trigger vs cascade. Never list cascades as root causes.
7. Every remediation step must answer: "Why does THIS step fix THIS root cause?"

═══ OUTPUT INSTRUCTIONS ═══

You MUST return ONLY a valid JSON object. No markdown, no explanations, no ```json fences.
Your ENTIRE response must start with {{ and end with }}.

Schema:
{{
  "root_cause": "Single precise technical statement. Include: what failed, why, evidence. 2-3 sentences.",

  "confidence_score": 0.0-1.0,

  "actual_incident_start": "ISO timestamp of when problem actually started (Stage 2 onset)",

  "impacted_services": ["directly affected services — not cascades"],

  "severity_assessment": "Blast radius: what was broken, what was NOT broken, scope of user impact",

  "infrastructure_scenario": "{scenario} — {scenario_desc}",

  "rca_report": {{
    "summary": "2-3 sentence executive summary: what broke, why, and impact",

    "timeline": {{
      "buildup": "Stage 1 findings. Healthy or early signals? Timestamps.",
      "failure": "Stage 2 trigger. Precise moment and mechanism of failure onset.",
      "impact":  "How Stage 2 cascaded into Stage 3."
    }},

    "instance_analysis": "Summary of which instances failed and which were healthy. Key differences between instances.",

    "metrics_analysis": "Explicit interpretation of each metric for the primary suspect. What each metric rules IN or OUT.",

    "infra_change_analysis": "Evidence of config/deployment/infrastructure changes before incident. If none: state explicitly.",

    "log_analysis": {{
      "application": "Application log findings — error counts, timing patterns, failure type.",
      "nginx": "Nginx log findings, or 'not available'",
      "system": "System-level log findings, or 'not available'",
      "database": "Database-side findings. If not directly available, infer from app-side DB errors."
    }},

    "root_cause_analysis": "Full causal chain: Symptom → Mechanism → Trigger → Root Cause. Postmortem-quality prose.",

    "contributing_factors": ["Factors that worsened the incident but are not root cause"],

    "blast_radius": "What was unavailable, for how long, what was unaffected"
  }},

  "remediation_steps": {{
    "immediate_actions": [
      "Specific and directly addresses root cause.",
      "Include exact command/config change/operation.",
      "State WHY each action works against the identified root cause."
    ],

    "verification_steps": [
      "Specific checks to confirm recovery. Exact log patterns or metrics to look for."
    ],

    "rollback_steps": [
      "If a recent change is implicated. Otherwise: 'No rollback applicable — failure was operational, not change-induced.'"
    ],

    "communication_template": "Plain-language status update for stakeholders."
  }}
}}
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — Bedrock Invocation
# ═══════════════════════════════════════════════════════════════════════════════

def _invoke_bedrock(prompt: str, aws_factory: AWSClientFactory) -> dict:
    logger.info(f"Invoking Bedrock: {BEDROCK_MODEL}")

    config = Config(read_timeout=300, retries={"max_attempts": 3})
    bedrock = aws_factory.get_client("bedrock-runtime", region_name=REGION, config=config)

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 8192,
        "temperature": 0.1,
        "top_p": 0.9,
        "messages": [{"role": "user", "content": prompt}],
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
    logger.info(f"[Bedrock Raw Response]\n{text[:8000]}")

    cleaned = re.sub(r"```json|```", "", text).strip()
    match   = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        logger.warning("No JSON object in Bedrock response")
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
        "root_cause":            "AI response parsing failed — manual review required",
        "confidence_score":      0.3,
        "actual_incident_start": "unknown",
        "impacted_services":     [],
        "severity_assessment":   "Unknown",
        "rca_report":            raw_text[:3000],
        "remediation_steps": (
            "1. Check EC2 instance health in AWS console\n"
            "2. Review all CloudWatch log groups manually\n"
            "3. Verify application process is running\n"
            "4. Check disk, memory, and CPU utilisation\n"
            "5. Inspect security group and network ACL rules"
        ),
        "prevention_recommendations": {
            "monitoring": [], "security": [], "infrastructure": [],
            "application": [], "operational": []
        }
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — DB Helpers
# ═══════════════════════════════════════════════════════════════════════════════

STATUS_PROGRESS = {
    "queued":           5,
    "resolving_deps":   10,
    "fetching_ec2":     15,
    "fetching_metrics": 25,
    "fetching_logs":    40,
    "compressing_logs": 55,
    "correlating":      65,
    "building_prompt":  70,
    "finding_rca":      80,
    "storing_results":  95,
    "completed":        100,
    "failed":           0,
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
# SECTION 7 — Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def process_incident(payload: dict) -> None:
    """
    Process a single incident. Called by the worker thread pool.

    payload requires only {"incident_id": str}.
    All other data is read from meyiconnect.insight_incidents.

    DB `dependencies` JSONB supports both legacy (instance_id) and new
    (type + resource_id) schemas — both are handled transparently.
    """
    logger.info("========== INCIDENT PROCESSOR STARTED ==========")
    incident_id = payload.get("incident_id", "unknown")

    try:
        # ── Load incident ──────────────────────────────────────────────────
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

        if not incident.get("incident_down_time"):
            logger.error(f"Missing incident_down_time for incident {incident_id}")
            _update_status(incident_id, "failed")
            return

        issue    = incident.get("issue")    or ""
        severity = incident.get("severity") or "medium"

        # ── Parse dependencies ─────────────────────────────────────────────
        raw_deps = incident.get("dependencies") or []
        if isinstance(raw_deps, str):
            try:
                raw_deps = json.loads(raw_deps)
            except Exception:
                raw_deps = []

        # ── Backwards-compat: legacy {instance_id, region, log_group_name} ──
        # Rewrite to new schema so resolver handles it uniformly
        normalised_raw = []
        for d in raw_deps:
            if "type" not in d:
                # Legacy EC2 dep
                d = {
                    "type":           "ec2",
                    "resource_id":    d.get("instance_id", ""),
                    "region":         d.get("region", REGION),
                    "log_group_name": d.get("log_group_name") or d.get("log_group_names") or [],
                }
            normalised_raw.append(d)

        if not normalised_raw:
            logger.error(f"No dependencies for incident {incident_id}")
            _update_status(incident_id, "failed")
            return

        # ── Fetch AWS factory ─────────────────────────────────────────────
        connector_id = incident.get("connector_id")
        try:
            aws_factory = AWSClientFactory(connector_id)
        except ValueError as e:
            logger.error(f"AWS Connector initialization failed: {e}")
            _update_status(incident_id, "failed")
            return

        # ── Resolve dependencies → normalized EC2 targets ──────────────────
        _update_status(incident_id, "resolving_deps")
        targets, alb_meta = resolve_dependencies(normalised_raw, aws_factory)

        if not targets:
            logger.error(f"Dependency resolution produced no targets for {incident_id}")
            _update_status(incident_id, "failed")
            return

        logger.info(
            f"Resolved {len(targets)} target(s): "
            f"{[t['instance_id'] for t in targets]}"
        )

        # dependency_ctx for cascade attribution
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

        # ── Parallel data collection for all instances ─────────────────────
        _update_status(incident_id, "fetching_ec2")

        instance_analyses = collect_all_instances(
            targets,
            incident_down_time,
            severity,
            issue,
            dependency_ctx,
            status_callback=lambda st: _update_status(incident_id, st),
            aws_factory=aws_factory,
        )

        if not instance_analyses:
            logger.error(f"No instance data collected for {incident_id}")
            _update_status(incident_id, "failed")
            return

        # ── Cross-instance correlation ─────────────────────────────────────
        _update_status(incident_id, "correlating")
        correlation = correlate_instances(instance_analyses, alb_meta)

        # ── Primary suspect for deep log details ───────────────────────────
        primary_id = (
            correlation.get("primary_suspect")
            or next(iter(instance_analyses))
        )

        logger.info(
            f"Correlation complete | scenario={correlation['scenario']} | "
            f"primary={primary_id} | "
            f"unhealthy={correlation['unhealthy_count']}/{correlation['total_count']}"
        )

        # ── Store raw collected data ────────────────────────────────────────
        with get_db() as conn:
            with conn.cursor() as cur:
                primary_analysis = instance_analyses[primary_id]
                primary_log      = primary_analysis.get("log_summary", {})

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
                        json.dumps(primary_analysis["ec2"]["details"]),
                        json.dumps(primary_analysis["ec2"]["status_checks"]),
                        json.dumps(primary_analysis["metrics"]),
                        json.dumps({
                            "primary_instance": primary_id,
                            "instances": {
                                iid: {
                                    "anchor":    a["log_summary"].get("anchor"),
                                    "stages":    a["log_summary"].get("stages"),
                                    "per_group": a["log_summary"].get("per_group"),
                                }
                                for iid, a in instance_analyses.items()
                            },
                            "correlation": correlation,
                            "alb_meta":    alb_meta,
                        }),
                        primary_log.get("total_raw_lines", 0),
                    ),
                )
                log_id = cur.fetchone()["id"]

        logger.info(f"Data stored | log_id: {log_id}")

        # ── Build Bedrock prompt ───────────────────────────────────────────
        _update_status(incident_id, "building_prompt")

        prompt = _build_prompt_multi(
            incident_id          = incident_id,
            issue                = issue,
            severity             = severity,
            down_time_iso        = incident_down_time.isoformat(),
            instance_analyses    = instance_analyses,
            correlation          = correlation,
            alb_meta             = alb_meta,
            dependency_ctx       = dependency_ctx,
            primary_instance_id  = primary_id,
        )

        # ── Invoke Bedrock ─────────────────────────────────────────────────
        _update_status(incident_id, "finding_rca")
        estimated_tokens = len(prompt) // 4

        if estimated_tokens > 25000:
            logger.warning(f"[Prompt Size Warning] ~{estimated_tokens} tokens")

        logger.info(
            f"[Bedrock Prompt] chars={len(prompt)} | "
            f"estimated_tokens={estimated_tokens} | "
            f"instances={len(instance_analyses)}"
        )
        logger.info(f"[Bedrock Prompt Preview]\n{prompt[:8000]}")

        rca = _invoke_bedrock(prompt, aws_factory)

        logger.info(
            f"[RCA Summary] confidence={rca.get('confidence_score')} | "
            f"root_cause={rca.get('root_cause', '')[:300]}"
        )

        # ── Store RCA results ──────────────────────────────────────────────
        with get_db() as conn:
            with conn.cursor() as cur:
                confidence_percentage = round(
                    float(rca.get("confidence_score", 0.5)) * 100, 2
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