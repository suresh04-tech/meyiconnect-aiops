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
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")

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
    lines     = []
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
 
 
def _fmt(v) -> str:
    return f"{v:.1f}" if v is not None else "n/a"
 
 
def _build_matrix_text(correlation: dict) -> str:
    """
    Tight per-instance table — unhealthy instances first.
    Each row: ID | health | CPU | ALB-target | errors | top error snippet
    """
    rows  = correlation.get("comparison_matrix", [])
    lines = []
    for r in rows:
        icon  = "✗" if r["health"] == "unhealthy" else "✓"
        lines.append(
            f"  {icon} {r['instance_id']}"
            f"  cpu={r['cpu']}%"
            f"  ec2={r['status_check']}"
            f"  alb={r['target_health']}"
            f"  errors={r['error_count']}"
        )
        if r.get("target_reason"):
            lines.append(f"    └ ALB reason : {r['target_reason']}")
        for e in r.get("top_errors", [])[:2]:
            lines.append(f"    └ {e[:160]}")
    return "\n".join(lines) if lines else "  (no instances)"
 
 
def _unhealthy_instance_list(correlation: dict) -> str:
    rows = [r for r in correlation.get("comparison_matrix", [])
            if r["health"] == "unhealthy"]
    if not rows:
        return "none"
    return ", ".join(r["instance_id"] for r in rows)

def _build_prompt_multi(
    incident_id:         str,
    issue:               str,
    severity:            str,
    down_time_iso:       str,
    instance_analyses:   dict,   # {iid: analysis_dict}
    correlation:         dict,
    alb_meta:            dict,
    dependency_ctx:      dict,
    primary_instance_id: str,
) -> str:
    """
    Build Bedrock prompt for multi-instance (ALB-aware) RCA.
 
    Design goals
    ────────────
    1. Instance-specific — failing instance ID is called out explicitly in
       every section so the AI can name it in root_cause and remediation.
    2. Scenario-guided reasoning — scenario A/B/C/D constrains hypothesis space
       before the AI writes a single word of analysis.
    3. Remediation quality — 3-point structure: immediate fix, verification,
       prevention. Each point names the specific instance/command/metric.
    4. Token-efficient — unhealthy instances get full detail; healthy instances
       appear only in the compact matrix (no log dump).
    """
 
    # ── Primary instance data ────────────────────────────────────────────────
    primary      = instance_analyses.get(primary_instance_id, {})
    primary_log  = primary.get("log_summary", {})
    primary_ec2  = primary.get("ec2", {})
    primary_m    = primary.get("metrics", {})
 
    log_summary_text = _format_log_summary_for_prompt(primary_log)
    top_errors_text  = "\n".join(
        f"  • {e}" for e in primary_log.get("top_errors", [])
    ) or "  (none)"
 
    anchor      = primary_log.get("anchor", {})
    ec2_d       = primary_ec2.get("details", {})
    ec2_sc      = primary_ec2.get("status_checks", {})
    tgt_health  = primary.get("target_health", "unknown")
    tgt_reason  = primary.get("target_reason", "") or "—"
 
    # ── Scenario metadata ────────────────────────────────────────────────────
    scenario      = correlation.get("scenario", "?")
    scenario_desc = correlation.get("scenario_description", "")
    unhealthy_ids = _unhealthy_instance_list(correlation)
    matrix_text   = _build_matrix_text(correlation)
 
    common_errors = "\n".join(
        f"  • {e}" for e in correlation.get("common_errors", [])
    ) or "  (none — errors are isolated to specific instance(s))"
 
    isolated_errors_text = json.dumps(
        correlation.get("isolated_errors", {}), indent=2
    )
 
    # ── ALB block ────────────────────────────────────────────────────────────
    alb_block = ""
    if alb_meta:
        alb_block = (
            f"ALB DNS      : {alb_meta.get('alb_dns', 'n/a')}\n"
            f"Targets      : {alb_meta.get('total', '?')} total  "
            f"| {alb_meta.get('healthy', '?')} healthy  "
            f"| {alb_meta.get('unhealthy', '?')} unhealthy\n"
        )
 
    dep_text = (
        json.dumps(dependency_ctx, indent=2, default=str)
        if dependency_ctx else "none"
    )
 
    # ── Metrics block (primary instance only) ────────────────────────────────
    metrics_text = (
        f"CPU            : {_fmt(primary_m.get('cpu_percent'))}%\n"
        f"NetworkIn      : {_fmt(primary_m.get('network_in_bytes'))} B\n"
        f"NetworkOut     : {_fmt(primary_m.get('network_out_bytes'))} B\n"
        f"DiskReadOps    : {_fmt(primary_m.get('disk_read_ops'))}\n"
        f"DiskWriteOps   : {_fmt(primary_m.get('disk_write_ops'))}\n"
        f"StatusCheckFailed: {_fmt(primary_m.get('status_check_failed'))}"
    )
 
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    return f"""You are a Principal AWS SRE conducting a live postmortem.
Do NOT summarize — reason causally and be specific to the failing instance(s).
 
━━━ INCIDENT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ID       : {incident_id}
Severity : {severity.upper()}
Issue    : {issue}
Detected : {down_time_iso}
First error in logs : {anchor.get('first_error_ts') or 'not found'}
First error message : {anchor.get('first_error_msg') or 'n/a'}
Adaptive lookback   : {primary_log.get('adaptive_window', {}).get('before_minutes')} min
 
━━━ INFRASTRUCTURE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{alb_block}Failing instance(s): {unhealthy_ids}
Primary suspect     : {primary_instance_id}
Scenario            : {scenario} — {scenario_desc}
 
Instance comparison (✗ = unhealthy, ✓ = healthy):
{matrix_text}
 
Errors common to ALL instances (→ shared dependency):
{common_errors}
 
Errors isolated to specific instance(s) (→ host/app-level):
{isolated_errors_text}
 
━━━ PRIMARY SUSPECT: {primary_instance_id} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EC2 state     : {ec2_d.get('state')}  ({ec2_d.get('instance_type')})  AZ: {ec2_d.get('availability_zone')}
Status checks : instance={ec2_sc.get('instance_status')}  system={ec2_sc.get('system_status')}
ALB target    : {tgt_health}  reason={tgt_reason}
Tags          : {json.dumps(ec2_d.get('tags', {}))}
 
CloudWatch metrics (last 15 min):
{metrics_text}
 
Metric rules:
  • CPU low + no disk pressure + timeouts  → dependency issue, NOT host failure
  • CPU high + disk pressure               → resource exhaustion on this EC2
  • All metrics clean                      → external dependency / network / auth
  • StatusCheckFailed=1                    → host-level failure, check EC2 console
 
Top error signals ({primary_instance_id}):
{top_errors_text}
 
Log detail — 3 stages (buildup → failure → impact):
  Stage 1 = pre-failure state  |  Stage 2 = ROOT CAUSE WINDOW  |  Stage 3 = cascades (not causes)
{log_summary_text}
 
━━━ DEPENDENCY CONTEXT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{dep_text}
 
━━━ REASONING FRAMEWORK ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Work through these IN ORDER. Reference {primary_instance_id} by name throughout.
 
Scenario guidance:
  A (single instance failing) → host bug / OOM / disk / stuck process on {primary_instance_id}.
    Other instances healthy = EVIDENCE AGAINST shared dependency. Do not conclude shared dep.
  B (all instances failing)   → shared dependency (DB/Redis/DNS/VPC). Rule out host causes.
  C (ALB issue only)          → health-check misconfiguration / port mismatch / SG rule.
  D (partial failure)         → rolling deploy / AZ issue / canary regression.
 
LAYER 1 — SYMPTOM      What error messages? HTTP codes? Timeout values?
LAYER 2 — MECHANISM    Why did those errors occur on {primary_instance_id} specifically?
LAYER 3 — TRIGGER      What changed or threshold was crossed just before Stage 2?
LAYER 4 — ROOT CAUSE   Single most specific actionable statement.
                        BAD : "database was unavailable"
                        GOOD: "psycopg2 pool on {primary_instance_id} exhausted because all N
                               connections blocked on 9 s connect_timeout to saturated Postgres,
                               cascading HTTP 500s to ALB"
LAYER 5 — CASCADE      How did root cause propagate into Stage 3?
 
Hard rules:
  • Name {primary_instance_id} explicitly in root_cause, not just "the instance".
  • Duration clustering (e.g. all timeouts at ~9 s) = saturation, not outage.
  • Do NOT attribute to AWS provider failure unless provider event is in the logs.
  • Cascades (Stage 3) are NEVER root causes.
 
━━━ REMEDIATION RULES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
immediate_actions   : EXACTLY 3 steps. Each must name {primary_instance_id} or the specific
                      resource to fix. Format: "<action> on <target> — <why this fixes root cause>"
                      No generic advice ("check logs", "restart app") unless restart IS the fix
                      and you explain why it clears the specific failure mode.
verification_steps  : EXACTLY 3 checks. Each must name a specific metric, log pattern, or
                      HTTP status code to confirm recovery. Example format:
                      "Confirm ALB UnHealthyHostCount for {primary_instance_id} drops to 0
                       in CloudWatch within 60 s of fix"
prevention          : EXACTLY 2 steps. Long-term fixes to prevent recurrence.
 
━━━ OUTPUT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Return ONLY valid JSON. No markdown, no fences, no text outside the object.
Start with {{ end with }}.
 
{{
  "root_cause": "Precise 2-sentence statement naming {primary_instance_id} explicitly.
                 What failed, why, what evidence confirms it.",
 
  "confidence_score": 0.0-1.0,
 
  "failing_instances": ["{primary_instance_id}"],
 
  "actual_incident_start": "ISO timestamp — Stage 2 onset, not detection time",
 
  "impacted_services": ["directly affected services only — no cascades"],
 
  "severity_assessment": "What broke, what did NOT break, estimated user impact",
 
  "infrastructure_scenario": "Scenario letter + one-line description",
 
  "rca_report": {{
 
    "summary": "2-3 sentences: what broke on which instance, why, user impact",
 
    "timeline": {{
      "buildup": "Stage 1 — was {primary_instance_id} healthy? Early signals? Timestamps.",
      "failure": "Stage 2 — exact onset moment and mechanism on {primary_instance_id}.",
      "impact":  "Stage 3 — how failure on {primary_instance_id} cascaded downstream."
    }},
 
    "instance_analysis": "Which instances failed vs healthy. Key metric/log differences that
                          confirm the failure was isolated to {primary_instance_id} (or shared).",
 
    "metrics_analysis": "Interpret each metric for {primary_instance_id}. State explicitly
                         what each metric rules IN or OUT as a cause.",
 
    "root_cause_analysis": "Postmortem-quality causal chain for {primary_instance_id}:
                            Symptom → Mechanism → Trigger → Root Cause. Cite Stage 2 evidence."
  }},
 
  "remediation_steps": {{
 
    "immediate_actions": [
      "1. <specific action> on {primary_instance_id} — <why this clears the root cause>",
      "2. <specific action> on <exact resource> — <why>",
      "3. <specific action> — <why>"
    ],
 
    "verification_steps": [
      "1. <metric or log pattern to check> — expected value after fix",
      "2. <HTTP/ALB health check result to verify> — expected outcome",
      "3. <CloudWatch alarm or log absence to confirm> — expected state"
    ],
 
    "prevention": [
      "1. <long-term architectural or config change> — prevents recurrence because <reason>",
      "2. <monitoring or alerting improvement> — detects this failure class earlier because <reason>"
    ],
 
    "communication_template": "One paragraph. Plain language. State: what is broken, which
                               instance is affected, what is being done, next update ETA."
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