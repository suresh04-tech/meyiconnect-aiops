"""
processor/process_incident.py
─────────────────────────────
Core RCA processing logic — called by the worker thread pool.

What's changed from previous version
──────────────────────────────────────
• CloudTrail infra context is now fetched as a first-class data source alongside
  CloudWatch logs.  This gives the AI both sides: infra changes AND app errors.

• fetch_infra_context() runs in parallel with EC2 details + metrics so it adds
  almost zero latency to the pipeline.

• _build_prompt() now receives infra_ctx and surfaces:
    – High-risk infra events ranked by proximity to the first error
    – Infra-side root cause hypotheses ("DeregisterTargets 3m before first error")
    – Failed API calls that may have broken something silently
    – "Who did what" change attribution

• The Bedrock prompt instructions are rewritten to explicitly cross-reference
  the infra timeline against the log stage breakdown, so the model answers:
    1. Root cause (infra change vs app bug vs resource exhaustion)
    2. Why it happened (what change / condition triggered it)
    3. Who triggered it (CloudTrail actor)
    4. How to fix it (immediate + long-term)
    5. How to prevent it (alarms, guards, review process)

Pipeline status steps (visible in UI):
  queued → fetching_ec2 → fetching_metrics → fetching_logs →
  fetching_infra → compressing_logs → building_prompt →
  finding_rca → storing_results → completed
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
from app.processor.cloudtrail_processor import (
    fetch_infra_context,
    format_infra_context_for_prompt,
)

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
    """
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
                    # Surface cascade and rarity flags
                    flags  = []
                    if c.get("is_rare"):
                        flags.append("[RARE-CRITICAL]")
                    if c.get("cascade_suspect"):
                        ups = ",".join(c.get("upstream_services", []))
                        flags.append(f"[CASCADE↑{ups}]")
                    flag_str = " ".join(flags) + " " if flags else ""
                    sample   = (c["samples"][0] if c["samples"] else c["fingerprint"])[:250]
                    lines.append(f"║   {tag} [{level}] {flag_str}{sample}")
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
    incident_id:    str,
    issue:          str,
    severity:       str,
    down_time_iso:  str,
    ec2:            dict,
    metrics:        dict,
    log_data:       dict,
    dependency_ctx: dict,
    infra_ctx:      dict,  
) -> str:

    log_summary_text  = _format_log_summary_for_prompt(log_data)
    top_errors_text   = "\n".join(f"  • {e}" for e in log_data.get("top_errors", []))
    infra_section     = format_infra_context_for_prompt(infra_ctx)

    anchor = log_data.get("anchor", {})
    anchor_text = (
        f"Pulse detected outage at  : {down_time_iso}\n"
        f"First error in logs       : {anchor.get('first_error_ts') or 'not found'}\n"
        f"First error log group     : {anchor.get('first_error_group') or 'n/a'}\n"
        f"First error message       : {anchor.get('first_error_msg') or 'n/a'}\n"
        f"Investigation anchored to : {anchor.get('true_start')}\n"
        f"Adaptive lookback used    : {log_data.get('adaptive_window', {}).get('before_minutes')} min"
    )

    # Infra hypothesis summary (top 3 for the anchor section)
    infra_hypotheses = infra_ctx.get("hypotheses", [])
    if infra_hypotheses:
        hyp_lines = [
            f"  [{h['confidence'].upper()}] {h['hypothesis']}"
            for h in infra_hypotheses[:3]
        ]
        infra_hyp_text = "\n".join(hyp_lines)
    else:
        infra_hyp_text = "  No high-confidence infra hypothesis — lean on log analysis."

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

    return f"""You are a Principal AWS Site Reliability Engineer and forensic incident investigator.
You have been given BOTH infrastructure change evidence (CloudTrail) AND application log evidence
(CloudWatch Logs) for an EC2 production incident. Your job is to cross-reference both data sources
to determine the definitive root cause, who triggered it, why it happened, and how to fix it.

═══ INCIDENT ═══
Event ID  : {incident_id}
Severity  : {severity.upper()}
Issue     : {issue}

═══ TIME ANCHOR ═══
{anchor_text}

Note on stages:
  Stage 1 (buildup)  = what was happening BEFORE the first error — degradation signals.
  Stage 2 (failure)  = active failure window — most likely contains root cause.
  Stage 3 (impact)   = cascading errors and recovery signals AFTER health check failed.

═══ INFRA-SIDE HYPOTHESES (CloudTrail — ranked by proximity to first error) ═══
{infra_hyp_text}

Use these as starting hypotheses.  CONFIRM or REJECT each using the log evidence below.

═══ EC2 SNAPSHOT ═══
{ec2_text}

═══ CLOUDWATCH METRICS (last 15 min before analysis) ═══
{metrics_text}

═══ TOP ERROR SIGNALS (global, across all log groups, weighted) ═══
{top_errors_text if top_errors_text else "  (none identified)"}

Flags:
  [RARE-CRITICAL]    = appeared once but high-severity (OOM, corruption, deadlock)
  [CASCADE↑service]  = likely a downstream symptom of upstream service failure
  [x N]              = appeared N times in this stage

═══ DETAILED LOG ANALYSIS (per group, per stage, deduplicated) ═══
{log_summary_text}

═══ INFRASTRUCTURE CHANGE EVENTS (CloudTrail) ═══
{infra_section}

═══ DEPENDENCY CONTEXT ═══
{dep_text}

━━━ CROSS-REFERENCE INSTRUCTIONS ━━━

You have four data sources: CloudTrail events, CloudWatch log stages, EC2 metrics,
and service dependency context.  Use ALL of them together.

STEP 1 — DETERMINE TRUE ROOT CAUSE

Infrastructure events are correlation signals, NOT proof of causation.

You MUST verify infra hypotheses using application logs, metrics,
and affected subsystem evidence.

DO NOT conclude infra_triggered unless ALL are true:
1. The infra event directly affects the failing subsystem
   (DB, network, IAM, EC2, load balancer, storage, etc.)
2. The first application/log errors explicitly support the infra hypothesis
3. No stronger application-level root cause exists

Examples:
- Security group ingress/egress revoke + DB timeout
  → infra_triggered

- RDS reboot/failover + connection refused
  → infra_triggered

- ECS deployment + startup failures
  → infra_triggered

- IAM AccessDenied exceptions in logs
  → infra_triggered

But:
- Generic application exceptions WITHOUT matching infra evidence
  → app_triggered

- Application stack traces BEFORE downstream failures
  → app_triggered

- PostgreSQL timeout after SG/network change
  → dependency_failure or infra_triggered(network)

If evidence is weak or ambiguous:
- prefer "dependency_failure" or "unknown"
- NEVER invent services not present in logs/evidence
- NEVER assume ECS/Lambda/CodePipeline unless explicitly seen in evidence

STEP 2 — WHY DID IT HAPPEN
  • For infra-triggered: Was it intentional (deployment) or accidental (wrong resource)?
    Was it a failed API call (check "Failed API calls" section) or a successful but wrong change?
  • For app-triggered: Was it gradual (memory/disk fill) or sudden (crash/OOM)?
    Which metric correlates: CPU spike, disk ops, network drop?

STEP 3 — BLAST RADIUS
  • Which services show cascade symptoms ([CASCADE↑x] flags)?
  • Which log groups have the most Stage 3 errors (post-detection impact)?
  • Did the incident spread to downstream consumers?

STEP 4 — ROOT CAUSE CHAIN
  Write the event chain in causal order:
  [infra change / resource exhaustion / code path] → [first error in logs] →
  [cascade to Stage 2 errors] → [health check failure / detection] →
  [Stage 3 impact on downstream]

STEP 5 — WHO, WHAT, WHEN
  • WHO: CloudTrail actor (user/role) if infra-triggered; application team if app-triggered.
  • WHAT: The specific change or condition (API call name, resource, config value).
  • WHEN: Exact timestamp of the triggering event vs first log error vs detection.

IMPORTANT:
You MUST return ONLY a valid JSON object.

Do NOT:
- add markdown
- add explanations
- add comments
- add ```json fences
- add text before or after JSON

Your ENTIRE response must:
- start with {{
- end with }}

If information is missing, use "unknown".
The response MUST be parseable by Python json.loads().



Schema:
{{
  "root_cause_type": "infra_triggered | app_triggered | resource_exhaustion | dependency_failure | unknown",
  "root_cause": "concise 1-2 sentence technical root cause",
  "confidence_score": 0.0-1.0,

  "who": "user/role/team who triggered or is responsible (from CloudTrail or app team if no infra change)",
  "what": "specific change or condition: API call + resource name, or error pattern + service",
  "when": "timestamp of the triggering event (CloudTrail event or first log error, whichever came first)",

  "actual_incident_start": "best estimate of when problem really started, not detection time",
  "impacted_services": ["list of services/components confirmed affected"],

  "causal_chain": "ordered event chain: trigger → first error → cascade → detection → impact",
  "infra_hypothesis_verdict": "CONFIRMED: <which hypothesis> | REJECTED: <reason> | NOT APPLICABLE: no infra changes",

  "severity_assessment": "brief blast-radius: which systems, how many users, estimated duration",

   "rca_report": {
        "summary": "",
        "timeline": {
        "buildup": "",
        "failure": "",
        "impact": ""
        },
        "metrics_analysis": "",
        "infra_change_analysis": "",
        "log_analysis": {
        "application": "",
        "nginx": "",
        "system": "",
        "database": ""
        },
        "root_cause_analysis": "",
        "contributing_factors": [],
        "blast_radius": ""
    },

  "remediation_steps": {
    "immediate_actions": [],
    "verification_steps": [],
    "rollback_steps": [],
    "communication_template": ""
   },

  "prevention_recommendations": "LONG-TERM: specific CloudWatch alarms to add | IAM/change-control guardrails | architectural changes | monitoring gaps to close"
}}
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Bedrock Invocation
# ═══════════════════════════════════════════════════════════════════════════════

def _invoke_bedrock(prompt: str) -> dict:
    logger.info(f"Invoking Bedrock: {BEDROCK_MODEL}")
    bedrock = boto3.client("bedrock-runtime", region_name=REGION)

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "temperature": 0.2,
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
    logger.info(f"[Bedrock Raw Response]\n{text[:8000]}")

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
        "root_cause_type":            "unknown",
        "root_cause":                 "AI response parsing failed — manual review required",
        "confidence_score":           0.3,
        "who":                        "unknown",
        "what":                       "unknown",
        "when":                       "unknown",
        "actual_incident_start":      "unknown",
        "impacted_services":          [],
        "causal_chain":               "unknown",
        "infra_hypothesis_verdict":   "unknown",
        "severity_assessment":        "Unknown",
        "rca_report":                 raw_text[:3000],
        "remediation_steps": (
            "1. Check EC2 instance health in AWS console\n"
            "2. Review all CloudWatch log groups manually\n"
            "3. Check CloudTrail for recent infra changes\n"
            "4. Verify application process is running (systemctl / docker ps)\n"
            "5. Check disk, memory, and CPU utilisation\n"
            "6. Inspect security group and network ACL rules"
        ),
        "prevention_recommendations": "Set up CloudWatch alarms for key metrics.",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — DB Helpers
# ═══════════════════════════════════════════════════════════════════════════════

STATUS_PROGRESS = {
    "queued":           5,
    "fetching_ec2":     12,
    "fetching_metrics": 20,
    "fetching_logs":    32,
    "fetching_infra":   48,    # ← NEW
    "compressing_logs": 58,
    "building_prompt":  68,
    "finding_rca":      82,
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
# SECTION 6 — Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def process_incident(payload: dict) -> None:
    """
    Process a single incident.  Called by the worker thread pool.

    payload requires only {"incident_id": str}.
    All other data is read from meyiconnect.insight_incidents.

    Schema uses a `dependencies` JSONB array:
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

        issue    = incident.get("issue")    or ""
        severity = incident.get("severity") or "medium"

        # ── Parse dependencies ──────────────────────────────────────────────
        raw_deps = incident.get("dependencies") or []
        if isinstance(raw_deps, str):
            try:
                raw_deps = json.loads(raw_deps)
            except Exception:
                raw_deps = []

        if not raw_deps:
            logger.error(f"No dependencies defined for incident {incident_id}")
            _update_status(incident_id, "failed")
            return

        dep         = raw_deps[0]
        instance_id = dep.get("instance_id", "")
        region      = dep.get("region") or "ap-south-1"

        # Collect log groups from ALL dependencies
        log_groups: list[str] = []
        for d in raw_deps:
            raw_lg = d.get("log_group_name") or d.get("log_group_names") or []
            if isinstance(raw_lg, str):
                raw_lg = [g.strip() for g in raw_lg.split(",") if g.strip()]
            log_groups.extend([g for g in raw_lg if g])

        if not log_groups:
            logger.warning(f"No log groups for incident {incident_id}")

        dependency_ctx = incident.get("dependency_context") or {}
        if isinstance(dependency_ctx, str):
            try:
                dependency_ctx = json.loads(dependency_ctx)
            except Exception:
                dependency_ctx = {}

        incident_down_time = _parse_time(incident.get("incident_down_time"))
        if not incident_down_time:
            logger.warning("incident_down_time missing — falling back to now-30min")
            incident_down_time = datetime.now(timezone.utc) - timedelta(minutes=30)

        logger.info(
            f"Event: {incident_id} | instance: {instance_id} | region: {region} | "
            f"severity: {severity} | down_time: {incident_down_time.isoformat()} | "
            f"log_groups: {log_groups}"
        )

        # ── AWS clients ──────────────────────────────────────────────────────
        boto_config = Config(max_pool_connections=50)
        ec2_client  = boto3.client("ec2",        region_name=region)
        cw_client   = boto3.client("cloudwatch", region_name=region)
        logs_client = boto3.client("logs",       region_name=region, config=boto_config)

        # ── Fetch EC2 details and metrics in parallel ────────────────────────
        _update_status(incident_id, "fetching_ec2")
        ec2 = get_ec2_details(ec2_client, instance_id)

        _update_status(incident_id, "fetching_metrics")
        metrics = get_all_metrics(cw_client, instance_id)

        # ── Fetch logs ────────────────────────────────────────────────────────
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
            logger.warning("[RCA Warning] No CloudWatch logs retrieved for investigation window")

        logger.info(
            f"Logs fetched | "
            f"adaptive_window={log_data['adaptive_window']} | "
            f"anchor={log_data['anchor']} | "
            f"stages={[s['name'] for s in log_data['stages']]} | "
            f"error_events={len(log_data['error_events'])} | "
            f"total_raw={log_data['total_raw_lines']}"
        )

        # ── Fetch CloudTrail infra context ────────────────────────────────────
        # Runs AFTER log fetch so we can pass the log anchor (first_error_ts)
        # to the correlation engine.
        _update_status(incident_id, "fetching_infra")
        try:
            infra_ctx = fetch_infra_context(
                region      = region,
                instance_id = instance_id,
                down_time   = incident_down_time,
                anchor      = log_data["anchor"],
                severity    = severity,
                issue       = issue,
            )
            logger.info(
                f"Infra context fetched | "
                f"total_events={infra_ctx.get('total_events', 0)} | "
                f"high_risk={len(infra_ctx.get('high_risk_events', []))} | "
                f"hypotheses={len(infra_ctx.get('hypotheses', []))}"
            )
        except Exception as exc:
            logger.warning(f"CloudTrail fetch failed (non-fatal): {exc}")
            # Don't fail the whole pipeline if CloudTrail is unavailable
            infra_ctx = {
                "total_events": 0,
                "high_risk_events": [],
                "failed_api_calls": [],
                "hypotheses": [],
                "by_user": {},
                "summary_by_category": {},
                "window": {},
            }

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
                        json.dumps({
                            "anchor":    log_data["anchor"],
                            "stages":    log_data["stages"],
                            "per_group": log_data["per_group"],
                            # Store infra context alongside logs for audit
                            "infra_events_count":    infra_ctx.get("total_events", 0),
                            "infra_high_risk_count": len(infra_ctx.get("high_risk_events", [])),
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
            infra_ctx      = infra_ctx,   
        )

        # ── Invoke Bedrock ─────────────────────────────────────────────────────
        _update_status(incident_id, "finding_rca")
        estimated_tokens = len(prompt) // 4

        if estimated_tokens > 25000:
            logger.warning(f"[Prompt Size Warning] Large prompt: ~{estimated_tokens} tokens")

        logger.info(
            f"[Bedrock Prompt] "
            f"chars={len(prompt)} | "
            f"estimated_tokens={estimated_tokens} | "
            f"top_errors={len(log_data.get('top_errors', []))} | "
            f"groups={len(log_data.get('per_group', {}))} | "
            f"infra_events={infra_ctx.get('total_events', 0)}"
        )
        logger.info(f"[Bedrock Prompt Preview]\n{prompt[:8000]}")

        rca = _invoke_bedrock(prompt)

        logger.info(
            f"[RCA Summary] "
            f"confidence={rca.get('confidence_score')} | "
            f"type={rca.get('root_cause_type')} | "
            f"who={rca.get('who')} | "
            f"root_cause={rca.get('root_cause', '')[:300]}"
        )

        # ── Update RCA ──────────────────────────────────────────────────────────
        with get_db() as conn:
            with conn.cursor() as cur:
                confidence_percentage = round(
                    float(rca.get("confidence_score", 0.5)) * 100, 2
                )

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
                        rca.get("rca_report", ""),
                        rca.get("remediation_steps", ""),
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