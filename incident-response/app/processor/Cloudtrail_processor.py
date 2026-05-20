"""
processor/cloudtrail_processor.py
──────────────────────────────────
Infrastructure-side event collection via CloudTrail.

What this module does
──────────────────────
1. Fetches ALL infrastructure change events (deployments, scaling, IAM, config,
   network, storage, security) around the incident window.

2. Correlates each event with the incident timeline — "who did what, when,
   and how close to the outage?"

3. Produces a structured InfraContext dict that process_incident.py feeds
   directly into the Bedrock prompt alongside log data.

4. Adds a timeline_correlation section that ranks events by proximity to
   the first error anchor — so the AI can immediately see "IAM policy
   change 3 minutes before first error" vs noise from 2 hours prior.

Why separate from log_processor.py
────────────────────────────────────
• CloudTrail and CloudWatch Logs are completely different AWS APIs.
• CloudTrail has its own pagination model (lookup_events with LookupAttributes).
• Infra events need different compression logic — dedup by (EventName, resource)
  not by log fingerprint.
• Keeping them separate lets you disable CloudTrail without touching log logic.

Integration
────────────
Call fetch_infra_context() from process_incident.py after fetching logs:

    from app.processor.cloudtrail_processor import fetch_infra_context

    infra_ctx = fetch_infra_context(
        region          = region,
        instance_id     = instance_id,
        down_time       = incident_down_time,
        anchor          = log_data["anchor"],
        severity        = severity,
        issue           = issue,
    )

Then pass infra_ctx into _build_prompt() as a new parameter.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ─── CloudTrail API calls we care about, grouped by category ──────────────────

_INFRA_EVENTS: dict[str, list[str]] = {
    "deployment": [
        # EC2
        "RunInstances", "TerminateInstances", "StopInstances",
        "StartInstances", "RebootInstances", "ModifyInstanceAttribute",
        # ECS
        "UpdateService", "CreateService", "DeleteService", "RunTask",
        # Lambda
        "UpdateFunctionCode", "UpdateFunctionConfiguration",
        "PublishVersion", "CreateAlias", "UpdateAlias",
        # CodeDeploy
        "CreateDeployment", "StopDeployment",
        # SSM
        "SendCommand", "StartAutomationExecution",
        # EKS
        "UpdateNodegroupConfig", "UpdateClusterVersion",
    ],
    "scaling": [
        "UpdateAutoScalingGroup", "ExecutePolicy",
        "TerminateInstanceInAutoScalingGroup", "SetDesiredCapacity",
        "AttachInstances", "DetachInstances",
        "PutScalingPolicy", "DeleteScalingPolicy",
    ],
    "network": [
        # Security groups
        "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
        "CreateSecurityGroup", "DeleteSecurityGroup",
        # NACLs / Route tables
        "CreateNetworkAclEntry", "DeleteNetworkAclEntry",
        "ReplaceNetworkAclEntry", "CreateRoute", "DeleteRoute",
        "ReplaceRoute",
        # Load balancers
        "ModifyTargetGroupAttributes", "RegisterTargets",
        "DeregisterTargets", "CreateRule", "DeleteRule", "ModifyRule",
        "ModifyLoadBalancerAttributes",
        # VPC
        "ModifyVpcAttribute", "CreateVpcEndpoint", "DeleteVpcEndpoint",
    ],
    "storage": [
        # EBS
        "AttachVolume", "DetachVolume", "ModifyVolume",
        "EnableFastSnapshotRestores",
        # S3
        "PutBucketPolicy", "DeleteBucketPolicy",
        "PutBucketAcl",
        # EFS
        "CreateMountTarget", "DeleteMountTarget",
        # RDS
        "ModifyDBInstance", "RebootDBInstance",
        "FailoverDBCluster", "RestoreDBInstanceFromDBSnapshot",
    ],
    "iam": [
        "AttachRolePolicy", "DetachRolePolicy",
        "PutRolePolicy", "DeleteRolePolicy",
        "CreateRole", "DeleteRole",
        "AttachUserPolicy", "DetachUserPolicy",
        "PutUserPolicy", "DeleteUserPolicy",
        "AssumeRole",
        "UpdateAssumeRolePolicy",
    ],
    "config": [
        "PutSecretValue", "RotateSecret",
        "PutParameter", "DeleteParameter",               # SSM Parameter Store
        "PutConfigurationRecorder",
        "CreateStack", "UpdateStack", "DeleteStack",     # CloudFormation
        "ExecuteChangeSet",
        "ModifyInstanceAttribute",
    ],
    "security": [
        "DisableKey", "ScheduleKeyDeletion",            # KMS
        "PutKeyPolicy",
        "CreateGrant", "RetireGrant",
        "GetSecretValue",                               # unusual secret reads
    ],
}

# Flat lookup: event_name → category
_EVENT_TO_CATEGORY: dict[str, str] = {
    event: category
    for category, events in _INFRA_EVENTS.items()
    for event in events
}

ALL_TRACKED_EVENTS = set(_EVENT_TO_CATEGORY.keys())


# ─── Risk scoring: how dangerous is each event type to availability? ───────────
#
# Score 1-10.  Used to rank events in the correlation output.
# Higher = more likely to cause an outage.

_EVENT_RISK: dict[str, int] = {
    # Deployment events — high blast radius
    "TerminateInstances":              10,
    "StopInstances":                   10,
    "DeleteService":                   10,
    "RebootInstances":                  9,
    "UpdateFunctionCode":               8,
    "UpdateService":                    8,
    "CreateDeployment":                 8,
    "StopDeployment":                   7,
    "RunInstances":                     6,
    # IAM — permission changes can silently break everything
    "DetachRolePolicy":                 9,
    "DeleteRolePolicy":                 9,
    "AttachRolePolicy":                 7,
    "PutRolePolicy":                    7,
    # Network — wrong SG/NACL = connection refused
    "RevokeSecurityGroupIngress":       9,
    "RevokeSecurityGroupEgress":        9,
    "AuthorizeSecurityGroupIngress":    5,
    "DeleteRoute":                      9,
    "ReplaceRoute":                     8,
    "DeregisterTargets":               10,
    "ModifyTargetGroupAttributes":      8,
    # Storage
    "DetachVolume":                    10,
    "ModifyVolume":                     7,
    "ModifyDBInstance":                 8,
    "RebootDBInstance":                 9,
    "FailoverDBCluster":               10,
    # Config / secrets
    "PutParameter":                     6,
    "PutSecretValue":                   6,
    "RotateSecret":                     7,
    "UpdateStack":                      8,
    "ExecuteChangeSet":                 9,
    "DeleteStack":                     10,
    # Security
    "DisableKey":                      10,
    "ScheduleKeyDeletion":             10,
    "PutKeyPolicy":                     8,
    # Scaling
    "UpdateAutoScalingGroup":           6,
    "SetDesiredCapacity":               5,
    "TerminateInstanceInAutoScalingGroup": 8,
}

DEFAULT_RISK = 4  # for events not in the table


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _minutes_before(event_ts: str, reference_ts: str) -> Optional[float]:
    """Return how many minutes `event_ts` is before `reference_ts`. Negative = after."""
    try:
        e = datetime.fromisoformat(event_ts.replace("Z", "+00:00"))
        r = datetime.fromisoformat(reference_ts.replace("Z", "+00:00"))
        return round((r - e).total_seconds() / 60, 1)
    except Exception:
        return None


def _extract_user(raw_event: dict) -> str:
    """Best-effort: extract who triggered the event."""
    uid = raw_event.get("UserIdentity", {})
    if isinstance(uid, str):
        return uid
    # Principal types: Root, IAMUser, AssumedRole, FederatedUser, AWSService
    ptype = uid.get("type", "")
    if ptype == "Root":
        return "root"
    if ptype == "IAMUser":
        return uid.get("userName", "iam-user")
    if ptype == "AssumedRole":
        arn = uid.get("arn", "")
        # arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION
        parts = arn.split("/")
        role    = parts[1] if len(parts) > 1 else arn
        session = parts[2] if len(parts) > 2 else ""
        return f"{role}/{session}" if session else role
    if ptype == "AWSService":
        return uid.get("invokedBy", "aws-service")
    return uid.get("arn") or uid.get("principalId") or "unknown"


def _extract_resources(raw_event: dict) -> list[str]:
    """Extract resource names/ARNs from raw CloudTrail event."""
    resources = []
    for r in raw_event.get("Resources", []):
        name = r.get("ResourceName") or r.get("ARN", "")
        if name:
            resources.append(name)

    # Also pull from CloudTrail event detail if available
    detail_str = raw_event.get("CloudTrailEvent", "")
    if detail_str:
        try:
            detail = json.loads(detail_str)
            req = detail.get("requestParameters") or {}
            # EC2: instanceId / instanceIds
            for key in ("instanceId", "instanceIds", "dbInstanceIdentifier",
                        "functionName", "clusterName", "stackName"):
                val = req.get(key)
                if val:
                    if isinstance(val, list):
                        resources.extend(val)
                    else:
                        resources.append(str(val))
        except Exception:
            pass

    return list(dict.fromkeys(r for r in resources if r))  # dedup, preserve order


def _parse_error_code(raw_event: dict) -> Optional[str]:
    """If the API call failed, return the error code."""
    detail_str = raw_event.get("CloudTrailEvent", "")
    if not detail_str:
        return None
    try:
        detail = json.loads(detail_str)
        return detail.get("errorCode") or detail.get("errorMessage")
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE A — CloudTrail Fetch (paginated)
# ═══════════════════════════════════════════════════════════════════════════════

def _fetch_cloudtrail_events(
    ct_client,
    start_time: datetime,
    end_time:   datetime,
    max_events: int = 2000,
) -> list[dict]:
    """
    Paginated lookup_events for ALL tracked events in the window.
    We filter locally rather than by LookupAttributes so we catch
    every relevant event regardless of resource type.

    Returns list of raw CloudTrail event dicts (not yet structured).
    """
    collected = []
    next_token = None

    page = 0
    while True:
        try:
            kwargs: dict = dict(
                StartTime=start_time,
                EndTime=end_time,
                PaginationConfig={"MaxItems": 50, "PageSize": 50},
            )
            if next_token:
                kwargs["NextToken"] = next_token

            paginator = ct_client.get_paginator("lookup_events")
            # We can't pass PaginationConfig here; use manual pagination instead
            call_kwargs: dict = dict(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            )
            if next_token:
                call_kwargs["NextToken"] = next_token

            resp   = ct_client.lookup_events(**call_kwargs)
            events = resp.get("Events", [])
            page  += 1

            for raw in events:
                name = raw.get("EventName", "")
                if name in ALL_TRACKED_EVENTS:
                    collected.append(raw)

            logger.debug(f"[CloudTrail page {page}] +{len(events)} raw, {len(collected)} matched")

            next_token = resp.get("NextToken")
            if not next_token or len(collected) >= max_events:
                break

        except Exception as exc:
            logger.warning(f"[CloudTrail] fetch error (page {page}): {exc}")
            break

    logger.info(f"[CloudTrail] {len(collected)} infra events in {page} page(s)")
    return collected


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE B — Structured Event Parsing
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_event(raw: dict) -> dict:
    """Convert a raw CloudTrail event → structured InfraEvent."""
    name       = raw.get("EventName", "")
    event_time = raw.get("EventTime")
    ts_iso     = event_time.isoformat() if event_time else ""
    resources  = _extract_resources(raw)
    error_code = _parse_error_code(raw)
    user       = _extract_user(raw)
    category   = _EVENT_TO_CATEGORY.get(name, "other")
    risk       = _EVENT_RISK.get(name, DEFAULT_RISK)

    return {
        "ts":           ts_iso,
        "event_name":   name,
        "event_source": raw.get("EventSource", ""),
        "category":     category,
        "risk_score":   risk,
        "user":         user,
        "resources":    resources,
        "error_code":   error_code,   # None if the API call succeeded
        "failed":       bool(error_code),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE C — Timeline Correlation
# ═══════════════════════════════════════════════════════════════════════════════

def _correlate_timeline(
    events:          list[dict],
    first_error_ts:  Optional[str],
    down_time_iso:   str,
    scan_start_iso:  str,
) -> list[dict]:
    """
    For each infra event, compute:
      • mins_before_first_error   (positive = before, negative = after)
      • mins_before_detection     (vs down_time)
      • proximity_label           ("CRITICAL: 2m before first error")
      • correlation_strength      ("high" | "medium" | "low")

    Events are then sorted: highest risk × closest to first_error first.
    """
    reference = first_error_ts or down_time_iso

    for ev in events:
        mb_first  = _minutes_before(ev["ts"], reference)
        mb_detect = _minutes_before(ev["ts"], down_time_iso)

        ev["mins_before_first_error"] = mb_first
        ev["mins_before_detection"]   = mb_detect

        # Proximity label
        if mb_first is None:
            ev["proximity_label"] = "unknown timing"
            ev["correlation_strength"] = "low"
        elif 0 <= mb_first <= 5:
            ev["proximity_label"] = f"⚡ {mb_first}m before first error — HIGHLY SUSPICIOUS"
            ev["correlation_strength"] = "high"
        elif 5 < mb_first <= 15:
            ev["proximity_label"] = f"⚠ {mb_first}m before first error — suspicious"
            ev["correlation_strength"] = "medium"
        elif 15 < mb_first <= 60:
            ev["proximity_label"] = f"{mb_first}m before first error"
            ev["correlation_strength"] = "low"
        elif mb_first < 0:
            ev["proximity_label"] = f"{abs(mb_first)}m AFTER first error — likely consequence"
            ev["correlation_strength"] = "consequence"
        else:
            ev["proximity_label"] = f"{mb_first}m before first error"
            ev["correlation_strength"] = "low"

    # Sort: high-correlation + high-risk first
    weight_map = {"high": 3, "medium": 2, "consequence": 1, "low": 0}
    events.sort(key=lambda e: (
        -weight_map.get(e["correlation_strength"], 0),
        -e["risk_score"],
        e.get("mins_before_first_error") or 9999,
    ))

    return events


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE D — Compression & Dedup
# ═══════════════════════════════════════════════════════════════════════════════

def _compress_infra_events(events: list[dict]) -> dict:
    """
    Compress structured infra events into a prompt-ready summary.

    Dedup by (event_name, resource_key) — if the same operation was
    performed multiple times (e.g. auto-scaling), collapse into one
    entry with a count and the first/last timestamps.

    Returns:
    {
      "summary_by_category":  {category: [compressed_events]},
      "high_risk_events":     [events with risk_score >= 8],
      "failed_api_calls":     [events where the API call itself failed],
      "total_events":         int,
      "by_user":              {user: event_count},
    }
    """
    dedup: dict[str, dict] = {}

    for ev in events:
        res_key   = "|".join(sorted(ev["resources"])) or "no-resource"
        dedup_key = f"{ev['event_name']}::{res_key}"

        if dedup_key in dedup:
            existing = dedup[dedup_key]
            existing["count"] += 1
            # Keep earliest timestamp
            if ev["ts"] < existing["ts"]:
                existing["ts"]                    = ev["ts"]
                existing["mins_before_first_error"] = ev["mins_before_first_error"]
                existing["mins_before_detection"]   = ev["mins_before_detection"]
                existing["proximity_label"]         = ev["proximity_label"]
                existing["correlation_strength"]    = ev["correlation_strength"]
        else:
            entry = dict(ev)
            entry["count"] = 1
            dedup[dedup_key] = entry

    all_events = list(dedup.values())

    # Group by category
    by_cat: dict[str, list] = {}
    for ev in all_events:
        by_cat.setdefault(ev["category"], []).append(ev)

    # High risk
    high_risk = [e for e in all_events if e["risk_score"] >= 8]
    high_risk.sort(key=lambda e: -e["risk_score"])

    # Failed API calls (the infra change itself returned an error)
    failed = [e for e in all_events if e["failed"]]

    # Who did the most changes?
    by_user: dict[str, int] = {}
    for ev in all_events:
        by_user[ev["user"]] = by_user.get(ev["user"], 0) + ev["count"]

    return {
        "summary_by_category": by_cat,
        "high_risk_events":    high_risk[:20],
        "failed_api_calls":    failed,
        "total_events":        sum(e["count"] for e in all_events),
        "by_user":             dict(sorted(by_user.items(), key=lambda x: -x[1])),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE E — Root Cause Hypothesis Generation
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_infra_hypotheses(
    high_risk_events: list[dict],
    first_error_ts:   Optional[str],
) -> list[dict]:
    """
    From the high-risk events closest to the first error, generate explicit
    root cause hypotheses that the AI can confirm or reject using log evidence.

    Each hypothesis:
    {
      "hypothesis":   str,    # human-readable sentence
      "trigger":      str,    # which infra event
      "user":         str,    # who triggered it
      "ts":           str,    # when
      "confidence":   str,    # "high" | "medium" | "low"
    }
    """
    hypotheses = []

    for ev in high_risk_events:
        strength = ev.get("correlation_strength", "low")
        if strength not in ("high", "medium"):
            continue

        name    = ev["event_name"]
        user    = ev["user"]
        res     = ", ".join(ev["resources"][:2]) or "target resource"
        ts      = ev["ts"]
        mins    = ev.get("mins_before_first_error")
        mins_str = f"{mins}m before first error" if mins is not None else "near incident time"

        # Generate hypothesis text by event type
        if name in ("TerminateInstances", "StopInstances"):
            hyp = f"Instance termination/stop by '{user}' on {res} ({mins_str}) may have caused the outage directly."
        elif name == "RebootInstances":
            hyp = f"Instance reboot by '{user}' on {res} ({mins_str}) — downtime expected during reboot, may not have completed cleanly."
        elif name in ("DetachRolePolicy", "DeleteRolePolicy", "PutRolePolicy"):
            hyp = f"IAM policy change by '{user}' on {res} ({mins_str}) may have revoked permissions the application depends on."
        elif name in ("RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress"):
            hyp = f"Security group rule revoked by '{user}' on {res} ({mins_str}) — may have blocked required inbound/outbound traffic."
        elif name in ("DeregisterTargets", "ModifyTargetGroupAttributes"):
            hyp = f"Load balancer target change by '{user}' on {res} ({mins_str}) — instance may have been removed from rotation."
        elif name in ("UpdateService", "CreateDeployment"):
            hyp = f"Service update/deployment by '{user}' on {res} ({mins_str}) — new version may have introduced the failure."
        elif name in ("UpdateFunctionCode", "UpdateFunctionConfiguration"):
            hyp = f"Lambda function change by '{user}' on {res} ({mins_str}) — code or config update may have broken downstream calls."
        elif name == "FailoverDBCluster":
            hyp = f"Database failover triggered by '{user}' on {res} ({mins_str}) — connection pool exhaustion and 'connection refused' errors expected during failover."
        elif name == "ModifyDBInstance":
            hyp = f"DB instance modification by '{user}' on {res} ({mins_str}) — may have caused a maintenance restart or parameter change."
        elif name == "RotateSecret":
            hyp = f"Secret rotation by '{user}' on {res} ({mins_str}) — application may not have picked up new credentials yet."
        elif name in ("PutParameter", "PutSecretValue"):
            hyp = f"Config/secret value changed by '{user}' on {res} ({mins_str}) — application may be using wrong credentials or config."
        elif name in ("UpdateStack", "ExecuteChangeSet", "DeleteStack"):
            hyp = f"CloudFormation stack change by '{user}' on {res} ({mins_str}) — infrastructure change may have altered dependent resources."
        elif name == "DisableKey":
            hyp = f"KMS key disabled by '{user}' on {res} ({mins_str}) — encrypted resources (EBS, S3, RDS) may now be inaccessible."
        elif name in ("DeleteRoute", "ReplaceRoute"):
            hyp = f"Route table change by '{user}' on {res} ({mins_str}) — may have broken network path to dependent services."
        elif name == "DetachVolume":
            hyp = f"EBS volume detached by '{user}' from {res} ({mins_str}) — application filesystem may have become unavailable."
        else:
            hyp = f"Infrastructure change '{name}' by '{user}' on {res} ({mins_str}) — correlates with incident timeline."

        hypotheses.append({
            "hypothesis":  hyp,
            "trigger":     name,
            "user":        user,
            "resources":   ev["resources"],
            "ts":          ts,
            "confidence":  "high" if strength == "high" else "medium",
            "risk_score":  ev["risk_score"],
        })

    # Sort by confidence then risk
    hypotheses.sort(key=lambda h: (0 if h["confidence"] == "high" else 1, -h["risk_score"]))
    return hypotheses[:10]


# ═══════════════════════════════════════════════════════════════════════════════
# PROMPT FORMATTER
# ═══════════════════════════════════════════════════════════════════════════════

def format_infra_context_for_prompt(infra_ctx: dict) -> str:
    """
    Convert infra_ctx into a compact, AI-readable block for the Bedrock prompt.

    Format:
        ╔═ INFRASTRUCTURE CHANGE EVENTS ═════════════════════════════════════
        ║ Total events in window: 7  |  High-risk: 3  |  Failed API calls: 1
        ║
        ║ ── HIGH-RISK EVENTS (ranked by proximity × risk) ─────────────────
        ║  [RISK:10] DeregisterTargets | user: ops-role | res: tg-prod-api
        ║            ⚡ 3.2m before first error — HIGHLY SUSPICIOUS
        ║            ts: 2026-05-15T09:45:11Z
        ║
        ║  [RISK:8]  UpdateService | user: deploy-pipeline | res: svc-api
        ║            ⚠ 12.1m before first error — suspicious
        ║            ts: 2026-05-15T09:36:22Z
        ║
        ║ ── ROOT CAUSE HYPOTHESES (infra side) ─────────────────────────────
        ║  [HIGH] Instance removed from LB target group 3m before outage.
        ║         Cross-reference: expect 'connection refused' in nginx logs.
        ║
        ║ ── FAILED API CALLS ───────────────────────────────────────────────
        ║  UpdateStack → AccessDeniedException  (user: deploy-user)
        ║
        ║ ── CHANGES BY USER ────────────────────────────────────────────────
        ║  deploy-pipeline: 4 changes | ops-role: 2 | root: 1
        ╚════════════════════════════════════════════════════════════════════
    """
    if not infra_ctx or infra_ctx.get("total_events", 0) == 0:
        return "No infrastructure change events found in the investigation window."

    lines = []
    lines.append("╔═ INFRASTRUCTURE CHANGE EVENTS (CloudTrail)")

    total       = infra_ctx.get("total_events", 0)
    high_risk   = infra_ctx.get("high_risk_events", [])
    failed      = infra_ctx.get("failed_api_calls", [])
    by_user     = infra_ctx.get("by_user", {})
    hypotheses  = infra_ctx.get("hypotheses", [])
    first_error = infra_ctx.get("first_error_ts")
    detect_time = infra_ctx.get("detection_time")
    window      = infra_ctx.get("window", {})

    lines.append(
        f"║ Scan window : {window.get('start', 'n/a')} → {window.get('end', 'n/a')}"
    )
    lines.append(
        f"║ Total events: {total}  |  "
        f"High-risk: {len(high_risk)}  |  "
        f"Failed API calls: {len(failed)}"
    )
    if first_error:
        lines.append(f"║ First log error anchor : {first_error}")
    if detect_time:
        lines.append(f"║ Health-check detection : {detect_time}")
    lines.append("║")

    # High-risk events
    lines.append("║ ── HIGH-RISK EVENTS (ranked: proximity × risk) ─────────────────")
    if high_risk:
        for ev in high_risk[:10]:
            res_str = ", ".join(ev["resources"][:2]) or "n/a"
            lines.append(
                f"║  [RISK:{ev['risk_score']:02d}] {ev['event_name']} | "
                f"user: {ev['user']} | resource: {res_str}"
            )
            lines.append(f"║           {ev.get('proximity_label', '')}")
            lines.append(f"║           ts: {ev['ts']}")
            if ev.get("count", 1) > 1:
                lines.append(f"║           (repeated {ev['count']}x)")
            lines.append("║")
    else:
        lines.append("║  (none above risk threshold)")
        lines.append("║")

    # Hypotheses
    lines.append("║ ── ROOT CAUSE HYPOTHESES (infra-side) ──────────────────────────")
    if hypotheses:
        for h in hypotheses:
            tag = "HIGH" if h["confidence"] == "high" else "MED "
            lines.append(f"║  [{tag}] {h['hypothesis']}")
            lines.append(f"║         Verify in logs: look for errors starting at {h['ts']}")
            lines.append("║")
    else:
        lines.append("║  No high-confidence infra hypothesis (no changes close to first error).")
        lines.append("║  Root cause is more likely application-side — see log analysis above.")
        lines.append("║")

    # Failed API calls
    if failed:
        lines.append("║ ── FAILED INFRA API CALLS ──────────────────────────────────────")
        for ev in failed[:5]:
            res_str = ", ".join(ev["resources"][:1]) or "n/a"
            lines.append(
                f"║  {ev['event_name']} → {ev['error_code']} "
                f"(user: {ev['user']}, res: {res_str})"
            )
        lines.append("║")

    # Changes by user
    lines.append("║ ── CHANGES BY USER ─────────────────────────────────────────────")
    user_parts = [f"{u}: {c}" for u, c in list(by_user.items())[:6]]
    lines.append("║  " + "  |  ".join(user_parts) if user_parts else "║  (none)")

    lines.append("╚" + "═" * 60)
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_infra_context(
    cloudtrail_client,
    region:         str,
    instance_id:    str,
    down_time:      datetime,
    anchor:         dict,
    severity:       str = "medium",
    issue:          str = "",
    lookback_extra: int = 0,   # extra minutes before adaptive window
) -> dict:
    """
    Full CloudTrail pipeline for one incident.

    Args:
        cloudtrail_client boto3 client for CloudTrail
        region          AWS region of the primary instance
        instance_id     EC2 instance ID (for logging/context only; we scan all events)
        down_time       When the health check detected the failure
        anchor          log_data["anchor"] from log_processor — gives first_error_ts
        severity        incident severity
        issue           free-text issue description
        lookback_extra  additional minutes to scan before the adaptive window

    Returns infra_ctx dict with all phases merged.
    """
    logger.info(f"[CloudTrail] Starting infra context fetch for {instance_id} in {region}")

    # Determine scan window — match log_processor adaptive window + a bit extra
    from app.processor.log_processor import compute_adaptive_window
    adaptive    = compute_adaptive_window(severity, issue)
    before_mins = adaptive["before_minutes"] + lookback_extra
    after_mins  = adaptive["after_minutes"]

    scan_start = down_time - timedelta(minutes=before_mins)
    scan_end   = down_time + timedelta(minutes=after_mins)

    first_error_ts: Optional[str] = anchor.get("first_error_ts")

    logger.info(
        f"[CloudTrail] window: {scan_start.strftime('%H:%M')} → "
        f"{scan_end.strftime('%H:%M')} | first_error_anchor: {first_error_ts}"
    )

    try:
        # Phase A — fetch
        raw_events = _fetch_cloudtrail_events(cloudtrail_client, scan_start, scan_end)

        if not raw_events:
            logger.info("[CloudTrail] No matching infra events in window")
            return _empty_infra_result(scan_start, scan_end, down_time, first_error_ts)

        # Phase B — parse
        parsed = [_parse_event(e) for e in raw_events]

        # Phase C — timeline correlation
        correlated = _correlate_timeline(
            parsed,
            first_error_ts,
            down_time.isoformat(),
            scan_start.isoformat(),
        )

        # Phase D — compress
        compressed = _compress_infra_events(correlated)

        # Phase E — hypotheses
        hypotheses = _generate_infra_hypotheses(
            compressed["high_risk_events"], first_error_ts
        )

        result = {
            **compressed,
            "hypotheses":    hypotheses,
            "first_error_ts": first_error_ts,
            "detection_time": down_time.isoformat(),
            "window": {
                "start": scan_start.isoformat(),
                "end":   scan_end.isoformat(),
            },
        }

        logger.info(
            f"[CloudTrail] Done | total={result['total_events']} | "
            f"high_risk={len(result['high_risk_events'])} | "
            f"hypotheses={len(hypotheses)}"
        )
        return result

    except Exception as exc:
        logger.error(f"[CloudTrail] fetch_infra_context failed: {exc}", exc_info=True)
        return _empty_infra_result(scan_start, scan_end, down_time, first_error_ts)


def _empty_infra_result(
    scan_start:     datetime,
    scan_end:       datetime,
    down_time:      datetime,
    first_error_ts: Optional[str],
) -> dict:
    return {
        "summary_by_category": {},
        "high_risk_events":    [],
        "failed_api_calls":    [],
        "total_events":        0,
        "by_user":             {},
        "hypotheses":          [],
        "first_error_ts":      first_error_ts,
        "detection_time":      down_time.isoformat(),
        "window": {
            "start": scan_start.isoformat(),
            "end":   scan_end.isoformat(),
        },
    }