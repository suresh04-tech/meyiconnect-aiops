"""
processor/dependency_resolver.py
─────────────────────────────────
Resolves ANY dependency type (ec2 / alb) into a normalized list of EC2 targets.

The rest of the pipeline (metrics, logs, RCA) never cares about the source —
it always receives:

    [
        {
            "instance_id": "i-xxx",
            "region":      "us-east-1",
            "log_groups":  ["group-a", "group-b"],
        },
        ...
    ]

Supported dependency types
──────────────────────────
  • ec2  — direct instance ID, passed through unchanged
  • alb  — DNS name resolved → ARN → target groups → EC2 instance IDs

Input schema (one dependency dict)
───────────────────────────────────
{
    "type":            "ec2" | "alb",
    "resource_id":     "i-01cbe..." | "internal-api-prod.us-east-1.elb.amazonaws.com",
    "region":          "us-east-1",
    "log_group_name":  ["group-a", "group-b"]   # optional list or CSV string
}
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_log_groups(raw) -> list[str]:
    """Normalise log_group_name / log_group_names → plain list of strings."""
    if not raw:
        return []
    if isinstance(raw, str):
        return [g.strip() for g in raw.split(",") if g.strip()]
    if isinstance(raw, list):
        return [g for g in raw if g]
    return []


# ═══════════════════════════════════════════════════════════════════════════════
# ALB resolver
# ═══════════════════════════════════════════════════════════════════════════════

def _resolve_alb_dns_to_arn(elbv2_client, dns_name: str) -> Optional[str]:
    """
    Resolve an ALB DNS name to its LoadBalancerArn.

    AWS doesn't have a 'lookup by DNS' API, so we page through all ALBs
    in the account/region and match on DNSName (case-insensitive).
    """

    normalized_dns = (
        dns_name
        .replace("http://", "")
        .replace("https://", "")
        .strip("/")
        .lower()
    )

    paginator = elbv2_client.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page.get("LoadBalancers", []):
             alb_dns = lb.get("DNSName", "").lower()
             if alb_dns == normalized_dns:
                arn = lb["LoadBalancerArn"]
                logger.info(
                    f"[ALB resolver] Matched DNS "
                    f"'{normalized_dns}' → ARN '{arn}'"
                )
                return arn

    logger.warning(f"[ALB resolver] No ALB found for DNS name: {dns_name}")
    return None


def _get_target_instances(elbv2_client, alb_arn: str) -> list[dict]:
    """
    ALB ARN → list of EC2 instance IDs currently registered as targets.

    Returns:
        [
            {"instance_id": "i-xxx", "health": "healthy",
             "reason": "...", "target_group_arn": "arn:..."},
            ...
        ]
    """
    instances: list[dict] = []

    try:
        tg_resp = elbv2_client.describe_target_groups(LoadBalancerArn=alb_arn)
    except Exception as exc:
        logger.error(f"[ALB resolver] describe_target_groups failed: {exc}")
        return instances

    for tg in tg_resp.get("TargetGroups", []):
        tg_arn = tg["TargetGroupArn"]
        try:
            health_resp = elbv2_client.describe_target_health(TargetGroupArn=tg_arn)
        except Exception as exc:
            logger.warning(f"[ALB resolver] describe_target_health failed for {tg_arn}: {exc}")
            continue

        for thd in health_resp.get("TargetHealthDescriptions", []):
            target = thd.get("Target", {})
            instance_id = target.get("Id")
            if not instance_id or not instance_id.startswith("i-"):
                continue  # skip IP-mode or Lambda targets

            health_info = thd.get("TargetHealth", {})
            instances.append({
                "instance_id":     instance_id,
                "health":          health_info.get("State", "unknown"),
                "reason":          health_info.get("Reason", ""),
                "description":     health_info.get("Description", ""),
                "target_group_arn": tg_arn,
            })
            logger.info(
                f"[ALB resolver] Found target {instance_id} "
                f"state={health_info.get('State')} reason={health_info.get('Reason')}"
            )

    logger.info(f"[ALB resolver] Total targets for ALB: {len(instances)}")
    return instances


def resolve_alb(dep: dict, aws_factory) -> tuple[list[dict], dict]:
    """
    Resolve an ALB dependency into normalised EC2 targets.

    Returns:
        (normalized_instances, alb_meta)

        normalized_instances — list of {instance_id, region, log_groups}
        alb_meta             — raw ALB info for the prompt / DB (target health, etc.)
    """
    region      = dep.get("region", "us-east-1")
    resource_id = dep.get("resource_id", "")      # DNS name
    log_groups  = _parse_log_groups(
        dep.get("log_group_name") or dep.get("log_group_names")
    )

    elbv2 = aws_factory.get_client("elbv2", region_name=region)

    # Step 1 — DNS → ARN
    alb_arn = _resolve_alb_dns_to_arn(elbv2, resource_id)
    if not alb_arn:
        logger.error(f"[ALB resolver] Cannot resolve ALB DNS: {resource_id}")
        return [], {}

    # Step 2 — ARN → target instances
    raw_targets = _get_target_instances(elbv2, alb_arn)

    alb_meta = {
        "alb_dns":  resource_id,
        "alb_arn":  alb_arn,
        "targets":  raw_targets,
        "total":    len(raw_targets),
        "healthy":  sum(1 for t in raw_targets if t["health"] == "healthy"),
        "unhealthy": sum(1 for t in raw_targets if t["health"] == "unhealthy"),
    }

    normalized = [
        {
            "instance_id": t["instance_id"],
            "region":      region,
            "log_groups":  log_groups,
            # carry target health for prioritisation later
            "target_health": t["health"],
            "target_reason": t.get("reason", ""),
        }
        for t in raw_targets
    ]

    return normalized, alb_meta


# ═══════════════════════════════════════════════════════════════════════════════
# EC2 resolver (passthrough)
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_ec2(dep: dict) -> list[dict]:
    """Direct EC2 dependency — just normalise field names."""
    log_groups = _parse_log_groups(
        dep.get("log_group_name") or dep.get("log_group_names")
    )
    return [{
        "instance_id":   dep.get("resource_id") or dep.get("instance_id", ""),
        "region":        dep.get("region", "us-east-1"),
        "log_groups":    log_groups,
        "target_health": "unknown",
        "target_reason": "",
    }]


# ═══════════════════════════════════════════════════════════════════════════════
# Public entry point
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_dependencies(raw_deps: list[dict], aws_factory) -> tuple[list[dict], dict]:
    """
    Convert raw dependency list (from DB) into normalized EC2 targets.

    Returns:
        (normalized_instances, alb_meta)

        normalized_instances — list[{instance_id, region, log_groups, ...}]
        alb_meta             — ALB-specific data if dep type is alb, else {}
    """
    all_instances: list[dict] = []
    alb_meta: dict = {}

    for dep in raw_deps:
        dep_type = (dep.get("type") or "ec2").lower()

        if dep_type == "alb":
            instances, meta = resolve_alb(dep, aws_factory)
            all_instances.extend(instances)
            alb_meta = meta   # one ALB per incident for now

        else:
            # default: treat as EC2
            instances = resolve_ec2(dep)
            all_instances.extend(instances)

    # De-duplicate by instance_id (ALB may register same instance in multiple TGs)
    seen: set[str] = set()
    unique: list[dict] = []
    for inst in all_instances:
        iid = inst["instance_id"]
        if iid and iid not in seen:
            seen.add(iid)
            unique.append(inst)

    logger.info(
        f"[DependencyResolver] Resolved {len(raw_deps)} dep(s) → "
        f"{len(unique)} unique EC2 target(s): {[i['instance_id'] for i in unique]}"
    )
    return unique, alb_meta
