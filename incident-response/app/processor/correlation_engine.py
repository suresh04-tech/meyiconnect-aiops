"""
processor/correlation_engine.py
────────────────────────────────
Cross-instance correlation logic.

Takes per-instance analysis results and produces a compact correlation
summary that the prompt builder uses instead of raw per-instance dumps.

Scenarios detected:
  A — single instance failing, rest healthy    → isolated host failure
  B — all instances failing                    → shared dependency outage
  C — ALB-level issue (instances healthy)      → load-balancer misconfiguration
  D — partial degradation (subset unhealthy)   → rolling failure / canary issue
"""

import logging
import math
from collections import Counter

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _is_healthy(inst_analysis: dict) -> bool:
    """Heuristic: consider instance healthy if error rate is low and metrics ok."""
    metrics = inst_analysis.get("metrics", {})
    status  = inst_analysis.get("ec2", {}).get("status_checks", {})

    # Hard fail: instance/system status check failed
    if status.get("instance_status") == "impaired":
        return False
    if status.get("system_status") == "impaired":
        return False

    # Hard fail: target health says unhealthy
    if inst_analysis.get("target_health") == "unhealthy":
        return False

    # Soft signal: error count
    error_count = inst_analysis.get("total_error_count", 0)
    if error_count > 50:
        return False

    return True


def _extract_common_errors(analyses: list[dict]) -> list[str]:
    """Return error fingerprints that appear in >50 % of instances."""
    if not analyses:
        return []

    fingerprint_sets = []
    for a in analyses:
        fps = set()
        for stage_data in a.get("log_summary", {}).get("per_group", {}).values():
            for stage in stage_data.values():
                for cluster in stage.get("clusters", []):
                    fps.add(cluster.get("fingerprint", ""))
        fingerprint_sets.append(fps)

    if not fingerprint_sets:
        return []

    # Count how many instances share each fingerprint
    counter: Counter = Counter()
    for fps in fingerprint_sets:
        for fp in fps:
            if fp:
                counter[fp] += 1

    threshold = max(1, math.ceil(len(analyses) * 0.5))
    return [fp for fp, cnt in counter.most_common(10) if cnt >= threshold]


def _build_instance_row(inst_id: str, analysis: dict) -> dict:
    """Compact summary row for the comparison matrix."""
    metrics = analysis.get("metrics", {})
    ec2_d   = analysis.get("ec2", {})
    sc      = ec2_d.get("status_checks", {})

    def _fmt(v):
        return f"{v:.1f}" if v is not None else "n/a"

    return {
        "instance_id":     inst_id,
        "health":          "healthy" if _is_healthy(analysis) else "unhealthy",
        "target_health":   analysis.get("target_health", "unknown"),
        "target_reason":   analysis.get("target_reason", ""),
        "cpu":             _fmt(metrics.get("cpu_percent")),
        "status_check":    sc.get("instance_status", "unknown"),
        "system_check":    sc.get("system_status", "unknown"),
        "error_count":     analysis.get("total_error_count", 0),
        "top_errors":      analysis.get("top_errors", [])[:3],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Main entry point
# ═══════════════════════════════════════════════════════════════════════════════

def correlate_instances(
    instance_analyses: dict,       # {instance_id: analysis_dict}
    alb_meta: dict,                # from dependency_resolver
) -> dict:
    """
    Produce a cross-instance correlation summary.

    instance_analyses:
        {
            "i-1": {
                "ec2":               {...},
                "metrics":           {...},
                "log_summary":       {...},   # from log_processor
                "top_errors":        [...],
                "total_error_count": int,
                "target_health":     str,
                "target_reason":     str,
            },
            ...
        }

    Returns:
        {
            "scenario":              "A" | "B" | "C" | "D",
            "scenario_description":  str,
            "primary_suspect":       str | None,
            "healthy_count":         int,
            "unhealthy_count":       int,
            "comparison_matrix":     [...],
            "common_errors":         [...],
            "isolated_errors":       {instance_id: [...]},
            "alb_summary":           {...},
        }
    """
    if not instance_analyses:
        return {"scenario": "unknown", "scenario_description": "No instance data"}

    ids             = list(instance_analyses.keys())
    healthy_ids     = [i for i in ids if _is_healthy(instance_analyses[i])]
    unhealthy_ids   = [i for i in ids if not _is_healthy(instance_analyses[i])]
    healthy_count   = len(healthy_ids)
    unhealthy_count = len(unhealthy_ids)
    total           = len(ids)

    # ── Scenario detection ──────────────────────────────────────────────────
    if alb_meta and unhealthy_count == 0 and alb_meta.get("unhealthy", 0) > 0:
        scenario = "C"
        desc = (
            "All EC2 instances appear healthy but ALB target health check is failing. "
            "Root cause is likely a load-balancer misconfiguration or health-check mismatch."
        )
    elif unhealthy_count == 0:
        scenario = "C"
        desc = "All instances appear healthy. Issue may be transient or at the load-balancer layer."
    elif unhealthy_count == total:
        scenario = "B"
        desc = (
            f"All {total} instance(s) are failing. "
            "Likely a shared dependency outage (database, cache, external API, VPC issue)."
        )
    elif unhealthy_count == 1:
        scenario = "A"
        desc = (
            f"Single instance {unhealthy_ids[0]} is failing while "
            f"{healthy_count} other(s) are healthy. Isolated host or application failure."
        )
    else:
        scenario = "D"
        desc = (
            f"{unhealthy_count}/{total} instances failing. "
            "Partial degradation — rolling failure, canary regression, or AZ-specific issue."
        )

    # ── Primary suspect ─────────────────────────────────────────────────────
    # Highest error count among unhealthy, or first unhealthy if tied
    primary_suspect = None
    if unhealthy_ids:
        primary_suspect = max(
            unhealthy_ids,
            key=lambda i: instance_analyses[i].get("total_error_count", 0),
        )

    # ── Comparison matrix (compact per-instance rows) ───────────────────────
    matrix = [
        _build_instance_row(iid, instance_analyses[iid])
        for iid in ids
    ]
    # Sort: unhealthy first, then by error count desc
    matrix.sort(key=lambda r: (r["health"] == "healthy", -r["error_count"]))

    # ── Error distribution ───────────────────────────────────────────────────
    all_analyses = list(instance_analyses.values())
    common_errors = _extract_common_errors(all_analyses)

    isolated_errors: dict = {}
    for iid, analysis in instance_analyses.items():
        errors = [
            e for e in analysis.get("top_errors", [])
            if e not in common_errors
        ]
        if errors:
            isolated_errors[iid] = errors[:5]

    # ── ALB summary (compact) ────────────────────────────────────────────────
    alb_summary = {}
    if alb_meta:
        alb_summary = {
            "dns":             alb_meta.get("alb_dns"),
            "total_targets":   alb_meta.get("total"),
            "healthy_targets": alb_meta.get("healthy"),
            "unhealthy_targets": alb_meta.get("unhealthy"),
        }

    result = {
        "scenario":             scenario,
        "scenario_description": desc,
        "primary_suspect":      primary_suspect,
        "healthy_count":        healthy_count,
        "unhealthy_count":      unhealthy_count,
        "total_count":          total,
        "comparison_matrix":    matrix,
        "common_errors":        common_errors,
        "isolated_errors":      isolated_errors,
        "alb_summary":          alb_summary,
    }

    logger.info(
        f"[Correlation] Scenario {scenario} | "
        f"unhealthy={unhealthy_count}/{total} | "
        f"primary_suspect={primary_suspect}"
    )
    return result
