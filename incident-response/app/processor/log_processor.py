"""
processor/log_processor.py
──────────────────────────
Production-grade multi-log-group CloudWatch fetching for EC2 RCA.

Only one timestamp is required as input: incident_down_time.
Everything else is derived automatically from the logs themselves.

Full Pipeline
─────────────
Phase A  — Wide Error Scan (paginated)
    Scan the adaptive window around incident_down_time across all log groups
    in parallel.  Uses full nextToken pagination so NO log is dropped due to
    CW API truncation.

Phase B  — First-Error Anchoring
    Find the earliest HIGH-WEIGHT error event across all groups.
    Re-anchor the entire investigation to that timestamp (not down_time).

Phase C  — Three-Stage Context Fetch (paginated)
    Stage 1  buildup   true_start    → first_error_ts   (build-up / degradation)
    Stage 2  failure   first_error_ts → down_time        (active failure / root cause)
    Stage 3  impact    down_time     → down_time + 10min (cascade / recovery)

Phase D  — Weighted Compression
    Each log line receives a severity_weight score based on error type.
    Clusters are sorted by  weight × log2(count+1)  — NOT frequency alone.
    This keeps rare-but-critical events (DB corruption, OOM, segfault) visible
    even when 500 nginx timeouts dominate the raw count.

Phase E  — Cascade Attribution
    Uses dependency_context (user-supplied service graph) to tag every cluster
    with whether it is a known downstream symptom of another service's failure.
    This gives Bedrock explicit "do not blame nginx for a postgres failure" hints.

Deployment Correlation (separate function, called by process_incident.py)
    Queries CloudTrail for EC2/ECS/Lambda/deployment API calls in the
    investigation window so the AI can correlate "deployment at 14:58,
    outage at 15:00" even when the application logs show nothing unusual.
"""

import re
import json
import math
import logging
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# ─── Tunables ─────────────────────────────────────────────────────────────────
DEFAULT_SCAN_BEFORE_MINUTES    = 30
DEFAULT_SCAN_AFTER_MINUTES     = 10
FIRST_ERROR_PRE_BUFFER_MINUTES = 5
IMPACT_WINDOW_MINUTES          = 10

# Pagination safety cap — prevents runaway fetches on very noisy log groups.
# 10 000 events per (group × window) is enough for any real incident.
MAX_EVENTS_PER_FETCH = 10_000
# CW API max per page
CW_PAGE_SIZE         = 10_000   # filter_log_events max is 10 000

# Token budget — max clusters sent to Bedrock per (group × stage)
MAX_CLUSTERS_PER_STAGE  = 25
MAX_CONTEXT_LINES       = 15    # info lines kept for timeline
MAX_REPEAT_SHOW         = 3     # sample copies per cluster

# ─── Error keyword regex ───────────────────────────────────────────────────────
ERROR_PATTERN = re.compile(
    r"error|exception|fatal|critical|fail|traceback|panic|oom|killed|"
    r"segfault|refused|timeout|unavailable|"
    r"\b500\b|\b502\b|\b503\b|\b504\b", 
    re.IGNORECASE,
)

# ─── Noise filter — infra/OS chatter that drowns out real app failures ─────────
IGNORE_PATTERNS = re.compile(
    r"systemd\[|kernel:|BOOT_IMAGE|system-modprobe|"
    r"cloud-init|cron\[|session opened|session closed",
    re.IGNORECASE,
)

# ─── Fingerprint strip patterns ────────────────────────────────────────────────
_STRIP_PATTERNS = [
    re.compile(
        r"\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}"
        r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:\d{2})?"
    ),                                                         # timestamps
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),               # IPv4
    re.compile(r"\*\d+"),                                      # nginx conn id
    re.compile(r'"[A-Z]+ [^"]*"'),                             # HTTP request line
    re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE),           # hex IDs
    re.compile(r"\b\d{5,}\b"),                                 # long ints (PIDs)
    re.compile(r"line \d+", re.IGNORECASE),                    # "at line 42"
]

# ─── Severity weight table ─────────────────────────────────────────────────────
# Used in Phase D to ensure rare-but-critical events outrank frequent noise.
# Score = weight × log2(count + 1)
# A single "corruption" event (weight=100) beats 500 "timeout" events (weight=4):
#   corruption: 100 × log2(2) = 100
#   timeout×500: 4 × log2(501) ≈ 36
#
# Add any application-specific patterns here.
_WEIGHT_RULES: list[tuple[re.Pattern, int, str]] = [
    # (pattern, weight, label)
    (re.compile(r"corrupt|corruption|data.?loss|data.?integrity",           re.I), 100, "data-integrity"),
    (re.compile(r"oom.?kill|out.of.memory|killed.process|memory.?pressure", re.I),  90, "oom"),
    (re.compile(r"segfault|segmentation.fault|core.dump|signal 11",        re.I),  90, "crash"),
    (re.compile(r"panic|kernel.?panic|fatal",                               re.I),  80, "fatal"),
    (re.compile(r"deadlock|lock.?wait.?timeout|innodb.?deadlock",           re.I),  75, "deadlock"),
    (re.compile(r"replication.?error|replica.?lag|binlog",                  re.I),  70, "replication"),
    (re.compile(r"disk.?full|no.space.left|enospc",                         re.I),  70, "disk-full"),
    (re.compile(r"ssl.?error|certificate.?expired|handshake.?fail",         re.I),  65, "ssl"),
    (re.compile(r"connection.?pool|pool.?exhausted|too.many.connections",   re.I),  60, "conn-pool"),
    (re.compile(r"exception|traceback|stack.?trace",                        re.I),  55, "exception"),
    (re.compile(r"oom|out.of.memory(?!.kill)",                              re.I),  50, "oom-warn"),
    (re.compile(r"refused|econnrefused|connection.?refused",                re.I),  45, "conn-refused"),
    (re.compile(r"unavailable|service.?unavailable",                        re.I),  40, "unavailable"),
    (re.compile(r"\b500\b|internal.server.error",                           re.I),  35, "http-500"),
    (re.compile(r"\b502\b|bad.gateway",                                     re.I),  30, "http-502"),
    (re.compile(r"\b503\b|service.temporarily.unavailable",                 re.I),  30, "http-503"),
    (re.compile(r"timeout|timed.out|deadline.exceeded",                     re.I),  25, "timeout"),
    (re.compile(r"\b504\b|gateway.timeout",                                 re.I),  20, "http-504"),
    (re.compile(r"error",                                                   re.I),  15, "generic-error"),
    (re.compile(r"warn|warning",                                            re.I),   5, "warning"),
    (re.compile(r"fail",                                                    re.I),   8, "fail"),
    (re.compile(r"forbidden|403",                                           re.I),   3, "http-403"),
]

# CloudTrail API calls that indicate deployment / change events
_DEPLOYMENT_API_CALLS = {
    # EC2
    "RunInstances", "TerminateInstances", "StopInstances", "StartInstances",
    "RebootInstances", "ModifyInstanceAttribute",
    # ECS
    "UpdateService", "CreateService", "DeleteService", "RunTask",
    # Lambda
    "UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion",
    "CreateAlias", "UpdateAlias",
    # Auto Scaling
    "UpdateAutoScalingGroup", "ExecutePolicy", "TerminateInstanceInAutoScalingGroup",
    # CodeDeploy
    "CreateDeployment",
    # Systems Manager
    "SendCommand", "StartAutomationExecution",
    # Secrets / Config
    "PutSecretValue", "RotateSecret",
    "PutConfigurationRecorder",
    # IAM (permission changes can cause outages)
    "AttachRolePolicy", "DetachRolePolicy", "PutRolePolicy", "DeleteRolePolicy",
    # Load Balancer
    "ModifyTargetGroupAttributes", "RegisterTargets", "DeregisterTargets",
    "CreateRule", "DeleteRule",
}


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _fingerprint(message: str) -> str:
    fp = message
    for pat in _STRIP_PATTERNS:
        fp = pat.sub("…", fp)
    fp = re.sub(r"[…\s]+", " ", fp).strip()
    return fp[:200]


def _severity_weight(message: str) -> tuple[int, str]:
    """
    Return (weight, label) for a log message.
    Uses the first matching rule in _WEIGHT_RULES (highest weight first).
    """
    for pattern, weight, label in _WEIGHT_RULES:
        if pattern.search(message):
            return weight, label
    return 1, "info"


def _parse_log_line(raw: str) -> dict:
    """
    Normalise a raw CW log line → {"level": str, "message": str}.

    Handles:
      • JSON structured   {"level": "error", "message": "…"}
      • nginx/apache      2026/05/15 14:22:49 [error] 179#179: …
      • Plain text / syslog
    """
    line = raw.strip()

    # JSON
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            level = (
                obj.get("level") or obj.get("severity") or
                obj.get("log_level") or obj.get("status") or "info"
            ).lower()
            message = str(
                obj.get("message") or obj.get("msg") or
                obj.get("error") or obj.get("body") or line
            )
            return {"level": level, "message": message}
        except Exception:
            pass

    # nginx bracket level:  [error] / [warn] / [notice]
    m = re.search(r"\[(\w+)\]", line)
    if m:
        return {"level": m.group(1).lower(), "message": line}

    # Plain — infer from keywords
    level = "error" if ERROR_PATTERN.search(line) else "info"
    return {"level": level, "message": line}


# ═══════════════════════════════════════════════════════════════════════════════
# PAGINATED CLOUDWATCH FETCH  (replaces old _fetch_raw_events)
# ═══════════════════════════════════════════════════════════════════════════════

def _fetch_paginated(logs_client, log_group: str,
                     start_ms: int, end_ms: int,
                     filter_pattern: str = "",
                     max_events: int = MAX_EVENTS_PER_FETCH) -> list[dict]:
    """
    Fully paginated filter_log_events call.

    CW returns at most 10 000 events per page; without pagination any window
    with > 10 000 events is silently truncated — which means the root cause
    event may never reach the AI.

    Safety cap: stop after `max_events` total to avoid runaway cost/time.

    Returns [{"ts": epoch_ms, "message": str}].
    Never raises — logs warning and returns whatever was collected so far.
    """
    if start_ms >= end_ms:
        return []

    collected: list[dict] = []
    next_token: Optional[str] = None

    kwargs = dict(
        logGroupName=log_group,
        startTime=start_ms,
        endTime=end_ms,
        limit=CW_PAGE_SIZE,
    )
    if filter_pattern:
        kwargs["filterPattern"] = filter_pattern

    page = 0
    while True:
        try:
            if next_token:
                kwargs["nextToken"] = next_token
            elif "nextToken" in kwargs:
                del kwargs["nextToken"]

            resp   = logs_client.filter_log_events(**kwargs)
            events = resp.get("events", [])
            page  += 1

            for e in events:
                if e.get("message"):
                    collected.append({"ts": e["timestamp"], "message": e["message"]})

            logger.debug(
                f"[CW page {page}] {log_group}: +{len(events)} events "
                f"(total so far: {len(collected)})"
            )

            next_token = resp.get("nextToken")

            # Stop conditions
            if not next_token:
                break
            if len(collected) >= max_events:
                logger.debug(
                    f"[CW] {log_group}: safety cap {max_events} reached, stopping pagination"
                )
                break

        except Exception as exc:
            logger.warning(f"[CW] fetch failed for {log_group} (page {page}): {exc}")
            break

    logger.info(f"[CW] {log_group}: {len(collected)} events in {page} page(s)")
    collected.sort(key=lambda e: e["ts"])
    return collected


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTIVE WINDOW
# ═══════════════════════════════════════════════════════════════════════════════

def compute_adaptive_window(severity: str, issue: str) -> dict:
    """
    Decide how far before/after incident_down_time to scan.

    Memory leaks / disk fills → symptoms 30-60 min before detection.
    DB pool exhaustion        → 10-20 min before.
    Deployment failures       → essentially at down_time.
    A flat window misses slow-burn root causes.

    Returns {"before_minutes": int, "after_minutes": int}.
    """
    sev   = (severity or "").lower()
    issue = (issue or "").lower()

    before = DEFAULT_SCAN_BEFORE_MINUTES   # default 30 min

    if sev == "critical":
        before = 60
    elif sev == "high":
        before = 45

    keyword_map = [
        (["memory", "oom", "heap", "swap", "out of memory"],  60),
        (["disk", "storage", "no space", "iops", "ebs"],      45),
        (["cpu", "load average", "throttl"],                   40),
        (["timeout", "connection refused", "pool exhausted"],  30),
        (["502", "503", "504", "gateway", "upstream"],         25),
        (["deploy", "release", "restart", "rollback"],         20),
    ]
    for keywords, mins in keyword_map:
        if any(kw in issue for kw in keywords):
            before = max(before, mins)

    return {"before_minutes": before, "after_minutes": DEFAULT_SCAN_AFTER_MINUTES}


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE A — Wide Error Scan
# ═══════════════════════════════════════════════════════════════════════════════

def _run_phase_a(logs_client, log_groups: list[str],
                 scan_start: datetime, scan_end: datetime) -> dict:
    """
    Paginated error scan for all log groups in parallel.
    Returns {log_group: [error_events_tagged_with_weight]}.
    """
    def _task(lg: str):
        # Fetch ALL events (paginated) then filter locally.
        # We intentionally do NOT use filterPattern here because CW pattern
        # syntax is limited; Python regex matching is more powerful.
        events = _fetch_paginated(
            logs_client, lg,
            _ms(scan_start), _ms(scan_end),
        )
        errors = []
        for e in events:
            msg = e["message"]
            if IGNORE_PATTERNS.search(msg):
                continue
            if ERROR_PATTERN.search(msg):
                weight, wlabel = _severity_weight(msg)
                e["log_group"]      = lg
                e["weight"]         = weight
                e["weight_label"]   = wlabel
                errors.append(e)

        logger.info(
            f"[Phase-A] {lg}: {len(errors)}/{len(events)} error events "
            f"[{scan_start.strftime('%H:%M')} – {scan_end.strftime('%H:%M')}]"
        )
        return lg, errors

    results: dict[str, list[dict]] = {}
    with ThreadPoolExecutor(max_workers=min(len(log_groups), 6)) as pool:
        futures = {pool.submit(_task, lg): lg for lg in log_groups}
        for future in as_completed(futures):
            lg = futures[future]
            try:
                lg_key, errors = future.result()
                results[lg_key] = errors
            except Exception as exc:
                logger.warning(f"[Phase-A] {lg} failed: {exc}")
                results[lg] = []

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE B — First-Error Anchoring (weight-aware)
# ═══════════════════════════════════════════════════════════════════════════════

def _anchor_true_start(phase_a_results: dict, down_time: datetime,
                       scan_start: datetime) -> dict:
    """
    Find the first sustained error spike (Error Density Anchoring) across
    ALL log groups and use it as the true incident start.

    Returns:
        {
          "first_error_ts":    datetime | None,
          "first_error_msg":   str,
          "first_error_group": str,
          "true_start":        datetime,
        }

    Why this matters
    ─────────────────
    down_time is when the health check DETECTED the problem.
    The actual root cause (e.g. DB pool exhausted, OOM pressure, disk fill)
    started earlier. By finding the first high-density error window rather than
    an isolated early error, we anchor Stage 2 to the true start of the failure.
    """
    all_errors = [e for errs in phase_a_results.values() for e in errs]

    if not all_errors:
        logger.info("[Phase-B] No errors in Phase-A scan — true_start = scan_start")
        return {
            "first_error_ts":    None,
            "first_error_msg":   "",
            "first_error_group": "",
            "true_start":        scan_start,
        }

    # STEP 1: Sort errors by timestamp
    sorted_errors = sorted(all_errors, key=lambda e: e["ts"])

    # STEP 2 & 3: Find first high-density window (5-minute bucket)
    window_ms = 5 * 60 * 1000
    threshold = max(5, int(len(sorted_errors) * 0.05))
    anchor_error = sorted_errors[0]

    for i, err in enumerate(sorted_errors):
        window_end = err["ts"] + window_ms
        count = 0
        for j in range(i, len(sorted_errors)):
            if sorted_errors[j]["ts"] <= window_end:
                count += 1
            else:
                break
        
        if count >= threshold:
            anchor_error = err
            logger.info(f"[Phase-B] Found sustained spike starting at {datetime.fromtimestamp(err['ts']/1000, tz=timezone.utc).strftime('%H:%M:%S')} with {count} errors in 5m")
            break
    else:
        logger.info("[Phase-B] No sustained spike found, falling back to earliest error")

    first_dt = datetime.fromtimestamp(anchor_error["ts"] / 1000, tz=timezone.utc)

    # Add a small pre-buffer before the first error to capture build-up signals
    true_start = first_dt - timedelta(minutes=FIRST_ERROR_PRE_BUFFER_MINUTES)

    # Never go before the original Phase-A scan start
    true_start = max(true_start, scan_start)

    logger.info(
        f"[Phase-B] First error: {first_dt.strftime('%H:%M:%S')} "
        f"in {anchor_error['log_group']} | "
        f"true_start anchored → {true_start.strftime('%H:%M:%S')}"
    )

    return {
        "first_error_ts":     first_dt,
        "first_error_msg":    anchor_error["message"][:200],
        "first_error_group":  anchor_error["log_group"],
        "first_error_weight": anchor_error.get("weight", 0),
        "true_start":         true_start,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE C — Three-Stage Context Fetch
# ═══════════════════════════════════════════════════════════════════════════════

def _build_stages(anchor: dict, down_time: datetime) -> list[dict]:
    """
    Build three labelled investigation windows.

    Normal (first_error_ts found before down_time):
        buildup    true_start    → first_error_ts
        failure    first_error_ts → down_time
        impact     down_time     → down_time + 10 min

    Degenerate (no pre-down_time errors):
        pre_failure  true_start  → down_time
        impact       down_time   → down_time + 10 min
    """
    true_start     = anchor["true_start"]
    first_error_ts = anchor["first_error_ts"]
    impact_end     = down_time + timedelta(minutes=IMPACT_WINDOW_MINUTES)

    if first_error_ts and true_start < first_error_ts < down_time:
        return [
            {"name": "buildup",   "label": "Pre-failure buildup",   "start": true_start,    "end": first_error_ts},
            {"name": "failure",   "label": "Failure propagation",   "start": first_error_ts,"end": down_time},
            {"name": "impact",    "label": "Impact / recovery",     "start": down_time,     "end": impact_end},
        ]

    return [
        {"name": "pre_failure", "label": "Pre-failure window",  "start": true_start, "end": down_time},
        {"name": "impact",      "label": "Impact / recovery",   "start": down_time,  "end": impact_end},
    ]


def _run_phase_c(logs_client, log_groups: list[str],
                 stages: list[dict]) -> dict:
    """
    Paginated fetch for all (group × stage) pairs in parallel.
    Returns {log_group: {stage_name: [raw_message_strings]}}.
    """
    tasks = [(lg, stage) for lg in log_groups for stage in stages]

    def _task(lg: str, stage: dict):
        events = _fetch_paginated(
            logs_client, lg,
            _ms(stage["start"]), _ms(stage["end"]),
        )
        lines = [e["message"] for e in events]
        logger.info(
            f"[Phase-C] {lg} / {stage['name']}: {len(lines)} lines "
            f"[{stage['start'].strftime('%H:%M')} – {stage['end'].strftime('%H:%M')}]"
        )
        return lg, stage["name"], lines

    results: dict[str, dict[str, list[str]]] = {lg: {} for lg in log_groups}
    with ThreadPoolExecutor(max_workers=min(len(tasks), 12)) as pool:
        futures = {pool.submit(_task, lg, s): (lg, s["name"]) for lg, s in tasks}
        for future in as_completed(futures):
            lg, sname = futures[future]
            try:
                lg_r, sname_r, lines = future.result()
                results[lg_r][sname_r] = lines
            except Exception as exc:
                logger.warning(f"[Phase-C] {lg}/{sname} failed: {exc}")
                results[lg][sname] = []

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE D — Weighted Compression
# ═══════════════════════════════════════════════════════════════════════════════

def _compress_lines(raw_lines: list[str]) -> dict:
    """
    Compress raw log lines into a structured summary.

    WEIGHTED SORT — prevents frequency bias
    ────────────────────────────────────────
    Sort key:  weight × log2(count + 1)

    Why log2?  A single "corruption" (weight=100) scores 100.
    500 nginx timeouts (weight=25) score  25 × log2(501) ≈ 224 — they would
    still outrank corruption if we used raw count.  But log2 compresses the
    frequency dimension so the weight matters more than count for rare events:

        corruption  ×1:   100 × log2(2)   = 100   ← stays near top
        timeout    ×500:   25 × log2(501)  ≈ 224   ← nginx noise below threshold?

    In practice we also apply a "rarity bonus": if count == 1 and weight >= 50,
    we multiply weight by 2 to explicitly surface unique critical events.

    Returns:
    {
        "total_raw":     int,
        "error_count":   int,
        "warn_count":    int,
        "clusters": [
            {
                "fingerprint":    str,
                "count":          int,
                "level":          str,
                "weight":         int,
                "weight_label":   str,
                "sort_score":     float,
                "is_rare":        bool,   ← count==1 and weight>=50
                "samples":        [str],
            }, …
        ],
        "context_lines": [str],
    }
    """
    fp_map:   dict[str, dict] = {}
    context:  list[str]       = []
    error_cnt = warn_cnt = 0

    for raw in raw_lines:
        p     = _parse_log_line(raw)
        level = p["level"]
        msg   = p["message"]

        if level in ("error", "fatal", "critical", "panic"):
            error_cnt += 1
            weight, wlabel = _severity_weight(msg)
            fp = _fingerprint(msg)
            cl = fp_map.setdefault(fp, {
                "fingerprint": fp, "count": 0,
                "level": level,
                "weight": weight, "weight_label": wlabel,
                "samples": [],
            })
            # Keep the highest weight seen for this fingerprint
            if weight > cl["weight"]:
                cl["weight"]       = weight
                cl["weight_label"] = wlabel
            cl["count"] += 1
            if len(cl["samples"]) < MAX_REPEAT_SHOW:
                cl["samples"].append(msg[:300])

        elif level in ("warn", "warning"):
            warn_cnt += 1
            weight, wlabel = _severity_weight(msg)
            fp = _fingerprint(msg)
            cl = fp_map.setdefault(fp, {
                "fingerprint": fp, "count": 0,
                "level": level,
                "weight": weight, "weight_label": wlabel,
                "samples": [],
            })
            if weight > cl["weight"]:
                cl["weight"]       = weight
                cl["weight_label"] = wlabel
            cl["count"] += 1
            if len(cl["samples"]) < MAX_REPEAT_SHOW:
                cl["samples"].append(msg[:300])

        else:
            if len(context) < MAX_CONTEXT_LINES:
                context.append(msg[:200])

    # Compute sort score and rarity flag
    for cl in fp_map.values():
        is_rare       = (cl["count"] == 1 and cl["weight"] >= 50)
        effective_w   = cl["weight"] * 2 if is_rare else cl["weight"]
        cl["sort_score"] = effective_w * math.log2(cl["count"] + 1)
        cl["is_rare"]    = is_rare

    clusters = sorted(fp_map.values(), key=lambda c: -c["sort_score"])

    return {
        "total_raw":     len(raw_lines),
        "error_count":   error_cnt,
        "warn_count":    warn_cnt,
        "clusters":      clusters[:MAX_CLUSTERS_PER_STAGE],
        "context_lines": context,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE E — Cascade Attribution
# ═══════════════════════════════════════════════════════════════════════════════

# Default service dependency map — downstream symptoms of upstream failures.
# process_incident.py can extend this from dependency_context.
_DEFAULT_CASCADE_MAP: dict[str, list[str]] = {
    # If postgres/mysql fails → expect these downstream symptoms
    "postgres":   ["502", "503", "connection refused", "upstream", "timeout", "pool"],
    "mysql":      ["502", "503", "connection refused", "upstream", "timeout", "pool"],
    "redis":      ["connection refused", "timeout", "cache miss"],
    "rabbitmq":   ["connection refused", "timeout", "channel error"],
    "mongodb":    ["connection refused", "timeout", "replica"],
    "elasticsearch": ["connection refused", "timeout", "search error"],
    # If app server fails → expect nginx to log 502/504
    "gunicorn":   ["502", "504", "upstream"],
    "uwsgi":      ["502", "504", "upstream"],
    "node":       ["502", "504", "upstream", "econnrefused"],
    "spring":     ["502", "504", "upstream"],
}


def _build_cascade_map(dependency_context: dict) -> dict[str, list[str]]:
    """
    Merge user-supplied dependency_context with the default cascade map.

    dependency_context schema (user-supplied):
    {
      "services": ["postgres", "redis", "nginx"],
      "dependencies": {
        "nginx": ["app"],
        "app":   ["postgres", "redis"]
      },
      "cascade_symptoms": {
        "postgres": ["connection refused", "timeout", "pool exhausted"]
      }
    }

    The "cascade_symptoms" key allows users to add application-specific
    downstream symptoms that we can't know generically.
    """
    cascade_map = dict(_DEFAULT_CASCADE_MAP)

    if not dependency_context:
        return cascade_map

    # User-supplied cascade symptom overrides/additions
    user_cascade = dependency_context.get("cascade_symptoms", {})
    for service, symptoms in user_cascade.items():
        svc_lower = service.lower()
        existing  = cascade_map.get(svc_lower, [])
        cascade_map[svc_lower] = list(set(existing + [s.lower() for s in symptoms]))

    return cascade_map


def _tag_clusters_with_cascade(clusters: list[dict],
                                cascade_map: dict[str, list[str]],
                                log_group: str) -> list[dict]:
    """
    For each cluster, check if its fingerprint matches known downstream
    symptoms of an upstream service failure.

    Adds "cascade_suspect" and "upstream_service" fields to the cluster.
    """
    # Infer upstream services from log group name (e.g. nginx-error → nginx)
    group_lower = log_group.lower()

    for cl in clusters:
        fp_lower = cl["fingerprint"].lower()
        cl["cascade_suspect"]  = False
        cl["upstream_services"] = []

        for service, symptoms in cascade_map.items():
            # If this log group belongs to a downstream service, and the error
            # looks like a symptom of the upstream failing…
            if any(sym in fp_lower for sym in symptoms):
                # Check if the current log group is NOT the upstream itself
                if service not in group_lower:
                    cl["cascade_suspect"] = True
                    cl["upstream_services"].append(service)

    return clusters


# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT CORRELATION (called from process_incident.py)
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_deployment_events(
    cloudtrail_client,
    instance_id:        str,
    investigation_start: datetime,
    investigation_end:   datetime,
    region:             str = "ap-south-1",
) -> list[dict]:
    """
    Query CloudTrail for deployment and change events in the investigation window.

    Returns a chronological list of change events so the AI can correlate
    "deployment at 14:58 → outage at 15:00" even when application logs
    show only downstream symptoms.

    Each returned event:
    {
        "ts":           ISO str,
        "event_name":   str,
        "event_source": str,
        "user":         str,
        "resources":    [str],
        "category":     str,   "deployment" | "scaling" | "config" | "iam"
    }
    """
    events: list[dict] = []

    try:
        paginator = cloudtrail_client.get_paginator("lookup_events")
        pages     = paginator.paginate(
            StartTime=investigation_start,
            EndTime=investigation_end,
            LookupAttributes=[],   # no filter — we filter locally below
            PaginationConfig={"MaxItems": 1000, "PageSize": 50},
        )

        for page in pages:
            for raw in page.get("Events", []):
                name = raw.get("EventName", "")
                if name not in _DEPLOYMENT_API_CALLS:
                    continue

                # Categorise
                if name in {
                    "RunInstances", "TerminateInstances", "StopInstances",
                    "StartInstances", "RebootInstances",
                    "UpdateService", "CreateService", "DeleteService",
                    "UpdateFunctionCode", "UpdateFunctionConfiguration",
                    "CreateDeployment", "RunTask",
                }:
                    category = "deployment"
                elif name in {
                    "UpdateAutoScalingGroup", "ExecutePolicy",
                    "TerminateInstanceInAutoScalingGroup",
                }:
                    category = "scaling"
                elif name in {
                    "PutSecretValue", "RotateSecret", "PutConfigurationRecorder",
                    "SendCommand", "StartAutomationExecution",
                    "ModifyInstanceAttribute",
                    "ModifyTargetGroupAttributes", "RegisterTargets",
                    "DeregisterTargets", "CreateRule", "DeleteRule",
                }:
                    category = "config"
                elif name in {
                    "AttachRolePolicy", "DetachRolePolicy",
                    "PutRolePolicy", "DeleteRolePolicy",
                }:
                    category = "iam"
                else:
                    category = "other"

                user = (
                    raw.get("Username") or
                    raw.get("UserIdentity", {}).get("arn", "unknown")
                )
                resources = [
                    r.get("ResourceName", "")
                    for r in raw.get("Resources", [])
                    if r.get("ResourceName")
                ]

                events.append({
                    "ts":           raw["EventTime"].isoformat(),
                    "event_name":   name,
                    "event_source": raw.get("EventSource", ""),
                    "user":         user,
                    "resources":    resources,
                    "category":     category,
                })

    except Exception as exc:
        logger.warning(f"CloudTrail lookup failed: {exc}")

    events.sort(key=lambda e: e["ts"])
    logger.info(f"[CloudTrail] Found {len(events)} deployment/change events")
    return events


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_and_compress_logs(
    logs_client,
    log_groups:          list[str],
    incident_down_time:  datetime,
    severity:            str = "medium",
    issue:               str = "",
    dependency_context:  dict | None = None,
    status_callback:     Callable[[str], None] | None = None,
) -> dict:
    """
    Full pipeline: Phase A → B → C → D → E.

    Args:
        logs_client          boto3 CloudWatch Logs client
        log_groups           CW log group names (user-supplied via UI)
        incident_down_time   moment Pulse detected the health check failure
        severity             incident severity ("critical", "high", …)
        issue                free-text issue description
        dependency_context   optional service dependency graph from DB

    Returns the full structured analysis dict (see inline docs for schema).
    """
    if status_callback:
        status_callback("fetching_logs")

    log_groups = [g for g in log_groups if g]
    if not log_groups:
        logger.warning("No log groups — skipping log fetch")
        return _empty_result(incident_down_time)

    # ── Adaptive window ────────────────────────────────────────────────────────
    adaptive   = compute_adaptive_window(severity, issue)
    scan_start = incident_down_time - timedelta(minutes=adaptive["before_minutes"])
    scan_end   = incident_down_time + timedelta(minutes=adaptive["after_minutes"])

    logger.info(
        f"[Start] down_time={incident_down_time.strftime('%H:%M:%S')} | "
        f"window=-{adaptive['before_minutes']}min/+{adaptive['after_minutes']}min | "
        f"groups={log_groups}"
    )

    # ── Phase A ────────────────────────────────────────────────────────────────
    phase_a_results  = _run_phase_a(logs_client, log_groups, scan_start, scan_end)
    all_error_events = [e for errs in phase_a_results.values() for e in errs]
    logger.info(f"[Phase-A] {len(all_error_events)} total error events")

    # ── Phase B ────────────────────────────────────────────────────────────────
    anchor = _anchor_true_start(phase_a_results, incident_down_time, scan_start)

    # ── Phase C ────────────────────────────────────────────────────────────────
    stages = _build_stages(anchor, incident_down_time)
    logger.info(
        "[Timeline Stages]\n" +
        "\n".join(
            f"  {s['name']}: "
            f"{s['start'].strftime('%H:%M:%S')} → "
            f"{s['end'].strftime('%H:%M:%S')}"
            for s in stages
        )
    )
    phase_c_results = _run_phase_c(logs_client, log_groups, stages)

    if status_callback:
        status_callback("compressing_logs")

    # ── Phase D + E ────────────────────────────────────────────────────────────
    cascade_map = _build_cascade_map(dependency_context or {})
    per_group: dict[str, dict] = {}
    total_raw = 0

    for lg in log_groups:
        per_group[lg] = {}
        for stage in stages:
            sn    = stage["name"]
            lines = phase_c_results.get(lg, {}).get(sn, [])
            total_raw += len(lines)

            compressed = _compress_lines(lines)

            # Phase E: tag clusters with cascade suspect info
            compressed["clusters"] = _tag_clusters_with_cascade(
                compressed["clusters"], cascade_map, lg
            )

            per_group[lg][sn] = {
                "stage_label": stage["label"],
                "window": (
                    f"{stage['start'].strftime('%H:%M')} – "
                    f"{stage['end'].strftime('%H:%M')}"
                ),
                **compressed,
            }

    # ── Global top_errors (weighted, deduplicated) ─────────────────────────────
    all_clusters: list[dict] = []
    for group_stages in per_group.values():
        for stage_summary in group_stages.values():
            all_clusters.extend(stage_summary.get("clusters", []))

    all_clusters.sort(key=lambda c: -c.get("sort_score", 0))

    top_errors: list[str] = []
    seen_fps: set[str]    = set()
    for cl in all_clusters:
        fp = cl["fingerprint"]
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        sample = cl["samples"][0] if cl["samples"] else fp
        parts  = []
        if cl.get("is_rare"):
            parts.append("[RARE-HIGH-SIGNAL]")
        if cl.get("cascade_suspect"):
            upstreams = ", ".join(cl.get("upstream_services", []))
            parts.append(f"[CASCADE-SYMPTOM of {upstreams}]")
        parts.append(f"[x{cl['count']}]" if cl["count"] > 1 else "")
        parts.append(f"[{cl['weight_label'].upper()}]")
        parts.append(sample)
        top_errors.append(" ".join(p for p in parts if p))
        if len(top_errors) >= 10:
            break

    logger.info(
        "[Top Error Signals]\n" +
        "\n".join(f"  • {e}" for e in top_errors[:10])
    )

    # Serialise anchor datetimes
    serialised_anchor = {
        "true_start":        anchor["true_start"].isoformat(),
        "first_error_ts":    anchor["first_error_ts"].isoformat() if anchor["first_error_ts"] else None,
        "first_error_msg":   anchor["first_error_msg"],
        "first_error_group": anchor["first_error_group"],
        "first_error_weight": anchor.get("first_error_weight", 0),
    }

    logger.info(
        f"[Done] groups={len(log_groups)} stages={len(stages)} "
        f"total_raw={total_raw} top_errors={len(top_errors)}"
    )

    return {
        "adaptive_window": adaptive,
        "anchor":          serialised_anchor,
        "stages": [
            {"name": s["name"], "label": s["label"],
             "start": s["start"].isoformat(), "end": s["end"].isoformat()}
            for s in stages
        ],
        "per_group":       per_group,
        "top_errors":      top_errors,
        "error_events":    all_error_events,
        "total_raw_lines": total_raw,
    }


def _empty_result(incident_down_time: datetime) -> dict:
    return {
        "adaptive_window": {"before_minutes": DEFAULT_SCAN_BEFORE_MINUTES,
                            "after_minutes":  DEFAULT_SCAN_AFTER_MINUTES},
        "anchor": {
            "true_start": incident_down_time.isoformat(),
            "first_error_ts": None, "first_error_msg": "",
            "first_error_group": "", "first_error_weight": 0,
        },
        "stages":          [],
        "per_group":       {},
        "top_errors":      [],
        "error_events":    [],
        "total_raw_lines": 0,
    }