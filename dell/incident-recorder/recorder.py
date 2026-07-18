#!/usr/bin/env python3
import hmac
import json
import math
import os
import re
import signal
import sqlite3
import sys
import threading
import time
import traceback
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError as UrlHTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen


PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090").rstrip("/")
BLACKBOX_URL = os.getenv("BLACKBOX_URL", "http://192.168.66.108:9115").rstrip("/")
SQLITE_PATH = os.getenv("SQLITE_PATH", "/data/incidents.db")
INTERVAL_SECONDS = int(os.getenv("INTERVAL_SECONDS", "5"))
LOOKBACK_SECONDS = int(os.getenv("LOOKBACK_SECONDS", "60"))
QUERY_STEP_SECONDS = int(os.getenv("QUERY_STEP_SECONDS", "5"))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "6"))
DEBUG_TIMEOUT_SECONDS = float(os.getenv("DEBUG_TIMEOUT_SECONDS", "8"))
DEBUG_LOG_MAX_CHARS = int(os.getenv("DEBUG_LOG_MAX_CHARS", "60000"))
UTC_OFFSET_HOURS = int(os.getenv("UTC_OFFSET_HOURS", "8"))
ANALYZE_HTTP_HOST = os.getenv("ANALYZE_HTTP_HOST", "0.0.0.0")
ANALYZE_HTTP_PORT = int(os.getenv("ANALYZE_HTTP_PORT", "8088"))
REQUIRE_GRAFANA_AUTH = os.getenv("REQUIRE_GRAFANA_AUTH", "false").lower() in ("1", "true", "yes")
GRAFANA_AUTH_URL = os.getenv("GRAFANA_AUTH_URL", "http://grafana:3000/api/user")
GRAFANA_AUTH_TIMEOUT_SECONDS = float(os.getenv("GRAFANA_AUTH_TIMEOUT_SECONDS", "5"))
LLM_API_BASE_URL = os.getenv("LLM_API_BASE_URL", "https://api.deepseek.com").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-v4-pro")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "").strip()
LLM_HTTP_TIMEOUT_SECONDS = float(os.getenv("LLM_HTTP_TIMEOUT_SECONDS", "60"))
LLM_DEBUG_LOG_MAX_CHARS = int(os.getenv("LLM_DEBUG_LOG_MAX_CHARS", "16000"))
LLM_RAW_RESPONSE_MAX_CHARS = int(os.getenv("LLM_RAW_RESPONSE_MAX_CHARS", "120000"))
PI_INGEST_TOKEN = os.getenv("PI_INGEST_TOKEN", "").strip()
INGEST_MAX_BODY_CHARS = int(os.getenv("INGEST_MAX_BODY_CHARS", "500000"))

DEFAULT_MODULE_BY_JOB = {
    "blackbox_icmp": "icmp_v4",
    "blackbox_tcp": "tcp_443",
    "blackbox_http": "https_2xx_4xx",
    "blackbox_dns": "dns_a",
}

MODULE_BY_JOB = DEFAULT_MODULE_BY_JOB.copy()
if os.getenv("MODULE_BY_JOB_JSON"):
    MODULE_BY_JOB.update(json.loads(os.environ["MODULE_BY_JOB_JSON"]))

STOP = False
DB_LOCK = threading.RLock()
ANALYSIS_IN_FLIGHT = set()

INCIDENT_LLM_COLUMNS = (
    ("llm_status", "TEXT"),
    ("llm_requested_at", "TEXT"),
    ("llm_requested_at_epoch", "INTEGER"),
    ("llm_completed_at", "TEXT"),
    ("llm_completed_at_epoch", "INTEGER"),
    ("llm_model", "TEXT"),
    ("llm_summary", "TEXT"),
    ("llm_diagnosis", "TEXT"),
    ("llm_confidence", "TEXT"),
    ("llm_affected_scope", "TEXT"),
    ("llm_evidence", "TEXT"),
    ("llm_next_steps", "TEXT"),
    ("llm_uncertainties", "TEXT"),
    ("llm_error", "TEXT"),
    ("llm_raw_response", "TEXT"),
)

INCIDENT_DIAGNOSTIC_COLUMNS = (
    ("failure_layer", "TEXT"),
    ("failure_reason", "TEXT"),
    ("probe_metrics_json", "TEXT"),
    ("debug_source", "TEXT"),
    ("debug_fetched_at", "TEXT"),
    ("debug_fetched_at_epoch", "INTEGER"),
)

INCIDENT_SOURCE_COLUMNS = (
    ("source", "TEXT"),
    ("source_incident_id", "TEXT"),
    ("source_event_id", "TEXT"),
    ("source_sequence", "INTEGER"),
    ("batch_started_at", "TEXT"),
    ("batch_started_at_epoch", "INTEGER"),
    ("batch_window_seconds", "INTEGER"),
)


class ApiError(Exception):
    def __init__(self, status_code: int, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.details = details or {}


class LLMProviderError(Exception):
    def __init__(self, message: str, raw_response: str = ""):
        super().__init__(message)
        self.raw_response = raw_response


def request_stop(_signum, _frame):
    global STOP
    STOP = True


signal.signal(signal.SIGTERM, request_stop)
signal.signal(signal.SIGINT, request_stop)


def now_epoch() -> int:
    return int(time.time())


def format_ts(epoch: int) -> str:
    tz = timezone(timedelta(hours=UTC_OFFSET_HOURS))
    return datetime.fromtimestamp(epoch, tz).isoformat(timespec="seconds")


def truncate_text(value: Optional[str], max_chars: int) -> str:
    if not value:
        return ""
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n...<truncated>"


def json_response(status: str, **fields: Any) -> dict:
    return {"status": status, **fields}


def normalize_llm_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def target_name(target: str) -> str:
    parsed = urlparse(target)
    if parsed.hostname:
        return parsed.hostname
    return target


def target_key(job: str, target: str, module: str) -> str:
    return f"{job}|{target}|{module}"


def parse_event_epoch(payload: dict) -> int:
    if payload.get("event_epoch") is not None:
        try:
            return int(payload["event_epoch"])
        except (TypeError, ValueError):
            pass
    event_time = str(payload.get("event_time") or "")
    if event_time:
        try:
            return int(datetime.fromisoformat(event_time).timestamp())
        except ValueError:
            pass
    return now_epoch()


def event_id_from_payload(payload: dict) -> str:
    event_id = str(payload.get("event_id") or "").strip()
    if event_id:
        return event_id
    trigger = payload.get("trigger") or {}
    return "|".join(
        [
            str(payload.get("source") or ""),
            str(payload.get("incident_id") or ""),
            str(payload.get("event_type") or ""),
            str(payload.get("sequence") or ""),
            str(trigger.get("job") or ""),
            str(trigger.get("target") or ""),
            str(trigger.get("module") or ""),
        ]
    )


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          target_key TEXT NOT NULL,
          started_at TEXT NOT NULL,
          started_at_epoch INTEGER NOT NULL,
          recovered_at TEXT,
          recovered_at_epoch INTEGER,
          status TEXT NOT NULL CHECK(status IN ('down', 'recovered')),
          probe_layer TEXT NOT NULL,
          job TEXT NOT NULL,
          target TEXT NOT NULL,
          target_name TEXT NOT NULL,
          module TEXT NOT NULL,
          error_summary TEXT,
          debug_log TEXT,
          failure_layer TEXT,
          failure_reason TEXT,
          probe_metrics_json TEXT,
          debug_source TEXT,
          debug_fetched_at TEXT,
          debug_fetched_at_epoch INTEGER,
          duration_seconds INTEGER,
          llm_status TEXT,
          llm_requested_at TEXT,
          llm_requested_at_epoch INTEGER,
          llm_completed_at TEXT,
          llm_completed_at_epoch INTEGER,
          llm_model TEXT,
          llm_summary TEXT,
          llm_diagnosis TEXT,
          llm_confidence TEXT,
          llm_affected_scope TEXT,
          llm_evidence TEXT,
          llm_next_steps TEXT,
          llm_uncertainties TEXT,
          llm_error TEXT,
          llm_raw_response TEXT,
          source TEXT,
          source_incident_id TEXT,
          source_event_id TEXT,
          source_sequence INTEGER,
          batch_started_at TEXT,
          batch_started_at_epoch INTEGER,
          batch_window_seconds INTEGER,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
        """
    )
    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()
    }
    for column_name, column_type in INCIDENT_DIAGNOSTIC_COLUMNS + INCIDENT_LLM_COLUMNS + INCIDENT_SOURCE_COLUMNS:
        if column_name not in existing_columns:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {column_name} {column_type}")
    conn.execute("UPDATE incidents SET source='prometheus' WHERE source IS NULL OR source = ''")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS probe_targets (
          target_key TEXT PRIMARY KEY,
          probe_layer TEXT NOT NULL,
          job TEXT NOT NULL,
          target TEXT NOT NULL,
          target_name TEXT NOT NULL,
          module TEXT NOT NULL,
          last_success INTEGER,
          last_seen_at TEXT NOT NULL,
          last_seen_epoch INTEGER NOT NULL,
          updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_one_open
        ON incidents(target_key)
        WHERE status = 'down'
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incidents_started
        ON incidents(started_at_epoch DESC)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incidents_filter
        ON incidents(probe_layer, target, started_at_epoch DESC)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incidents_llm_status
        ON incidents(llm_status, started_at_epoch DESC)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incidents_source
        ON incidents(source, source_incident_id, started_at_epoch DESC)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_evidence (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id INTEGER NOT NULL,
          source TEXT NOT NULL,
          source_incident_id TEXT NOT NULL,
          source_event_id TEXT NOT NULL,
          event_type TEXT NOT NULL CHECK(event_type IN ('started', 'snapshot', 'recovered')),
          event_time TEXT NOT NULL,
          event_time_epoch INTEGER NOT NULL,
          sequence INTEGER NOT NULL,
          trigger_json TEXT NOT NULL,
          probe_results_json TEXT NOT NULL,
          evidence_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          created_at_epoch INTEGER NOT NULL,
          UNIQUE(source, source_event_id)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident
        ON incident_evidence(incident_id, event_time_epoch)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incident_evidence_source
        ON incident_evidence(source, source_incident_id, event_time_epoch)
        """
    )
    conn.commit()


def prometheus_query_range(query: str, start: int, end: int, step: int) -> Iterable[dict]:
    params = urlencode({"query": query, "start": start, "end": end, "step": step})
    with urlopen(f"{PROMETHEUS_URL}/api/v1/query_range?{params}", timeout=HTTP_TIMEOUT_SECONDS) as resp:
        payload = json.loads(resp.read())
    if payload.get("status") != "success":
        raise RuntimeError(payload)
    return payload.get("data", {}).get("result", [])


def prometheus_query(query: str, query_time: Optional[int] = None) -> Iterable[dict]:
    params: Dict[str, Any] = {"query": query}
    if query_time is not None:
        params["time"] = query_time
    with urlopen(f"{PROMETHEUS_URL}/api/v1/query?{urlencode(params)}", timeout=HTTP_TIMEOUT_SECONDS) as resp:
        payload = json.loads(resp.read())
    if payload.get("status") != "success":
        raise RuntimeError(payload)
    return payload.get("data", {}).get("result", [])


def promql_string(value: str) -> str:
    return json.dumps(value)


def normalize_metric_value(value: Any) -> Any:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return value
    if not math.isfinite(number):
        return str(value)
    if number.is_integer():
        return int(number)
    return number


def fetch_probe_metrics_snapshot(job: str, target: str, epoch: int) -> List[dict]:
    query = (
        '{__name__=~"probe_.*",'
        f"job={promql_string(job)},"
        f"instance={promql_string(target)}}}"
    )
    rows = prometheus_query(query, query_time=epoch)
    metrics = []
    for row in rows:
        labels = dict(row.get("metric", {}))
        name = labels.pop("__name__", "")
        value = ""
        if row.get("value") and len(row["value"]) >= 2:
            value = row["value"][1]
        metrics.append(
            {
                "name": name,
                "labels": labels,
                "value": normalize_metric_value(value),
            }
        )
    return sorted(metrics, key=lambda item: (item["name"], json.dumps(item["labels"], sort_keys=True)))


def fetch_probe_debug(target: str, module: str) -> str:
    params = urlencode({"target": target, "module": module, "debug": "true"})
    with urlopen(f"{BLACKBOX_URL}/probe?{params}", timeout=DEBUG_TIMEOUT_SECONDS) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return body[:DEBUG_LOG_MAX_CHARS]


def http_post_json(url: str, payload: dict, headers: Dict[str, str], timeout: float) -> dict:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as resp:
            response_body = resp.read().decode("utf-8", errors="replace")
    except UrlHTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")[:4000]
        raise LLMProviderError(f"LLM provider returned HTTP {exc.code}: {error_body}", error_body) from exc
    except URLError as exc:
        raise LLMProviderError(f"LLM provider request failed: {exc}") from exc

    try:
        return json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise LLMProviderError("LLM provider returned non-JSON response", response_body[:4000]) from exc


def validate_grafana_session(cookie_header: str) -> None:
    if not REQUIRE_GRAFANA_AUTH:
        return
    if not cookie_header:
        raise ApiError(401, "Grafana login is required")

    request = Request(
        GRAFANA_AUTH_URL,
        headers={"Cookie": cookie_header, "Accept": "application/json"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=GRAFANA_AUTH_TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                return
            raise ApiError(401, "Grafana login is required")
    except UrlHTTPError as exc:
        if exc.code in (401, 403):
            raise ApiError(401, "Grafana login is required") from exc
        raise ApiError(502, f"Grafana auth check failed with HTTP {exc.code}") from exc
    except URLError as exc:
        raise ApiError(502, f"Grafana auth check failed: {exc}") from exc


def compact_line(line: str, max_chars: int = 500) -> str:
    return re.sub(r"\s+", " ", line).strip()[:max_chars]


def summarize_debug(debug_log: str) -> str:
    lines = [line.strip() for line in debug_log.splitlines() if line.strip()]
    priority_groups = (
        ("level=error", "err="),
        ("err=",),
        ("connection refused",),
        ("no such host",),
        ("network is unreachable",),
        ("no route to host",),
        ("tls", "handshake"),
        ("x509:",),
        ("timeout",),
        ("deadline exceeded",),
        ("failed",),
        ("probe_success 0",),
    )
    for markers in priority_groups:
        for line in reversed(lines):
            low = line.lower()
            if all(marker in low for marker in markers):
                return compact_line(line)
    if lines:
        return compact_line(lines[-1])
    return "probe failed, debug output empty"


def debug_contains_failure(debug_log: str) -> bool:
    low = debug_log.lower()
    return any(
        marker in low
        for marker in (
            "level=error",
            "err=",
            "error",
            "failed",
            "timeout",
            "refused",
            "no such host",
            "probe_success 0",
        )
    )


def metric_value(metrics: List[dict], name: str, labels: Optional[Dict[str, str]] = None) -> Any:
    labels = labels or {}
    for metric in metrics:
        if metric.get("name") != name:
            continue
        metric_labels = metric.get("labels", {})
        if all(metric_labels.get(key) == value for key, value in labels.items()):
            return metric.get("value")
    return None


def numeric_metric(metrics: List[dict], name: str, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
    value = metric_value(metrics, name, labels)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def dns_rcode_name(code: Optional[float]) -> str:
    if code is None:
        return "unknown"
    names = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    return names.get(int(code), str(int(code)))


def classify_debug_failure(layer: str, debug_log: str) -> Optional[Tuple[str, str]]:
    low = debug_log.lower()
    if not low:
        return None
    if any(marker in low for marker in ("x509:", "certificate has expired", "certificate signed by unknown authority")):
        return "tls_cert", "TLS certificate validation failed"
    if "tls handshake timeout" in low:
        return "tls", "TLS handshake timeout"
    if "tls:" in low or "handshake failure" in low:
        return "tls", "TLS handshake failed"
    if "no such host" in low or "server misbehaving" in low or "lookup " in low:
        return "dns", "DNS resolution failed"
    if "connection refused" in low:
        return "tcp_connect", "TCP connection refused"
    if "network is unreachable" in low or "no route to host" in low:
        return "ip_route", "IP routing failed"
    if "i/o timeout" in low or "deadline exceeded" in low or "context deadline" in low:
        if layer == "dns":
            return "dns", "DNS query timed out"
        if layer == "icmp":
            return "icmp", "ICMP echo timed out"
        if layer == "tcp":
            return "tcp_connect", "TCP connect timed out"
        if layer == "http":
            return "http_probe", "HTTP probe timed out before a valid response"
        return "timeout", "Probe timed out"
    if "invalid ssl" in low:
        return "tls", "TLS expectation failed"
    if "probe failed" in low:
        return layer or "probe", "Probe failed"
    return None


def classify_metrics_failure(
    layer: str,
    module: str,
    metrics: List[dict],
    epoch: int,
) -> Tuple[str, str]:
    if not metrics:
        return layer or "unknown", "probe_success=0; no probe metric snapshot was available"

    probe_success = numeric_metric(metrics, "probe_success")
    if probe_success == 1:
        return layer or "unknown", "Prometheus recorded probe_success=0, but the instant metric snapshot had already recovered"

    if layer == "dns":
        rcode = numeric_metric(metrics, "probe_dns_rcode")
        query_succeeded = numeric_metric(metrics, "probe_dns_query_succeeded")
        if rcode is not None and rcode != 0:
            return "dns", f"DNS query returned rcode={dns_rcode_name(rcode)}"
        if query_succeeded == 0:
            return "dns", "DNS query did not complete successfully"
        return "dns", "DNS probe failed"

    if layer == "icmp":
        replies = numeric_metric(metrics, "probe_icmp_replies")
        if replies == 0:
            return "icmp", "ICMP echo received no replies"
        return "icmp", "ICMP probe failed"

    if layer == "tcp":
        return "tcp_connect", "TCP probe failed before a successful connection"

    if layer == "http":
        regex_failed = numeric_metric(metrics, "probe_failed_due_to_regex")
        status_code = numeric_metric(metrics, "probe_http_status_code")
        ssl_expiry = numeric_metric(metrics, "probe_ssl_earliest_cert_expiry")
        if regex_failed == 1:
            return "http_content", "HTTP response body/header regex validation failed"
        if ssl_expiry is not None and ssl_expiry > 0 and ssl_expiry <= epoch:
            return "tls_cert", "TLS certificate is expired"
        if status_code is not None and status_code > 0:
            return "http_status", f"HTTP returned status code {int(status_code)}"
        if module.startswith("https"):
            return "http_probe", "HTTPS probe failed before receiving an HTTP status code"
        return "http_probe", "HTTP probe failed before receiving an HTTP status code"

    return layer or "unknown", "probe_success=0"


def derive_failure_diagnostics(
    layer: str,
    module: str,
    metrics: List[dict],
    debug_log: str,
    epoch: int,
) -> Tuple[str, str, str]:
    debug_diag = classify_debug_failure(layer, debug_log)
    metric_diag = classify_metrics_failure(layer, module, metrics, epoch)
    failure_layer, failure_reason = debug_diag or metric_diag
    debug_summary = summarize_debug(debug_log)

    if debug_contains_failure(debug_log):
        summary = f"{failure_reason}; debug: {debug_summary}"
    elif metrics:
        summary = f"{failure_reason}; post-failure debug did not reproduce the failure"
    else:
        summary = failure_reason
    return failure_layer, failure_reason, summary[:500]


def require_ingest_auth(headers: Any) -> None:
    if not PI_INGEST_TOKEN:
        raise ApiError(503, "PI_INGEST_TOKEN is not configured")
    auth = headers.get("Authorization", "")
    prefix = "Bearer "
    if not auth.startswith(prefix):
        raise ApiError(401, "Bearer token is required")
    token = auth[len(prefix) :].strip()
    if not hmac.compare_digest(token, PI_INGEST_TOKEN):
        raise ApiError(403, "Bearer token is invalid")


def validate_pi_event(payload: Any) -> dict:
    if not isinstance(payload, dict):
        raise ApiError(400, "request body must be a JSON object")
    required = ("source", "incident_id", "event_type", "event_time", "sequence", "trigger")
    missing = [key for key in required if payload.get(key) in (None, "")]
    if missing:
        raise ApiError(400, f"missing required fields: {', '.join(missing)}")
    if payload["event_type"] not in ("started", "snapshot", "recovered"):
        raise ApiError(400, "event_type must be started, snapshot, or recovered")
    trigger = payload.get("trigger")
    if not isinstance(trigger, dict):
        raise ApiError(400, "trigger must be an object")
    for key in ("probe_layer", "target"):
        if not trigger.get(key):
            raise ApiError(400, f"trigger.{key} is required")
    trigger.setdefault("job", f"blackbox_{trigger['probe_layer']}")
    trigger.setdefault("module", MODULE_BY_JOB.get(trigger["job"], trigger["probe_layer"]))
    trigger.setdefault("target_name", target_name(trigger["target"]))
    payload.setdefault("probe_results", [])
    payload.setdefault("evidence", {})
    return payload


def event_trigger_key(payload: dict) -> Tuple[str, str, str, str, str, str]:
    trigger = payload["trigger"]
    layer = str(trigger.get("probe_layer") or "")
    job = str(trigger.get("job") or f"blackbox_{layer}")
    target = str(trigger.get("target") or "")
    module = str(trigger.get("module") or MODULE_BY_JOB.get(job, layer))
    name = str(trigger.get("target_name") or target_name(target))
    return target_key(job, target, module), layer, job, target, module, name


def result_matches_trigger(result: dict, job: str, target: str, module: str) -> bool:
    return (
        result.get("job") == job
        and result.get("target") == target
        and result.get("module") == module
    )


def trigger_probe_result(payload: dict, job: str, target: str, module: str) -> dict:
    for result in payload.get("probe_results") or []:
        if isinstance(result, dict) and result_matches_trigger(result, job, target, module):
            return result
    return {}


def trigger_debug_entry(payload: dict, job: str, target: str, module: str) -> dict:
    debug = (payload.get("evidence") or {}).get("blackbox_debug") or {}
    if not isinstance(debug, dict):
        return {}
    key = target_key(job, target, module)
    if isinstance(debug.get(key), dict):
        return debug[key]
    for entry in debug.values():
        if isinstance(entry, dict) and result_matches_trigger(entry, job, target, module):
            return entry
    return {}


def metrics_from_pi_event(payload: dict, job: str, target: str, module: str) -> List[dict]:
    result = trigger_probe_result(payload, job, target, module)
    metrics = result.get("metrics") if isinstance(result, dict) else []
    if isinstance(metrics, list) and metrics:
        return metrics
    debug_entry = trigger_debug_entry(payload, job, target, module)
    metrics = debug_entry.get("metrics") if isinstance(debug_entry, dict) else []
    return metrics if isinstance(metrics, list) else []


def debug_log_from_pi_event(payload: dict, job: str, target: str, module: str) -> Tuple[str, str, Optional[int]]:
    debug_entry = trigger_debug_entry(payload, job, target, module)
    if not debug_entry:
        return "", "pi_agent_no_debug", None
    body = str(debug_entry.get("body") or "")
    error = str(debug_entry.get("error") or "")
    source = "pi_agent_blackbox_debug"
    if error:
        source = "pi_agent_blackbox_debug_failed"
        body = f"Pi agent failed to fetch blackbox debug output: {error}\n{body}"
    fetched_epoch = debug_entry.get("fetched_at_epoch")
    try:
        fetched_epoch_int = int(fetched_epoch) if fetched_epoch is not None else None
    except (TypeError, ValueError):
        fetched_epoch_int = None
    return truncate_text(body, DEBUG_LOG_MAX_CHARS), source, fetched_epoch_int


def batch_fields_from_event(payload: dict, event_epoch: int) -> Tuple[str, int, int]:
    batch = payload.get("batch") if isinstance(payload.get("batch"), dict) else {}
    window = int(batch.get("group_window_seconds") or 30)
    batch_epoch = int(batch.get("batch_started_at_epoch") or (event_epoch - (event_epoch % max(1, window))))
    batch_at = str(batch.get("batch_started_at") or format_ts(batch_epoch))
    return batch_at, batch_epoch, window


def upsert_probe_target_from_pi(conn: sqlite3.Connection, result: dict, fallback_epoch: int) -> None:
    if not isinstance(result, dict):
        return
    job = result.get("job")
    target = result.get("target")
    layer = result.get("probe_layer")
    module = result.get("module") or MODULE_BY_JOB.get(str(job), str(layer))
    if not job or not target or not layer or not module:
        return
    try:
        success = int(result.get("success"))
    except (TypeError, ValueError):
        success = None
    try:
        seen_epoch = int(result.get("sample_epoch") or fallback_epoch)
    except (TypeError, ValueError):
        seen_epoch = fallback_epoch
    seen_at = str(result.get("sample_at") or format_ts(seen_epoch))
    name = str(result.get("target_name") or target_name(str(target)))
    key = target_key(str(job), str(target), str(module))
    conn.execute(
        """
        INSERT INTO probe_targets (
          target_key, probe_layer, job, target, target_name, module,
          last_success, last_seen_at, last_seen_epoch, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(target_key) DO UPDATE SET
          probe_layer=excluded.probe_layer,
          job=excluded.job,
          target=excluded.target,
          target_name=excluded.target_name,
          module=excluded.module,
          last_success=excluded.last_success,
          last_seen_at=excluded.last_seen_at,
          last_seen_epoch=excluded.last_seen_epoch,
          updated_at=excluded.updated_at
        """,
        (key, layer, job, target, name, module, success, seen_at, seen_epoch, seen_at),
    )


def insert_incident_evidence(
    conn: sqlite3.Connection,
    incident_id: int,
    payload: dict,
    source: str,
    source_incident_id: str,
    source_event_id: str,
    event_epoch: int,
) -> bool:
    created_epoch = now_epoch()
    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO incident_evidence (
          incident_id, source, source_incident_id, source_event_id,
          event_type, event_time, event_time_epoch, sequence,
          trigger_json, probe_results_json, evidence_json,
          created_at, created_at_epoch
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            source,
            source_incident_id,
            source_event_id,
            payload["event_type"],
            str(payload["event_time"]),
            event_epoch,
            int(payload["sequence"]),
            truncate_text(json.dumps(payload.get("trigger") or {}, ensure_ascii=False, sort_keys=True), DEBUG_LOG_MAX_CHARS),
            truncate_text(json.dumps(payload.get("probe_results") or [], ensure_ascii=False, sort_keys=True), DEBUG_LOG_MAX_CHARS),
            truncate_text(json.dumps(payload.get("evidence") or {}, ensure_ascii=False, sort_keys=True), DEBUG_LOG_MAX_CHARS * 4),
            format_ts(created_epoch),
            created_epoch,
        ),
    )
    return cursor.rowcount > 0


def find_pi_incident_row(
    conn: sqlite3.Connection,
    key: str,
    source: str,
    source_incident_id: str,
) -> Optional[sqlite3.Row]:
    row = conn.execute(
        "SELECT * FROM incidents WHERE target_key=? AND status='down'",
        (key,),
    ).fetchone()
    if row:
        return row
    return conn.execute(
        """
        SELECT *
        FROM incidents
        WHERE source=? AND source_incident_id=? AND target_key=?
        ORDER BY started_at_epoch DESC, id DESC
        LIMIT 1
        """,
        (source, source_incident_id, key),
    ).fetchone()


def record_pi_started(conn: sqlite3.Connection, payload: dict) -> int:
    source = str(payload["source"])
    source_incident_id = str(payload["incident_id"])
    source_event_id = event_id_from_payload(payload)
    event_epoch = parse_event_epoch(payload)
    event_time = str(payload.get("event_time") or format_ts(event_epoch))
    sequence = int(payload["sequence"])
    key, layer, job, target, module, name = event_trigger_key(payload)
    batch_at, batch_epoch, batch_window = batch_fields_from_event(payload, event_epoch)
    metrics = metrics_from_pi_event(payload, job, target, module)
    debug_log, debug_source, debug_epoch = debug_log_from_pi_event(payload, job, target, module)
    failure_layer, failure_reason, summary = derive_failure_diagnostics(
        layer,
        module,
        metrics,
        debug_log,
        event_epoch,
    )
    if not summary:
        summary = str((payload.get("trigger") or {}).get("reason") or "Pi observed probe_success=0")
    probe_metrics_json = truncate_text(
        json.dumps(
            {
                "source": source,
                "source_incident_id": source_incident_id,
                "event_id": source_event_id,
                "event_time": event_time,
                "trigger": payload.get("trigger") or {},
                "probe_results": payload.get("probe_results") or [],
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        DEBUG_LOG_MAX_CHARS,
    )

    row = conn.execute("SELECT * FROM incidents WHERE target_key=? AND status='down'", (key,)).fetchone()
    now_ts = format_ts(now_epoch())
    if row:
        incident_id = int(row["id"])
        conn.execute(
            """
            UPDATE incidents
            SET started_at=?,
                started_at_epoch=?,
                probe_layer=?,
                job=?,
                target=?,
                target_name=?,
                module=?,
                error_summary=?,
                debug_log=?,
                failure_layer=?,
                failure_reason=?,
                probe_metrics_json=?,
                debug_source=?,
                debug_fetched_at=?,
                debug_fetched_at_epoch=?,
                source=?,
                source_incident_id=?,
                source_event_id=?,
                source_sequence=?,
                batch_started_at=?,
                batch_started_at_epoch=?,
                batch_window_seconds=?,
                updated_at=?
            WHERE id=?
            """,
            (
                event_time,
                event_epoch,
                layer,
                job,
                target,
                name,
                module,
                summary,
                debug_log,
                failure_layer,
                failure_reason,
                probe_metrics_json,
                debug_source,
                format_ts(debug_epoch) if debug_epoch else None,
                debug_epoch,
                source,
                source_incident_id,
                source_event_id,
                sequence,
                batch_at,
                batch_epoch,
                batch_window,
                now_ts,
                incident_id,
            ),
        )
    else:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO incidents (
              target_key, started_at, started_at_epoch, status, probe_layer, job,
              target, target_name, module, error_summary, debug_log,
              failure_layer, failure_reason, probe_metrics_json,
              debug_source, debug_fetched_at, debug_fetched_at_epoch,
              source, source_incident_id, source_event_id, source_sequence,
              batch_started_at, batch_started_at_epoch, batch_window_seconds,
              created_at, updated_at
            )
            VALUES (?, ?, ?, 'down', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                event_time,
                event_epoch,
                layer,
                job,
                target,
                name,
                module,
                summary,
                debug_log,
                failure_layer,
                failure_reason,
                probe_metrics_json,
                debug_source,
                format_ts(debug_epoch) if debug_epoch else None,
                debug_epoch,
                source,
                source_incident_id,
                source_event_id,
                sequence,
                batch_at,
                batch_epoch,
                batch_window,
                event_time,
                now_ts,
            ),
        )
        if cursor.rowcount == 0:
            row = conn.execute("SELECT id FROM incidents WHERE target_key=? AND status='down'", (key,)).fetchone()
            if not row:
                raise ApiError(409, "incident insert was ignored but no open row was found")
            incident_id = int(row["id"])
        else:
            incident_id = int(cursor.lastrowid)
    return incident_id


def record_pi_recovered(conn: sqlite3.Connection, payload: dict) -> int:
    source = str(payload["source"])
    source_incident_id = str(payload["incident_id"])
    source_event_id = event_id_from_payload(payload)
    event_epoch = parse_event_epoch(payload)
    event_time = str(payload.get("event_time") or format_ts(event_epoch))
    sequence = int(payload["sequence"])
    key, layer, job, target, module, name = event_trigger_key(payload)
    batch_at, batch_epoch, batch_window = batch_fields_from_event(payload, event_epoch)
    row = find_pi_incident_row(conn, key, source, source_incident_id)
    now_ts = format_ts(now_epoch())
    if not row:
        cursor = conn.execute(
            """
            INSERT INTO incidents (
              target_key, started_at, started_at_epoch, recovered_at, recovered_at_epoch,
              status, probe_layer, job, target, target_name, module,
              error_summary, duration_seconds,
              source, source_incident_id, source_event_id, source_sequence,
              batch_started_at, batch_started_at_epoch, batch_window_seconds,
              created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 'recovered', ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                event_time,
                event_epoch,
                event_time,
                event_epoch,
                layer,
                job,
                target,
                name,
                module,
                "Pi reported recovery without a matching open incident",
                source,
                source_incident_id,
                source_event_id,
                sequence,
                batch_at,
                batch_epoch,
                batch_window,
                event_time,
                now_ts,
            ),
        )
        return int(cursor.lastrowid)

    incident_id = int(row["id"])
    duration = max(0, event_epoch - int(row["started_at_epoch"]))
    conn.execute(
        """
        UPDATE incidents
        SET status='recovered',
            recovered_at=?,
            recovered_at_epoch=?,
            duration_seconds=?,
            source=?,
            source_incident_id=?,
            source_event_id=?,
            source_sequence=?,
            batch_started_at=COALESCE(batch_started_at, ?),
            batch_started_at_epoch=COALESCE(batch_started_at_epoch, ?),
            batch_window_seconds=COALESCE(batch_window_seconds, ?),
            updated_at=?
        WHERE id=?
        """,
        (
            event_time,
            event_epoch,
            duration,
            source,
            source_incident_id,
            source_event_id,
            sequence,
            batch_at,
            batch_epoch,
            batch_window,
            now_ts,
            incident_id,
        ),
    )
    return incident_id


def record_pi_snapshot(conn: sqlite3.Connection, payload: dict) -> int:
    source = str(payload["source"])
    source_incident_id = str(payload["incident_id"])
    key, _layer, _job, _target, _module, _name = event_trigger_key(payload)
    row = find_pi_incident_row(conn, key, source, source_incident_id)
    if not row:
        raise ApiError(404, "no matching incident for snapshot")
    now_ts = format_ts(now_epoch())
    conn.execute(
        """
        UPDATE incidents
        SET source_event_id=?, source_sequence=?, updated_at=?
        WHERE id=?
        """,
        (event_id_from_payload(payload), int(payload["sequence"]), now_ts, int(row["id"])),
    )
    return int(row["id"])


def ingest_pi_event(payload: dict) -> Tuple[int, dict]:
    payload = validate_pi_event(payload)
    source = str(payload["source"])
    source_event_id = event_id_from_payload(payload)
    source_incident_id = str(payload["incident_id"])
    event_epoch = parse_event_epoch(payload)
    conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        with DB_LOCK:
            init_db(conn)
            duplicate = conn.execute(
                "SELECT incident_id FROM incident_evidence WHERE source=? AND source_event_id=?",
                (source, source_event_id),
            ).fetchone()
            if duplicate:
                return 200, json_response(
                    "duplicate",
                    incident_id=int(duplicate["incident_id"]),
                    source=source,
                    source_incident_id=source_incident_id,
                    source_event_id=source_event_id,
                )
            for result in payload.get("probe_results") or []:
                upsert_probe_target_from_pi(conn, result, event_epoch)

            if payload["event_type"] == "started":
                incident_id = record_pi_started(conn, payload)
            elif payload["event_type"] == "recovered":
                incident_id = record_pi_recovered(conn, payload)
            else:
                incident_id = record_pi_snapshot(conn, payload)

            inserted = insert_incident_evidence(
                conn,
                incident_id,
                payload,
                source,
                source_incident_id,
                source_event_id,
                event_epoch,
            )
            conn.commit()
            status = "accepted" if inserted else "duplicate"
            print(
                f"pi event {status}: source={source} event={source_event_id} type={payload['event_type']} incident_id={incident_id}",
                flush=True,
            )
            return 200, json_response(
                status,
                incident_id=incident_id,
                source=source,
                source_incident_id=source_incident_id,
                source_event_id=source_event_id,
            )
    finally:
        conn.close()


def build_llm_prompt(incident: sqlite3.Row, batch_rows: List[sqlite3.Row]) -> List[dict]:
    incident_context = {
        "id": incident["id"],
        "status": incident["status"],
        "started_at": incident["started_at"],
        "recovered_at": incident["recovered_at"],
        "duration_seconds": incident["duration_seconds"],
        "probe_layer": incident["probe_layer"],
        "job": incident["job"],
        "target": incident["target"],
        "target_label": target_label(incident),
        "module": incident["module"],
        "source": incident["source"],
        "source_incident_id": incident["source_incident_id"],
        "failure_layer": incident["failure_layer"],
        "failure_reason": incident["failure_reason"],
        "error_summary": incident["error_summary"],
        "probe_metrics_json": truncate_text(incident["probe_metrics_json"], 8000),
        "debug_log": truncate_text(incident["debug_log"], LLM_DEBUG_LOG_MAX_CHARS),
    }
    batch_context = [
        {
            "id": row["id"],
            "status": row["status"],
            "started_at": row["started_at"],
            "recovered_at": row["recovered_at"],
            "duration_seconds": row["duration_seconds"],
            "probe_layer": row["probe_layer"],
            "target": row["target"],
            "target_label": target_label(row),
            "module": row["module"],
            "source": row["source"],
            "source_incident_id": row["source_incident_id"],
            "failure_layer": row["failure_layer"],
            "failure_reason": row["failure_reason"],
            "error_summary": row["error_summary"],
        }
        for row in batch_rows
    ]
    topology = {
        "prometheus_host": "Dell PC 192.168.66.152 USB eth / 192.168.66.208 Wi-Fi",
        "blackbox_probe_host": "Raspberry Pi 192.168.66.108",
        "gateway": "192.168.66.1",
        "targets": {
            "192.168.66.1": "LAN gateway",
            "114.114.114.114": "LDNS target, dns_a queries baidu.com",
            "119.29.29.29": "public ICMP control",
            "118.31.170.151": "owned server ICMP",
            "remote.zhoushicheng.cn:443": "owned server TCP 443",
            "https://remote.zhoushicheng.cn": "owned server HTTPS",
        },
    }
    output_schema = {
        "summary": "short Chinese summary of what the probe data shows",
        "diagnosis": "best-fit diagnostic category, not a root-cause claim unless evidence supports it",
        "confidence": "low|medium|high",
        "affected_scope": "what appears affected from the supplied incidents",
        "evidence": ["specific observed evidence only"],
        "next_steps": ["actionable checks ordered by value"],
        "uncertainties": ["unknowns or missing evidence"],
    }
    system_prompt = (
        "你是家庭网络 incident 分析助手。你的输入来自 Prometheus/Blackbox/SQLite。"
        "边界：不要判断 incident 是否成立，不要发告警，不要编造证据，"
        "不要把探测失败直接等同于根因。你的目标是基于 down 时 raw debug output、"
        "同批次 probe 结果、恢复时间和拓扑信息，给出可执行排查建议。"
        "只能返回严格 JSON，不能包含 Markdown、代码块或额外解释。"
    )
    user_payload = {
        "task": "分析这一条已记录 incident，LLM 只做辅助分析，不参与断线判定。",
        "incident": incident_context,
        "same_30s_batch_incidents": batch_context,
        "topology": topology,
        "required_json_schema": output_schema,
    }
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
    ]


def parse_llm_json(content: str) -> dict:
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise LLMProviderError(f"LLM response was not valid JSON: {exc}", content[:4000]) from exc
    if not isinstance(parsed, dict):
        raise LLMProviderError("LLM response JSON must be an object", content[:4000])
    return parsed


def call_llm(messages: List[dict]) -> Tuple[dict, str]:
    if not DEEPSEEK_API_KEY:
        raise ApiError(503, "DEEPSEEK_API_KEY is not configured")
    payload = {
        "model": LLM_MODEL,
        "messages": messages,
        "stream": False,
        "response_format": {"type": "json_object"},
    }
    response = http_post_json(
        f"{LLM_API_BASE_URL}/v1/chat/completions",
        payload,
        {"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
        LLM_HTTP_TIMEOUT_SECONDS,
    )
    raw_response = truncate_text(json.dumps(response, ensure_ascii=False), LLM_RAW_RESPONSE_MAX_CHARS)
    choices = response.get("choices") or []
    if not choices:
        raise LLMProviderError("LLM response did not include choices", raw_response)
    content = choices[0].get("message", {}).get("content", "")
    if not content:
        raise LLMProviderError("LLM response did not include message content", raw_response)
    parsed = parse_llm_json(content)
    return parsed, raw_response


def open_incidents(conn: sqlite3.Connection) -> Dict[str, int]:
    rows = conn.execute("SELECT target_key, id FROM incidents WHERE status = 'down'").fetchall()
    return {row[0]: row[1] for row in rows}


def load_target_state(conn: sqlite3.Connection) -> Tuple[Dict[str, Optional[int]], Dict[str, int]]:
    rows = conn.execute("SELECT target_key, last_success, last_seen_epoch FROM probe_targets").fetchall()
    last_success = {row[0]: row[1] for row in rows}
    last_processed_epoch = {row[0]: int(row[2]) for row in rows}
    for key in open_incidents(conn):
        last_success[key] = 0
    return last_success, last_processed_epoch


def load_incident_for_analysis(conn: sqlite3.Connection, incident_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()


def load_batch_incidents(conn: sqlite3.Connection, incident: sqlite3.Row) -> List[sqlite3.Row]:
    batch_epoch = incident["batch_started_at_epoch"]
    if batch_epoch is None:
        batch_epoch = int(incident["started_at_epoch"]) - (int(incident["started_at_epoch"]) % 30)
    batch_epoch = int(batch_epoch)
    return conn.execute(
        """
        SELECT *
        FROM incidents
        WHERE COALESCE(batch_started_at_epoch, started_at_epoch - (started_at_epoch % 30)) = ?
        ORDER BY started_at_epoch ASC, id ASC
        """,
        (batch_epoch,),
    ).fetchall()


def llm_result_from_row(row: sqlite3.Row) -> dict:
    return {
        "incident_id": row["id"],
        "llm_status": row["llm_status"],
        "llm_requested_at": row["llm_requested_at"],
        "llm_completed_at": row["llm_completed_at"],
        "llm_model": row["llm_model"],
        "summary": row["llm_summary"],
        "diagnosis": row["llm_diagnosis"],
        "confidence": row["llm_confidence"],
        "affected_scope": row["llm_affected_scope"],
        "evidence": row["llm_evidence"],
        "next_steps": row["llm_next_steps"],
        "uncertainties": row["llm_uncertainties"],
        "error": row["llm_error"],
    }


def analyze_incident(incident_id: int, force: bool = False) -> Tuple[int, dict]:
    requested_epoch = now_epoch()
    requested_at = format_ts(requested_epoch)
    in_flight_added = False
    conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        with DB_LOCK:
            init_db(conn)
            incident = load_incident_for_analysis(conn, incident_id)
            if not incident:
                raise ApiError(404, f"incident_id={incident_id} not found")
            if (
                not force
                and incident["llm_status"] == "completed"
                and incident["llm_completed_at"]
            ):
                return 200, json_response("cached", **llm_result_from_row(incident))
            if incident_id in ANALYSIS_IN_FLIGHT:
                raise ApiError(409, f"incident_id={incident_id} analysis is already running")
            ANALYSIS_IN_FLIGHT.add(incident_id)
            in_flight_added = True
            conn.execute(
                """
                UPDATE incidents
                SET llm_status='running',
                    llm_requested_at=?,
                    llm_requested_at_epoch=?,
                    llm_completed_at=NULL,
                    llm_completed_at_epoch=NULL,
                    llm_model=?,
                    llm_summary=NULL,
                    llm_diagnosis=NULL,
                    llm_confidence=NULL,
                    llm_affected_scope=NULL,
                    llm_evidence=NULL,
                    llm_next_steps=NULL,
                    llm_uncertainties=NULL,
                    llm_error=NULL,
                    llm_raw_response=NULL,
                    updated_at=?
                WHERE id=?
                """,
                (requested_at, requested_epoch, LLM_MODEL, requested_at, incident_id),
            )
            conn.commit()
            incident = load_incident_for_analysis(conn, incident_id)
            if not incident:
                raise ApiError(404, f"incident_id={incident_id} not found")
            batch_rows = load_batch_incidents(conn, incident)

        messages = build_llm_prompt(incident, batch_rows)
        result, raw_response = call_llm(messages)
        completed_epoch = now_epoch()
        completed_at = format_ts(completed_epoch)
        llm_fields = {
            "summary": normalize_llm_value(result.get("summary")),
            "diagnosis": normalize_llm_value(result.get("diagnosis")),
            "confidence": normalize_llm_value(result.get("confidence")),
            "affected_scope": normalize_llm_value(result.get("affected_scope")),
            "evidence": normalize_llm_value(result.get("evidence")),
            "next_steps": normalize_llm_value(result.get("next_steps")),
            "uncertainties": normalize_llm_value(result.get("uncertainties")),
        }
        with DB_LOCK:
            conn.execute(
                """
                UPDATE incidents
                SET llm_status='completed',
                    llm_completed_at=?,
                    llm_completed_at_epoch=?,
                    llm_model=?,
                    llm_summary=?,
                    llm_diagnosis=?,
                    llm_confidence=?,
                    llm_affected_scope=?,
                    llm_evidence=?,
                    llm_next_steps=?,
                    llm_uncertainties=?,
                    llm_error=NULL,
                    llm_raw_response=?,
                    updated_at=?
                WHERE id=?
                """,
                (
                    completed_at,
                    completed_epoch,
                    LLM_MODEL,
                    llm_fields["summary"],
                    llm_fields["diagnosis"],
                    llm_fields["confidence"],
                    llm_fields["affected_scope"],
                    llm_fields["evidence"],
                    llm_fields["next_steps"],
                    llm_fields["uncertainties"],
                    raw_response,
                    completed_at,
                    incident_id,
                ),
            )
            conn.commit()
            updated = load_incident_for_analysis(conn, incident_id)
            if not updated:
                raise ApiError(404, f"incident_id={incident_id} not found after analysis")
            return 200, json_response("completed", **llm_result_from_row(updated))
    except ApiError as exc:
        if exc.status_code == 503 and in_flight_added:
            with DB_LOCK:
                conn.execute(
                    """
                    UPDATE incidents
                    SET llm_status='error',
                        llm_error=?,
                        llm_completed_at=?,
                        llm_completed_at_epoch=?,
                        updated_at=?
                    WHERE id=?
                    """,
                    (exc.message, requested_at, requested_epoch, requested_at, incident_id),
                )
                conn.commit()
        raise
    except Exception as exc:
        completed_epoch = now_epoch()
        completed_at = format_ts(completed_epoch)
        raw_response = exc.raw_response if isinstance(exc, LLMProviderError) else ""
        message = str(exc)
        with DB_LOCK:
            conn.execute(
                """
                UPDATE incidents
                SET llm_status='error',
                    llm_error=?,
                    llm_raw_response=?,
                    llm_completed_at=?,
                    llm_completed_at_epoch=?,
                    updated_at=?
                WHERE id=?
                """,
                (
                    message,
                    truncate_text(raw_response, LLM_RAW_RESPONSE_MAX_CHARS),
                    completed_at,
                    completed_epoch,
                    completed_at,
                    incident_id,
                ),
            )
            conn.commit()
        raise ApiError(502, message) from exc
    finally:
        if in_flight_added:
            with DB_LOCK:
                ANALYSIS_IN_FLIGHT.discard(incident_id)
        conn.close()


class AnalyzeHandler(BaseHTTPRequestHandler):
    server_version = "IncidentRecorderAnalyze/1.0"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/analyze":
            if parsed.path == "/healthz":
                self.send_json(200, json_response("ok"))
                return
            self.send_json(404, json_response("error", error="not found"))
            return

        try:
            validate_grafana_session(self.headers.get("Cookie", ""))
        except ApiError as exc:
            self.send_json(exc.status_code, json_response("error", error=exc.message, **exc.details))
            return

        query = parse_qs(parsed.query)
        incident_values = query.get("incident_id", [])
        if not incident_values:
            self.send_json(400, json_response("error", error="incident_id is required"))
            return
        try:
            incident_id = int(incident_values[0])
        except ValueError:
            self.send_json(400, json_response("error", error="incident_id must be an integer"))
            return

        force = query.get("force", ["0"])[0].lower() in ("1", "true", "yes")
        try:
            status_code, payload = analyze_incident(incident_id, force=force)
        except ApiError as exc:
            self.send_json(exc.status_code, json_response("error", error=exc.message, **exc.details))
            return
        self.send_json(status_code, payload)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/v1/pi-incident-events":
            self.send_json(404, json_response("error", error="not found"))
            return
        try:
            require_ingest_auth(self.headers)
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                raise ApiError(400, "request body is required")
            if content_length > INGEST_MAX_BODY_CHARS:
                raise ApiError(413, "request body is too large")
            raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            payload = json.loads(raw_body)
            status_code, response = ingest_pi_event(payload)
        except json.JSONDecodeError as exc:
            self.send_json(400, json_response("error", error=f"invalid JSON: {exc}"))
            return
        except ApiError as exc:
            self.send_json(exc.status_code, json_response("error", error=exc.message, **exc.details))
            return
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self.send_json(500, json_response("error", error=str(exc)))
            return
        self.send_json(status_code, response)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"analyze-http: {self.address_string()} - {fmt % args}", flush=True)

    def send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_analyze_server() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((ANALYZE_HTTP_HOST, ANALYZE_HTTP_PORT), AnalyzeHandler)
    thread = threading.Thread(target=server.serve_forever, name="analyze-http", daemon=True)
    thread.start()
    print(f"analyze-http started: {ANALYZE_HTTP_HOST}:{ANALYZE_HTTP_PORT}", flush=True)
    return server


def metric_identity(metric: dict) -> Tuple[str, str, str, str, str, str]:
    job = metric["job"]
    target = metric["instance"]
    layer = metric.get("probe_layer", job.replace("blackbox_", ""))
    module = MODULE_BY_JOB.get(job, layer)
    name = target_name(target)
    key = target_key(job, target, module)
    return key, layer, job, target, module, name


def target_label(row: sqlite3.Row) -> str:
    target = row["target"]
    layer = row["probe_layer"]
    if target == "192.168.66.1":
        return "网关 192.168.66.1"
    if target == "119.29.29.29":
        return "公网对照 119.29.29.29"
    if target == "118.31.170.151":
        return "自有服务器IP 118.31.170.151"
    if target == "114.114.114.114" and layer == "dns":
        return "LDNS 114.114.114.114"
    if target == "remote.zhoushicheng.cn:443":
        return "自有服务器 remote.zhoushicheng.cn"
    if target == "https://remote.zhoushicheng.cn":
        return "自有服务器 remote.zhoushicheng.cn"
    return row["target_name"]


def upsert_target(conn: sqlite3.Connection, metric: dict, success: int, seen_epoch: int) -> Tuple[str, str, str, str, str]:
    key, layer, job, target, module, name = metric_identity(metric)
    seen_at = format_ts(seen_epoch)
    conn.execute(
        """
        INSERT INTO probe_targets (
          target_key, probe_layer, job, target, target_name, module,
          last_success, last_seen_at, last_seen_epoch, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(target_key) DO UPDATE SET
          probe_layer=excluded.probe_layer,
          job=excluded.job,
          target=excluded.target,
          target_name=excluded.target_name,
          module=excluded.module,
          last_success=excluded.last_success,
          last_seen_at=excluded.last_seen_at,
          last_seen_epoch=excluded.last_seen_epoch,
          updated_at=excluded.updated_at
        """,
        (key, layer, job, target, name, module, success, seen_at, seen_epoch, seen_at),
    )
    return key, layer, job, target, module


def record_down(conn: sqlite3.Connection, key: str, layer: str, job: str, target: str, module: str, epoch: int) -> bool:
    ts = format_ts(epoch)
    with DB_LOCK:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO incidents (
              target_key, started_at, started_at_epoch, status, probe_layer, job,
              target, target_name, module, error_summary, debug_log, source, created_at, updated_at
            )
            VALUES (?, ?, ?, 'down', ?, ?, ?, ?, ?, ?, ?, 'prometheus', ?, ?)
            """,
            (
                key,
                ts,
                epoch,
                layer,
                job,
                target,
                target_name(target),
                module,
                "Prometheus observed probe_success=0; fetching blackbox debug output",
                "",
                ts,
                ts,
            ),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return False

    metrics_error = ""
    metrics_snapshot: List[dict] = []
    try:
        metrics_snapshot = fetch_probe_metrics_snapshot(job, target, epoch)
    except Exception as exc:
        metrics_error = str(exc)

    debug_source = "blackbox_post_failure_debug"
    debug_fetched_epoch = now_epoch()
    debug_fetched_at = format_ts(debug_fetched_epoch)
    try:
        debug_log = fetch_probe_debug(target, module)
        if not debug_contains_failure(debug_log):
            debug_source = "blackbox_post_failure_debug_no_failure"
    except Exception as exc:
        debug_source = "blackbox_post_failure_debug_failed"
        debug_log = f"Prometheus observed probe_success=0 at {ts}; failed to fetch blackbox debug output: {exc}"
    failure_layer, failure_reason, summary = derive_failure_diagnostics(
        layer,
        module,
        metrics_snapshot,
        debug_log,
        epoch,
    )
    if metrics_error:
        summary = f"{summary}; metric snapshot fetch failed: {metrics_error}"[:500]

    metrics_payload = {
        "sample_at": ts,
        "sample_epoch": epoch,
        "job": job,
        "target": target,
        "module": module,
        "metrics": metrics_snapshot,
    }
    if metrics_error:
        metrics_payload["error"] = metrics_error
    metrics_json = truncate_text(json.dumps(metrics_payload, ensure_ascii=False, sort_keys=True), DEBUG_LOG_MAX_CHARS)

    update_ts = format_ts(now_epoch())
    with DB_LOCK:
        conn.execute(
            """
            UPDATE incidents
            SET error_summary=?,
                debug_log=?,
                failure_layer=?,
                failure_reason=?,
                probe_metrics_json=?,
                debug_source=?,
                debug_fetched_at=?,
                debug_fetched_at_epoch=?,
                updated_at=?
            WHERE target_key=? AND started_at_epoch=? AND status='down'
            """,
            (
                summary,
                debug_log,
                failure_layer,
                failure_reason,
                metrics_json,
                debug_source,
                debug_fetched_at,
                debug_fetched_epoch,
                update_ts,
                key,
                epoch,
            ),
        )
        conn.commit()
    print(
        f"incident down: layer={layer} target={target} module={module} failure_layer={failure_layer} summary={summary}",
        flush=True,
    )
    return True


def record_recovered(conn: sqlite3.Connection, key: str, epoch: int) -> None:
    with DB_LOCK:
        row = conn.execute(
            "SELECT id, started_at_epoch, probe_layer, target FROM incidents WHERE target_key = ? AND status = 'down'",
            (key,),
        ).fetchone()
        if not row:
            return
        incident_id, started_epoch, layer, target = row
        ts = format_ts(epoch)
        duration = max(0, epoch - int(started_epoch))
        conn.execute(
            """
            UPDATE incidents
            SET status='recovered', recovered_at=?, recovered_at_epoch=?,
                duration_seconds=?, updated_at=?
            WHERE id=?
            """,
            (ts, epoch, duration, ts, incident_id),
        )
        conn.commit()
    print(f"incident recovered: layer={layer} target={target} duration={duration}s", flush=True)


def process_sample(
    conn: sqlite3.Connection,
    metric: dict,
    sample_epoch: int,
    success: int,
    last_success: Dict[str, Optional[int]],
    last_processed_epoch: Dict[str, int],
) -> None:
    with DB_LOCK:
        key, layer, job, target, module = upsert_target(conn, metric, success, sample_epoch)
        previous = last_success.get(key)
        is_open = key in open_incidents(conn)
        conn.commit()

    if previous is None:
        last_success[key] = success
        last_processed_epoch[key] = sample_epoch
        return

    if success == 0 and previous != 0 and not is_open:
        record_down(conn, key, layer, job, target, module, sample_epoch)
    elif success == 1 and previous == 0 and is_open:
        record_recovered(conn, key, sample_epoch)

    last_success[key] = success
    last_processed_epoch[key] = sample_epoch


def poll_once(
    conn: sqlite3.Connection,
    last_success: Dict[str, Optional[int]],
    last_processed_epoch: Dict[str, int],
) -> None:
    end_epoch = now_epoch()
    start_epoch = end_epoch - LOOKBACK_SECONDS
    series = prometheus_query_range(
        'probe_success{job=~"blackbox_.*"}',
        start_epoch,
        end_epoch,
        QUERY_STEP_SECONDS,
    )

    pending: List[Tuple[int, dict, int]] = []
    for result in series:
        metric = result["metric"]
        key, _layer, _job, _target, _module, _name = metric_identity(metric)
        values = result.get("values", [])
        if key not in last_success and values:
            sample_epoch = int(float(values[-1][0]))
            success = int(float(values[-1][1]))
            process_sample(conn, metric, sample_epoch, success, last_success, last_processed_epoch)
            continue

        last_processed = last_processed_epoch.get(key, 0)
        for value in values:
            sample_epoch = int(float(value[0]))
            if sample_epoch <= last_processed:
                continue
            success = int(float(value[1]))
            pending.append((sample_epoch, metric, success))

    for sample_epoch, metric, success in sorted(pending, key=lambda item: item[0]):
        process_sample(conn, metric, sample_epoch, success, last_success, last_processed_epoch)
    with DB_LOCK:
        conn.commit()


def main() -> int:
    os.makedirs(os.path.dirname(SQLITE_PATH), exist_ok=True)
    conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    with DB_LOCK:
        init_db(conn)
        last_success, last_processed_epoch = load_target_state(conn)
    analyze_server = start_analyze_server()

    print(
        f"incident-recorder started: prometheus={PROMETHEUS_URL} blackbox={BLACKBOX_URL} db={SQLITE_PATH} llm_model={LLM_MODEL}",
        flush=True,
    )
    try:
        while not STOP:
            try:
                poll_once(conn, last_success, last_processed_epoch)
            except Exception:
                traceback.print_exc(file=sys.stderr)
            if os.getenv("RUN_ONCE") == "true":
                break
            for _ in range(INTERVAL_SECONDS):
                if STOP:
                    break
                time.sleep(1)
    finally:
        analyze_server.shutdown()
        analyze_server.server_close()
        conn.close()
    print("incident-recorder stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
