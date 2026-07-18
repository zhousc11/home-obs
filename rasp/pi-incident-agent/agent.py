#!/usr/bin/env python3
import fcntl
import json
import os
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import traceback
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError as UrlHTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


SOURCE = os.getenv("SOURCE", "rasp")
PROBE_CONFIG = os.getenv("PROBE_CONFIG", "/app/probes.json")
BLACKBOX_URL = os.getenv("BLACKBOX_URL", "http://127.0.0.1:9115").rstrip("/")
DEFAULT_DELL_INGEST_URLS = (
    "http://192.168.66.152:8088/api/v1/pi-incident-events",
)
PI_INGEST_TOKEN = os.getenv("PI_INGEST_TOKEN", "").strip()
SQLITE_PATH = os.getenv("SQLITE_PATH", "/data/pi-incident-agent.db")
INTERVAL_SECONDS = int(os.getenv("INTERVAL_SECONDS", "5"))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "4"))
DEBUG_TIMEOUT_SECONDS = float(os.getenv("DEBUG_TIMEOUT_SECONDS", "6"))
POST_TIMEOUT_SECONDS = float(os.getenv("POST_TIMEOUT_SECONDS", "6"))
RING_SECONDS = int(os.getenv("RING_SECONDS", "600"))
GROUP_WINDOW_SECONDS = int(os.getenv("GROUP_WINDOW_SECONDS", "30"))
SNAPSHOT_INTERVAL_SECONDS = int(os.getenv("SNAPSHOT_INTERVAL_SECONDS", "0"))
UTC_OFFSET_HOURS = int(os.getenv("UTC_OFFSET_HOURS", "8"))
SYSLOG_UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "514"))
SYSLOG_RING_MAX_LINES = int(os.getenv("SYSLOG_RING_MAX_LINES", "2000"))
DEBUG_LOG_MAX_CHARS = int(os.getenv("DEBUG_LOG_MAX_CHARS", "60000"))
EVENT_JSON_MAX_CHARS = int(os.getenv("EVENT_JSON_MAX_CHARS", "240000"))
COMMAND_OUTPUT_MAX_CHARS = int(os.getenv("COMMAND_OUTPUT_MAX_CHARS", "20000"))
ERX_SSH_HOST = os.getenv("ERX_SSH_HOST", "").strip()
ERX_SSH_USER = os.getenv("ERX_SSH_USER", "").strip()
ERX_SSH_KEY_PATH = os.getenv("ERX_SSH_KEY_PATH", "").strip()
ERX_SSH_TIMEOUT_SECONDS = float(os.getenv("ERX_SSH_TIMEOUT_SECONDS", "6"))
ERX_SSH_COOLDOWN_SECONDS = int(os.getenv("ERX_SSH_COOLDOWN_SECONDS", "60"))
ERX_SSH_COMMANDS = json.loads(
    os.getenv(
        "ERX_SSH_COMMANDS_JSON",
        json.dumps(
            [
                "/opt/vyatta/bin/vyatta-op-cmd-wrapper show interfaces",
                "/opt/vyatta/bin/vyatta-op-cmd-wrapper show ip route",
                "/opt/vyatta/bin/vyatta-op-cmd-wrapper show log tail",
                "/opt/vyatta/bin/vyatta-op-cmd-wrapper show system uptime",
            ]
        ),
    )
)

STOP = False
DB_LOCK = threading.RLock()
LAST_ERX_SNAPSHOT_EPOCH = 0


class IngestDeliveryError(RuntimeError):
    pass


def parse_ingest_urls() -> List[str]:
    configured_urls = os.getenv("DELL_INGEST_URLS", "").strip()
    legacy_url = os.getenv("DELL_INGEST_URL", "").strip()
    if configured_urls:
        candidates = re.split(r"[\s,]+", configured_urls)
    elif legacy_url:
        candidates = [legacy_url]
    else:
        candidates = list(DEFAULT_DELL_INGEST_URLS)

    urls: List[str] = []
    for candidate in candidates:
        url = candidate.strip().rstrip("/")
        if url and url not in urls:
            urls.append(url)
    if not urls:
        raise RuntimeError("no Dell ingest URL is configured")
    return urls


DELL_INGEST_URLS = parse_ingest_urls()


def request_stop(_signum: int, _frame: Any) -> None:
    global STOP
    STOP = True


signal.signal(signal.SIGTERM, request_stop)
signal.signal(signal.SIGINT, request_stop)


def now_epoch() -> int:
    return int(time.time())


def format_ts(epoch: int) -> str:
    tz = timezone(timedelta(hours=UTC_OFFSET_HOURS))
    return datetime.fromtimestamp(epoch, tz).isoformat(timespec="seconds")


def truncate_text(value: Any, max_chars: int) -> str:
    text = "" if value is None else str(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...<truncated>"


def load_probes() -> List[dict]:
    with open(PROBE_CONFIG, "r", encoding="utf-8") as fp:
        payload = json.load(fp)
    probes = payload.get("probes", [])
    if not isinstance(probes, list) or not probes:
        raise RuntimeError(f"{PROBE_CONFIG} must contain a non-empty probes list")
    required = {"job", "probe_layer", "target", "module"}
    for probe in probes:
        missing = required - set(probe)
        if missing:
            raise RuntimeError(f"probe is missing required fields: {sorted(missing)}")
        probe.setdefault("target_name", probe["target"])
    return probes


def target_key(probe: dict) -> str:
    return f"{probe['job']}|{probe['target']}|{probe['module']}"


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS target_state (
          target_key TEXT PRIMARY KEY,
          job TEXT NOT NULL,
          probe_layer TEXT NOT NULL,
          target TEXT NOT NULL,
          target_name TEXT NOT NULL,
          module TEXT NOT NULL,
          last_success INTEGER,
          source_incident_id TEXT,
          last_snapshot_epoch INTEGER,
          updated_at TEXT NOT NULL,
          updated_at_epoch INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_state (
          source_incident_id TEXT PRIMARY KEY,
          batch_started_at TEXT NOT NULL,
          batch_started_at_epoch INTEGER NOT NULL,
          sequence INTEGER NOT NULL,
          updated_at TEXT NOT NULL,
          updated_at_epoch INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS outbox (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT NOT NULL UNIQUE,
          payload_json TEXT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          next_attempt_epoch INTEGER NOT NULL DEFAULT 0,
          last_error TEXT,
          created_at TEXT NOT NULL,
          created_at_epoch INTEGER NOT NULL,
          delivered_at TEXT,
          delivered_at_epoch INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_outbox_due
        ON outbox(delivered_at_epoch, next_attempt_epoch, id)
        """
    )
    conn.commit()


def parse_labels(raw: str) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    if not raw:
        return labels
    for match in re.finditer(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"', raw):
        labels[match.group(1)] = bytes(match.group(2), "utf-8").decode("unicode_escape")
    return labels


def normalize_metric_value(value: str) -> Any:
    try:
        number = float(value)
    except ValueError:
        return value
    if number != number or number in (float("inf"), float("-inf")):
        return value
    if number.is_integer():
        return int(number)
    return number


METRIC_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([^\s]+)")


def parse_probe_metrics(body: str) -> List[dict]:
    metrics: List[dict] = []
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        match = METRIC_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if not name.startswith("probe_"):
            continue
        metrics.append(
            {
                "name": name,
                "labels": parse_labels(match.group(2) or ""),
                "value": normalize_metric_value(match.group(3)),
            }
        )
    return sorted(metrics, key=lambda item: (item["name"], json.dumps(item["labels"], sort_keys=True)))


def metric_value(metrics: List[dict], name: str) -> Any:
    for metric in metrics:
        if metric.get("name") == name:
            return metric.get("value")
    return None


def int_metric(metrics: List[dict], name: str, default: int = 0) -> int:
    try:
        return int(float(metric_value(metrics, name)))
    except (TypeError, ValueError):
        return default


def float_metric(metrics: List[dict], name: str, default: Optional[float] = None) -> Optional[float]:
    try:
        return float(metric_value(metrics, name))
    except (TypeError, ValueError):
        return default


def fetch_probe(probe: dict, debug: bool = False) -> Tuple[str, List[dict]]:
    params = {"target": probe["target"], "module": probe["module"]}
    if debug:
        params["debug"] = "true"
    timeout = DEBUG_TIMEOUT_SECONDS if debug else HTTP_TIMEOUT_SECONDS
    with urlopen(f"{BLACKBOX_URL}/probe?{urlencode(params)}", timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return body[:DEBUG_LOG_MAX_CHARS], parse_probe_metrics(body)


def probe_once(probes: List[dict]) -> List[dict]:
    sample_epoch = now_epoch()
    results: List[dict] = []
    for probe in probes:
        error = ""
        body = ""
        metrics: List[dict] = []
        try:
            body, metrics = fetch_probe(probe)
            success = int_metric(metrics, "probe_success", 0)
        except Exception as exc:
            success = 0
            error = str(exc)
        results.append(
            {
                "sample_at": format_ts(sample_epoch),
                "sample_epoch": sample_epoch,
                "job": probe["job"],
                "probe_layer": probe["probe_layer"],
                "target": probe["target"],
                "target_name": probe.get("target_name", probe["target"]),
                "module": probe["module"],
                "success": success,
                "duration_seconds": float_metric(metrics, "probe_duration_seconds"),
                "metrics": metrics,
                "error": error,
                "body_excerpt": truncate_text(body, 4000) if error else "",
            }
        )
    return results


def compact_probe_ring(ring: Deque[dict], cutoff_epoch: int) -> List[dict]:
    return [sample for sample in ring if sample.get("sample_epoch", 0) >= cutoff_epoch]


def read_file(path: str, max_chars: int = 20000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            return truncate_text(fp.read(), max_chars)
    except Exception as exc:
        return f"unavailable: {exc}"


def parse_default_routes(route_text: str) -> List[dict]:
    rows = []
    lines = [line.split() for line in route_text.splitlines() if line.strip()]
    for parts in lines[1:]:
        if len(parts) < 8 or parts[1] != "00000000":
            continue
        gateway_hex = parts[2]
        try:
            gateway = socket.inet_ntoa(struct.pack("<L", int(gateway_hex, 16)))
        except Exception:
            gateway = gateway_hex
        rows.append(
            {
                "iface": parts[0],
                "gateway": gateway,
                "flags": parts[3],
                "metric": parts[6],
            }
        )
    return rows


def ioctl_ipv4_address(ifname: str) -> Optional[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        request = struct.pack("256s", ifname[:15].encode("utf-8"))
        response = fcntl.ioctl(sock.fileno(), 0x8915, request)
        return socket.inet_ntoa(response[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def ipv6_addresses_by_iface() -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    text = read_file("/host/proc/net/if_inet6")
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        raw, _idx, _plen, _scope, _flags, iface = parts
        chunks = [raw[i : i + 4] for i in range(0, len(raw), 4)]
        try:
            address = socket.inet_ntop(socket.AF_INET6, bytes.fromhex("".join(chunks)))
        except OSError:
            address = ":".join(chunks)
        result.setdefault(iface, []).append(address)
    return result


def collect_interfaces() -> List[dict]:
    interfaces: List[dict] = []
    ipv6 = ipv6_addresses_by_iface()
    sys_net = "/host/sys/class/net"
    try:
        names = sorted(os.listdir(sys_net))
    except Exception:
        names = []
    for name in names:
        base = os.path.join(sys_net, name)
        interfaces.append(
            {
                "name": name,
                "operstate": read_file(os.path.join(base, "operstate"), 200).strip(),
                "carrier": read_file(os.path.join(base, "carrier"), 200).strip(),
                "mac": read_file(os.path.join(base, "address"), 200).strip(),
                "mtu": read_file(os.path.join(base, "mtu"), 200).strip(),
                "ipv4": [ioctl_ipv4_address(name)] if ioctl_ipv4_address(name) else [],
                "ipv6": ipv6.get(name, []),
            }
        )
    return interfaces


def collect_pi_snapshot() -> dict:
    epoch = now_epoch()
    route_text = read_file("/host/proc/net/route")
    return {
        "captured_at": format_ts(epoch),
        "captured_at_epoch": epoch,
        "uptime": read_file("/host/proc/uptime").strip(),
        "loadavg": read_file("/host/proc/loadavg").strip(),
        "meminfo": read_file("/host/proc/meminfo"),
        "interfaces": collect_interfaces(),
        "default_routes": parse_default_routes(route_text),
        "route_table_raw": route_text,
        "arp_table": read_file("/host/proc/net/arp"),
        "resolver_config": read_file("/host/resolv.conf"),
    }


class SyslogRing:
    def __init__(self, port: int, ring_seconds: int, max_lines: int):
        self.port = port
        self.ring_seconds = ring_seconds
        self.max_lines = max_lines
        self.rows: Deque[dict] = deque()
        self.lock = threading.RLock()
        self.thread = threading.Thread(target=self._run, name="syslog-udp", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def snapshot(self, since_epoch: int) -> List[dict]:
        with self.lock:
            return [row for row in self.rows if row.get("epoch", 0) >= since_epoch]

    def _append(self, row: dict) -> None:
        cutoff = now_epoch() - self.ring_seconds
        with self.lock:
            self.rows.append(row)
            while self.rows and (self.rows[0].get("epoch", 0) < cutoff or len(self.rows) > self.max_lines):
                self.rows.popleft()

    def _run(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.port))
            sock.settimeout(1)
        except Exception as exc:
            print(f"syslog listener disabled: udp/{self.port}: {exc}", flush=True)
            return

        print(f"syslog listener started: udp/{self.port}", flush=True)
        while not STOP:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception as exc:
                print(f"syslog listener error: {exc}", flush=True)
                time.sleep(1)
                continue
            epoch = now_epoch()
            self._append(
                {
                    "time": format_ts(epoch),
                    "epoch": epoch,
                    "remote": f"{addr[0]}:{addr[1]}",
                    "message": data.decode("utf-8", errors="replace").strip(),
                }
            )
        sock.close()


def collect_blackbox_debug(probes: Iterable[dict]) -> Dict[str, dict]:
    debug: Dict[str, dict] = {}
    for probe in probes:
        key = target_key(probe)
        epoch = now_epoch()
        try:
            body, metrics = fetch_probe(probe, debug=True)
            error = ""
        except Exception as exc:
            body = ""
            metrics = []
            error = str(exc)
        debug[key] = {
            "fetched_at": format_ts(epoch),
            "fetched_at_epoch": epoch,
            "job": probe["job"],
            "probe_layer": probe["probe_layer"],
            "target": probe["target"],
            "module": probe["module"],
            "metrics": metrics,
            "error": error,
            "body": truncate_text(body, DEBUG_LOG_MAX_CHARS),
        }
    return debug


def collect_erx_snapshot(event_type: str) -> dict:
    global LAST_ERX_SNAPSHOT_EPOCH
    epoch = now_epoch()
    if not ERX_SSH_HOST or not ERX_SSH_USER or not ERX_SSH_KEY_PATH:
        return {"skipped": "ERX_SSH_HOST, ERX_SSH_USER, or ERX_SSH_KEY_PATH is not configured"}
    if epoch - LAST_ERX_SNAPSHOT_EPOCH < ERX_SSH_COOLDOWN_SECONDS:
        return {"skipped": "cooldown", "last_snapshot_epoch": LAST_ERX_SNAPSHOT_EPOCH}
    if not os.path.exists(ERX_SSH_KEY_PATH):
        return {"skipped": f"ssh key not found: {ERX_SSH_KEY_PATH}"}

    LAST_ERX_SNAPSHOT_EPOCH = epoch
    results = []
    base_cmd = [
        "ssh",
        "-i",
        ERX_SSH_KEY_PATH,
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={max(1, int(ERX_SSH_TIMEOUT_SECONDS))}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "UserKnownHostsFile=/data/known_hosts",
        f"{ERX_SSH_USER}@{ERX_SSH_HOST}",
    ]
    for command in ERX_SSH_COMMANDS:
        started = now_epoch()
        try:
            proc = subprocess.run(
                [*base_cmd, command],
                check=False,
                capture_output=True,
                text=True,
                timeout=ERX_SSH_TIMEOUT_SECONDS,
            )
            results.append(
                {
                    "command": command,
                    "returncode": proc.returncode,
                    "stdout": truncate_text(proc.stdout, COMMAND_OUTPUT_MAX_CHARS),
                    "stderr": truncate_text(proc.stderr, 4000),
                    "duration_seconds": now_epoch() - started,
                }
            )
        except Exception as exc:
            results.append({"command": command, "error": str(exc)})
    return {
        "captured_at": format_ts(epoch),
        "captured_at_epoch": epoch,
        "event_type": event_type,
        "host": ERX_SSH_HOST,
        "commands": results,
    }


def load_target_states(conn: sqlite3.Connection) -> Dict[str, dict]:
    rows = conn.execute("SELECT * FROM target_state").fetchall()
    return {row["target_key"]: dict(row) for row in rows}


def latest_open_batch(conn: sqlite3.Connection, epoch: int) -> Optional[str]:
    row = conn.execute(
        """
        SELECT source_incident_id, batch_started_at_epoch
        FROM incident_state
        WHERE batch_started_at_epoch >= ?
        ORDER BY batch_started_at_epoch DESC
        LIMIT 1
        """,
        (epoch - GROUP_WINDOW_SECONDS,),
    ).fetchone()
    if row:
        return row["source_incident_id"]
    return None


def create_batch(conn: sqlite3.Connection, epoch: int) -> str:
    source_incident_id = str(uuid.uuid4())
    ts = format_ts(epoch)
    conn.execute(
        """
        INSERT INTO incident_state (
          source_incident_id, batch_started_at, batch_started_at_epoch,
          sequence, updated_at, updated_at_epoch
        )
        VALUES (?, ?, ?, 0, ?, ?)
        """,
        (source_incident_id, ts, epoch, ts, epoch),
    )
    return source_incident_id


def next_sequence(conn: sqlite3.Connection, source_incident_id: str) -> int:
    row = conn.execute(
        "SELECT sequence FROM incident_state WHERE source_incident_id=?",
        (source_incident_id,),
    ).fetchone()
    if not row:
        epoch = now_epoch()
        ts = format_ts(epoch)
        conn.execute(
            """
            INSERT INTO incident_state (
              source_incident_id, batch_started_at, batch_started_at_epoch,
              sequence, updated_at, updated_at_epoch
            )
            VALUES (?, ?, ?, 0, ?, ?)
            """,
            (source_incident_id, ts, epoch, ts, epoch),
        )
        sequence = 0
    else:
        sequence = int(row["sequence"])
    sequence += 1
    epoch = now_epoch()
    conn.execute(
        """
        UPDATE incident_state
        SET sequence=?, updated_at=?, updated_at_epoch=?
        WHERE source_incident_id=?
        """,
        (sequence, format_ts(epoch), epoch, source_incident_id),
    )
    return sequence


def upsert_target_state(
    conn: sqlite3.Connection,
    probe: dict,
    success: int,
    source_incident_id: Optional[str],
    last_snapshot_epoch: Optional[int] = None,
) -> None:
    epoch = now_epoch()
    ts = format_ts(epoch)
    conn.execute(
        """
        INSERT INTO target_state (
          target_key, job, probe_layer, target, target_name, module,
          last_success, source_incident_id, last_snapshot_epoch,
          updated_at, updated_at_epoch
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(target_key) DO UPDATE SET
          job=excluded.job,
          probe_layer=excluded.probe_layer,
          target=excluded.target,
          target_name=excluded.target_name,
          module=excluded.module,
          last_success=excluded.last_success,
          source_incident_id=excluded.source_incident_id,
          last_snapshot_epoch=COALESCE(excluded.last_snapshot_epoch, target_state.last_snapshot_epoch),
          updated_at=excluded.updated_at,
          updated_at_epoch=excluded.updated_at_epoch
        """,
        (
            target_key(probe),
            probe["job"],
            probe["probe_layer"],
            probe["target"],
            probe.get("target_name", probe["target"]),
            probe["module"],
            success,
            source_incident_id,
            last_snapshot_epoch,
            ts,
            epoch,
        ),
    )


def queue_event(conn: sqlite3.Connection, payload: dict) -> None:
    event_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    if len(event_json) > EVENT_JSON_MAX_CHARS:
        payload = dict(payload)
        evidence = dict(payload.get("evidence") or {})
        if "probe_ring" in evidence:
            evidence["probe_ring"] = evidence["probe_ring"][-24:]
        if "erx_syslog" in evidence:
            evidence["erx_syslog"] = evidence["erx_syslog"][-200:]
        payload["evidence"] = evidence
        event_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    epoch = now_epoch()
    conn.execute(
        """
        INSERT OR IGNORE INTO outbox (
          event_id, payload_json, created_at, created_at_epoch, next_attempt_epoch
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (payload["event_id"], event_json, format_ts(epoch), epoch, epoch),
    )


def event_probe_from_result(result: dict) -> dict:
    return {
        "job": result["job"],
        "probe_layer": result["probe_layer"],
        "target": result["target"],
        "target_name": result.get("target_name", result["target"]),
        "module": result["module"],
    }


def build_event(
    conn: sqlite3.Connection,
    event_type: str,
    source_incident_id: str,
    trigger_result: dict,
    current_results: List[dict],
    probe_ring: Deque[dict],
    syslog_ring: SyslogRing,
) -> dict:
    epoch = now_epoch()
    sequence = next_sequence(conn, source_incident_id)
    batch_row = conn.execute(
        """
        SELECT batch_started_at, batch_started_at_epoch
        FROM incident_state
        WHERE source_incident_id=?
        """,
        (source_incident_id,),
    ).fetchone()
    batch_started_at = batch_row["batch_started_at"] if batch_row else format_ts(epoch)
    batch_started_at_epoch = int(batch_row["batch_started_at_epoch"]) if batch_row else epoch
    failed_probes = [
        event_probe_from_result(result)
        for result in current_results
        if int(result.get("success") or 0) == 0
    ]
    trigger_probe = event_probe_from_result(trigger_result)
    debug_probes = failed_probes if event_type in ("started", "snapshot") and failed_probes else [trigger_probe]
    since_epoch = epoch - RING_SECONDS
    reason = "probe_success=0" if event_type in ("started", "snapshot") else "probe_success=1"
    return {
        "event_id": f"{SOURCE}:{source_incident_id}:{sequence}",
        "source": SOURCE,
        "incident_id": source_incident_id,
        "event_type": event_type,
        "event_time": format_ts(epoch),
        "event_epoch": epoch,
        "sequence": sequence,
        "batch": {
            "group_window_seconds": GROUP_WINDOW_SECONDS,
            "batch_started_at": batch_started_at,
            "batch_started_at_epoch": batch_started_at_epoch,
        },
        "trigger": {
            "probe_layer": trigger_result["probe_layer"],
            "job": trigger_result["job"],
            "target": trigger_result["target"],
            "target_name": trigger_result.get("target_name", trigger_result["target"]),
            "module": trigger_result["module"],
            "reason": reason,
        },
        "probe_results": current_results,
        "evidence": {
            "pi_snapshot": collect_pi_snapshot(),
            "blackbox_debug": collect_blackbox_debug(debug_probes),
            "probe_ring": compact_probe_ring(probe_ring, since_epoch),
            "erx_snapshot": collect_erx_snapshot(event_type),
            "erx_syslog": syslog_ring.snapshot(since_epoch),
        },
    }


def post_payload_to_url(url: str, payload: dict) -> dict:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if PI_INGEST_TOKEN:
        headers["Authorization"] = f"Bearer {PI_INGEST_TOKEN}"
    request = Request(url, data=body, headers=headers, method="POST")
    with urlopen(request, timeout=POST_TIMEOUT_SECONDS) as resp:
        response_body = resp.read().decode("utf-8", errors="replace")
    try:
        response = json.loads(response_body)
    except json.JSONDecodeError:
        response = {"status": "ok", "raw": response_body[:4000]}
    response.setdefault("ingest_url", url)
    return response


def post_payload(payload: dict) -> dict:
    errors = []
    for url in DELL_INGEST_URLS:
        try:
            return post_payload_to_url(url, payload)
        except UrlHTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")[:4000]
            errors.append(f"{url}: HTTP {exc.code}: {error_body}")
            if 400 <= exc.code < 500:
                break
        except (URLError, TimeoutError, OSError) as exc:
            errors.append(f"{url}: {exc}")
    raise IngestDeliveryError("all ingest URLs failed: " + "; ".join(errors))


def flush_outbox(conn: sqlite3.Connection, limit: int = 20) -> None:
    epoch = now_epoch()
    rows = conn.execute(
        """
        SELECT *
        FROM outbox
        WHERE delivered_at_epoch IS NULL
          AND next_attempt_epoch <= ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (epoch, limit),
    ).fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
            response = post_payload(payload)
            delivered_epoch = now_epoch()
            conn.execute(
                """
                UPDATE outbox
                SET delivered_at=?, delivered_at_epoch=?, last_error=NULL
                WHERE id=?
                """,
                (format_ts(delivered_epoch), delivered_epoch, row["id"]),
            )
            print(f"event delivered: {payload.get('event_id')} status={response.get('status')}", flush=True)
        except (IngestDeliveryError, json.JSONDecodeError) as exc:
            delay = min(300, 2 ** min(8, int(row["attempts"])))
            conn.execute(
                """
                UPDATE outbox
                SET attempts=attempts+1, next_attempt_epoch=?, last_error=?
                WHERE id=?
                """,
                (now_epoch() + delay, str(exc), row["id"]),
            )
    conn.commit()


def handle_results(
    conn: sqlite3.Connection,
    probes_by_key: Dict[str, dict],
    states: Dict[str, dict],
    current_results: List[dict],
    probe_ring: Deque[dict],
    syslog_ring: SyslogRing,
) -> None:
    for result in current_results:
        probe = probes_by_key[f"{result['job']}|{result['target']}|{result['module']}"]
        key = target_key(probe)
        previous = states.get(key)
        previous_success = None if previous is None else previous.get("last_success")
        success = int(result.get("success") or 0)
        source_incident_id = None if previous is None else previous.get("source_incident_id")

        if success == 0 and previous_success != 0:
            source_incident_id = latest_open_batch(conn, int(result["sample_epoch"])) or create_batch(
                conn,
                int(result["sample_epoch"]),
            )
            event = build_event(
                conn,
                "started",
                source_incident_id,
                result,
                current_results,
                probe_ring,
                syslog_ring,
            )
            queue_event(conn, event)
            upsert_target_state(conn, probe, 0, source_incident_id)
            states[key] = {
                "target_key": key,
                "last_success": 0,
                "source_incident_id": source_incident_id,
                "last_snapshot_epoch": None,
            }
            print(f"incident started: target={probe['target']} incident={source_incident_id}", flush=True)
            continue

        if success == 1 and previous_success == 0 and source_incident_id:
            event = build_event(
                conn,
                "recovered",
                source_incident_id,
                result,
                current_results,
                probe_ring,
                syslog_ring,
            )
            queue_event(conn, event)
            upsert_target_state(conn, probe, 1, None)
            states[key] = {
                "target_key": key,
                "last_success": 1,
                "source_incident_id": None,
                "last_snapshot_epoch": None,
            }
            print(f"incident recovered: target={probe['target']} incident={source_incident_id}", flush=True)
            continue

        if success == 0 and source_incident_id and SNAPSHOT_INTERVAL_SECONDS > 0:
            last_snapshot = 0 if previous is None else int(previous.get("last_snapshot_epoch") or 0)
            if now_epoch() - last_snapshot >= SNAPSHOT_INTERVAL_SECONDS:
                event = build_event(
                    conn,
                    "snapshot",
                    source_incident_id,
                    result,
                    current_results,
                    probe_ring,
                    syslog_ring,
                )
                queue_event(conn, event)
                upsert_target_state(conn, probe, 0, source_incident_id, now_epoch())
                states[key] = {
                    "target_key": key,
                    "last_success": 0,
                    "source_incident_id": source_incident_id,
                    "last_snapshot_epoch": now_epoch(),
                }
            continue

        upsert_target_state(conn, probe, success, source_incident_id)
        states[key] = {
            "target_key": key,
            "last_success": success,
            "source_incident_id": source_incident_id,
            "last_snapshot_epoch": None if previous is None else previous.get("last_snapshot_epoch"),
        }
    conn.commit()


def append_probe_ring(probe_ring: Deque[dict], results: List[dict]) -> None:
    epoch = now_epoch()
    probe_ring.append(
        {
            "sample_at": format_ts(epoch),
            "sample_epoch": epoch,
            "results": results,
        }
    )
    cutoff = epoch - RING_SECONDS
    while probe_ring and probe_ring[0].get("sample_epoch", 0) < cutoff:
        probe_ring.popleft()


def main() -> int:
    os.makedirs(os.path.dirname(SQLITE_PATH), exist_ok=True)
    conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with DB_LOCK:
        init_db(conn)
        states = load_target_states(conn)
    probes = load_probes()
    probes_by_key = {target_key(probe): probe for probe in probes}
    probe_ring: Deque[dict] = deque()
    syslog_ring = SyslogRing(SYSLOG_UDP_PORT, RING_SECONDS, SYSLOG_RING_MAX_LINES)
    syslog_ring.start()

    print(
        f"pi-incident-agent started: source={SOURCE} blackbox={BLACKBOX_URL} ingest={','.join(DELL_INGEST_URLS)} probes={len(probes)}",
        flush=True,
    )
    try:
        while not STOP:
            try:
                results = probe_once(probes)
                append_probe_ring(probe_ring, results)
                with DB_LOCK:
                    handle_results(conn, probes_by_key, states, results, probe_ring, syslog_ring)
                    flush_outbox(conn)
            except Exception:
                traceback.print_exc()
            for _ in range(INTERVAL_SECONDS):
                if STOP:
                    break
                time.sleep(1)
    finally:
        conn.close()
    print("pi-incident-agent stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
