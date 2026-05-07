from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json
import os
import time
import logging
import uuid
import platform
import socket
import shutil
import sys
import sqlite3
from datetime import datetime


# =========================
# App Config
# =========================

APP_NAME = "ZeroSOC"
API_VERSION = "v1"
START_TIME = time.time()


# =========================
# Database Setup
# =========================

DATA_DIR = "data"
DB_FILE = os.path.join(DATA_DIR, "zerosoc.db")


# =========================
# API Key Authentication
# =========================

API_KEY = os.getenv("ZEROSOC_API_KEY", "dev-zero-soc-key")
API_KEY_HEADER = "X-API-Key"

PROTECTED_ENDPOINTS = {
    "/api/v1/system",
    "/api/v1/logs",
    "/api/v1/logs/recent",
    "/api/v1/events",
    "/api/v1/events/summary",
    "/api/v1/devices",
    "/api/v1/metrics"
}


# =========================
# Logging Config
# =========================

LOG_DIR = "logs"
REQUEST_LOG_FILE = os.path.join(LOG_DIR, "requests.log")

os.makedirs(LOG_DIR, exist_ok=True)

request_logger = logging.getLogger("zerosoc_request_logger")
request_logger.setLevel(logging.INFO)

if not request_logger.handlers:
    file_handler = logging.FileHandler(REQUEST_LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    request_logger.addHandler(file_handler)


# =========================
# Auth Helpers
# =========================

def is_authorized(headers):
    """
    Checks whether the request includes the correct API key.

    Expected header:
    X-API-Key: dev-zero-soc-key
    """
    provided_key = headers.get(API_KEY_HEADER)

    if provided_key is None:
        return False

    return provided_key == API_KEY


# =========================
# System Helpers
# =========================

def get_cpu_temp_c():
    """
    Attempts to read CPU temperature on Raspberry Pi/Linux systems.
    Returns None if temperature is unavailable.
    """
    temp_path = "/sys/class/thermal/thermal_zone0/temp"

    try:
        if os.path.exists(temp_path):
            with open(temp_path, "r", encoding="utf-8") as file:
                raw_temp = file.read().strip()
                return round(int(raw_temp) / 1000, 1)
    except Exception:
        return None

    return None


def get_uptime_seconds():
    return round(time.time() - START_TIME, 2)


def get_status_info():
    """
    Lightweight service status.
    """
    return {
        "status": "ok",
        "service": APP_NAME,
        "api_version": API_VERSION,
        "uptime_seconds": get_uptime_seconds(),
        "current_time": datetime.now().isoformat()
    }

def get_db_connection():
    """
    Opens a connection to the SQLite database.
    """
    os.makedirs(DATA_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    return conn


def init_database():
    """
    Creates required database tables if they do not already exist.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            tag TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_security_event(event):
    """
    Saves a security event to the SQLite database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO security_events (
            id,
            timestamp,
            source_ip,
            event_type,
            severity,
            message,
            tag
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event["id"],
        event["timestamp"],
        event["source"],
        event["event_type"],
        event["severity"],
        event["message"],
        ",".join(event["tags"])
    ))

    conn.commit()
    conn.close()


def get_security_events(limit=50, severity=None, tag=None):
    """
    Reads security events from the SQLite database.
    Supports optional filtering by severity and tag.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            id,
            timestamp,
            source_ip,
            event_type,
            severity,
            message,
            tag
        FROM security_events
    """

    filters = []
    params = []

    if severity:
        filters.append("severity = ?")
        params.append(severity)

    if tag:
        filters.append("tag = ?")
        params.append(tag)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()

    events = []

    for row in rows:
        events.append({
             "id": row["id"],
             "timestamp": row["timestamp"],
             "source_ip": row["source_ip"],
             "event_type": row["event_type"],
             "severity": row["severity"],
             "message": row["message"],
             "tags": row["tag"].split(",") if row["tag"] else []
   })

    conn.close()

    return events

def get_system_info():
    """
    Deeper host/machine health information.
    """
    total, used, free = shutil.disk_usage("/")

    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "machine": platform.machine(),
        "python_version": sys.version.split()[0],
        "uptime_seconds": get_uptime_seconds(),
        "current_time": datetime.now().isoformat(),
        "cpu_temp_c": get_cpu_temp_c(),
        "disk": {
            "total_gb": round(total / (1024 ** 3), 2),
            "used_gb": round(used / (1024 ** 3), 2),
            "free_gb": round(free / (1024 ** 3), 2)
        }
    }


# =========================
# Security Event Helpers
# =========================

def auto_tag_event(event):
    """
    Automatically assigns security tags based on event content.
    """
    tags = set()

    event_type = str(event.get("event_type", "")).lower()
    severity = str(event.get("severity", "")).lower()
    source = str(event.get("source", "")).lower()
    message = str(event.get("message", "")).lower()

    combined_text = f"{event_type} {severity} {source} {message}"

    if severity in ["critical", "high"]:
        tags.add("high-priority")
        tags.add("needs-review")

    if severity == "critical":
        tags.add("critical-severity")

    if severity == "high":
        tags.add("high-severity")

    if severity == "medium":
        tags.add("medium-severity")

    if severity == "low":
        tags.add("low-severity")

    auth_keywords = [
        "login",
        "logon",
        "authentication",
        "auth",
        "password",
        "credential",
        "credentials",
        "signin",
        "sign-in"
    ]

    failed_keywords = [
        "failed",
        "failure",
        "invalid",
        "denied",
        "unauthorized",
        "bad password"
    ]

    if any(keyword in combined_text for keyword in auth_keywords):
        tags.add("authentication")

    if any(keyword in combined_text for keyword in failed_keywords):
        tags.add("failed-attempt")

    if (
        any(keyword in combined_text for keyword in auth_keywords)
        and any(keyword in combined_text for keyword in failed_keywords)
    ):
        tags.add("failed-login")
        tags.add("suspicious")

    network_keywords = [
        "port",
        "scan",
        "nmap",
        "connection",
        "packet",
        "firewall",
        "ssh",
        "http",
        "https",
        "tcp",
        "udp"
    ]

    if any(keyword in combined_text for keyword in network_keywords):
        tags.add("network")

    if "scan" in combined_text or "nmap" in combined_text:
        tags.add("possible-recon")
        tags.add("suspicious")

    if "ssh" in combined_text:
        tags.add("ssh")

    if "firewall" in combined_text:
        tags.add("firewall")

    malware_keywords = [
        "malware",
        "virus",
        "trojan",
        "ransomware",
        "payload",
        "backdoor",
        "exploit",
        "shell",
        "reverse shell"
    ]

    if any(keyword in combined_text for keyword in malware_keywords):
        tags.add("malware-related")
        tags.add("threat")
        tags.add("needs-review")

    if "ransomware" in combined_text:
        tags.add("ransomware")

    if "reverse shell" in combined_text:
        tags.add("reverse-shell")
        tags.add("critical-signal")

    system_keywords = [
        "cpu",
        "memory",
        "disk",
        "temperature",
        "system",
        "uptime",
        "service",
        "process"
    ]

    if any(keyword in combined_text for keyword in system_keywords):
        tags.add("system")

    if "temperature" in combined_text or "cpu temp" in combined_text:
        tags.add("hardware-health")

    if "disk" in combined_text:
        tags.add("storage")

    if source:
        tags.add(f"source:{source}")

    if event_type:
        tags.add(f"type:{event_type}")

    return sorted(tags)


def create_security_event(event_type, severity, source, message, metadata=None):
    """
    Creates a structured security event and stores it in SQLite.
    """
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "message": message,
        "metadata": metadata or {}
    }

    event["tags"] = auto_tag_event(event)

    save_security_event(event)

    return event


def get_security_event_summary():
    """
    Builds a security event summary from SQLite.
    """
    severity_counts = {}
    source_counts = {}
    tag_counts = {}
    event_type_counts = {}

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            event_type,
            severity,
            tag
        FROM security_events
    """)

    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        severity = row["severity"] or "unknown"
        source_ip = row["source_ip"] or "unknown"
        event_type = row["event_type"] or "unknown"
        tags = row["tag"].split(",") if row["tag"] else []

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        source_counts[source_ip] = source_counts.get(source_ip, 0) + 1
        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1

        for tag in tags:
            tag = tag.strip()

            if not tag:
                continue

            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    return {
        "total_events": len(rows),
        "severity_counts": severity_counts,
        "source_counts": source_counts,
        "event_type_counts": event_type_counts,
        "tag_counts": tag_counts
    }


# =========================
# Route Helpers
# =========================

def normalize_route(path):
    """
    Normalizes incoming routes so /health and /health/ match the same handler.
    """
    if not path:
        return "/"

    normalized = path.rstrip("/")

    if normalized == "":
        return "/"

    return normalized


# =========================
# Request Context + Logging
# =========================

class RequestContext:
    def __init__(self, request_id, method, endpoint, client_ip, start_time):
        self.request_id = request_id
        self.method = method
        self.endpoint = endpoint
        self.client_ip = client_ip
        self.start_time = start_time


def log_request(ctx, status_code, message):
    latency_ms = round((time.time() - ctx.start_time) * 1000, 2)

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "request_id": ctx.request_id,
        "method": ctx.method,
        "endpoint": ctx.endpoint,
        "client_ip": ctx.client_ip,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "message": message
    }

    request_logger.info(json.dumps(log_entry))


def get_recent_logs(limit=10):
    if not os.path.exists(REQUEST_LOG_FILE):
        return []

    try:
        with open(REQUEST_LOG_FILE, "r", encoding="utf-8") as file:
            lines = file.readlines()

        recent_lines = lines[-limit:]
        logs = []

        for line in recent_lines:
            line = line.strip()

            if not line:
                continue

            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                logs.append({
                    "raw": line,
                    "parse_error": True
                })

        return logs

    except Exception as error:
        return [{
            "error": "Unable to read request logs",
            "details": str(error)
        }]


def get_request_metrics():
    if not os.path.exists(REQUEST_LOG_FILE):
        return {
            "total_requests_logged": 0,
            "status_code_counts": {},
            "recent_error_count": 0,
            "average_latency_ms": 0
        }

    status_code_counts = {}
    error_count = 0
    total_latency = 0
    latency_count = 0
    total_requests = 0

    try:
        with open(REQUEST_LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total_requests += 1

                status_code = str(entry.get("status_code", "unknown"))
                status_code_counts[status_code] = status_code_counts.get(status_code, 0) + 1

                if status_code.startswith("4") or status_code.startswith("5"):
                    error_count += 1

                latency = entry.get("latency_ms")

                if isinstance(latency, int) or isinstance(latency, float):
                    total_latency += latency
                    latency_count += 1

        average_latency = 0

        if latency_count > 0:
            average_latency = round(total_latency / latency_count, 2)

        return {
            "total_requests_logged": total_requests,
            "status_code_counts": status_code_counts,
            "recent_error_count": error_count,
            "average_latency_ms": average_latency
        }

    except Exception as error:
        return {
            "error": "Unable to calculate request metrics",
            "details": str(error)
        }


# =========================
# Request Handler
# =========================

class ZeroSOCHandler(BaseHTTPRequestHandler):
    def send_json(self, status_code, data, request_id=None):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")

        if request_id:
            self.send_header("X-Request-ID", request_id)

        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def read_json_body(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))

            if content_length <= 0:
                return {}

            body = self.rfile.read(content_length)
            return json.loads(body.decode("utf-8"))

        except json.JSONDecodeError:
            return None
        except Exception:
            return None

    def reject_unauthorized(self, ctx):
        log_request(ctx, 401, "Unauthorized request blocked")

        create_security_event(
            event_type="unauthorized_request",
            severity="medium",
            source=ctx.client_ip,
            message=f"Unauthorized request blocked for endpoint: {ctx.endpoint}",
            metadata={
                "method": ctx.method,
                "endpoint": ctx.endpoint
            }
        )

        self.send_json(401, {
            "status": "error",
            "service": APP_NAME,
            "api_version": API_VERSION,
            "error": "Unauthorized",
            "message": "Missing or invalid API key",
            "request_id": ctx.request_id
        }, ctx.request_id)

    def handle_health(self, ctx):
        log_request(ctx, 200, "Health check requested")

        self.send_json(200, {
            "status": "ok",
            "service": APP_NAME,
            "api_version": API_VERSION,
            "endpoint": ctx.endpoint,
            "message": "ZeroSOC backend is running",
            "current_time": datetime.now().isoformat(),
            "request_id": ctx.request_id
        }, ctx.request_id)

    def handle_status(self, ctx):
        log_request(ctx, 200, "Status requested")

        self.send_json(200, {
            "endpoint": ctx.endpoint,
            "data": get_status_info(),
            "request_id": ctx.request_id
        }, ctx.request_id)

    def handle_system(self, ctx):
        log_request(ctx, 200, "System information requested")

        self.send_json(200, {
            "endpoint": ctx.endpoint,
            "data": get_system_info(),
            "request_id": ctx.request_id
        }, ctx.request_id)

    def handle_events(self, ctx):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)

        severity = query_params.get("severity", [None])[0]
        tag = query_params.get("tag", [None])[0]
        limit_raw = query_params.get("limit", ["50"])[0]

        try:
            limit = int(limit_raw)
        except ValueError:
            limit = 50

        if limit < 1:
            limit = 50

        if limit > 100:
            limit = 100

        events = get_security_events(
            limit=limit,
            severity=severity,
            tag=tag
        )

        log_request(ctx, 200, "Security events requested from SQLite")

        self.send_json(200, {
            "endpoint": ctx.endpoint,
            "data": {
                "count": len(events),
                "limit": limit,
                "filters": {
                    "severity": severity,
                    "tag": tag
                },
                "events": events
            },
            "request_id": ctx.request_id
        }, ctx.request_id)

    def handle_events_summary(self, ctx):
        summary = get_security_event_summary()

        log_request(ctx, 200, "Security event summary requested")

        self.send_json(200, {
            "endpoint": ctx.endpoint,
            "data": summary,
            "request_id": ctx.request_id
        }, ctx.request_id)

    def handle_devices(self, ctx):
        log_request(ctx, 200, "Devices endpoint requested")

        self.send_json(200, {
            "endpoint": ctx.endpoint,
            "data": {
                "devices": [],
                "message": "Devices endpoint ready. Network scanner integration coming next."
            },
            "request_id": ctx.request_id
        }, ctx.request_id)

    def handle_recent_logs(self, ctx):
        logs = get_recent_logs(limit=10)

        log_request(ctx, 200, "Recent logs requested")

        self.send_json(200, {
            "endpoint": ctx.endpoint,
            "data": {
                "count": len(logs),
                "logs": logs
            },
            "request_id": ctx.request_id
        }, ctx.request_id)

    def handle_metrics(self, ctx):
        metrics = get_request_metrics()

        log_request(ctx, 200, "Metrics requested")

        self.send_json(200, {
            "endpoint": ctx.endpoint,
            "data": metrics,
            "request_id": ctx.request_id
        }, ctx.request_id)

    def do_GET(self):
        start_time = time.time()
        request_id = str(uuid.uuid4())

        parsed_path = urlparse(self.path)
        endpoint = normalize_route(parsed_path.path)
        client_ip = self.client_address[0]

        ctx = RequestContext(
            request_id=request_id,
            method="GET",
            endpoint=endpoint,
            client_ip=client_ip,
            start_time=start_time
        )

        if endpoint in PROTECTED_ENDPOINTS and not is_authorized(self.headers):
            self.reject_unauthorized(ctx)
            return

        routes = {
            "/health": self.handle_health,
            "/api/v1/health": self.handle_health,

            "/status": self.handle_status,
            "/api/v1/status": self.handle_status,

            "/system": self.handle_system,
            "/api/v1/system": self.handle_system,

            "/api/v1/events": self.handle_events,
            "/api/v1/events/summary": self.handle_events_summary,
            "/api/v1/devices": self.handle_devices,
            "/api/v1/logs/recent": self.handle_recent_logs,
            "/api/v1/metrics": self.handle_metrics,
        }

        handler = routes.get(endpoint)

        if handler is None:
            log_request(ctx, 404, "Endpoint not found")

            create_security_event(
                event_type="unknown_endpoint",
                severity="low",
                source=client_ip,
                message=f"Unknown GET endpoint requested: {endpoint}",
                metadata={
                    "method": "GET",
                    "path": endpoint
                }
            )

            self.send_json(404, {
                "status": "error",
                "service": APP_NAME,
                "api_version": API_VERSION,
                "error": "Endpoint not found",
                "path": endpoint,
                "request_id": request_id
            }, request_id)
            return

        try:
            handler(ctx)

        except Exception as error:
            log_request(ctx, 500, f"Internal server error: {str(error)}")

            self.send_json(500, {
                "status": "error",
                "service": APP_NAME,
                "api_version": API_VERSION,
                "error": "Internal server error",
                "path": endpoint,
                "details": str(error),
                "request_id": request_id
            }, request_id)

    def do_POST(self):
        start_time = time.time()
        request_id = str(uuid.uuid4())

        parsed_path = urlparse(self.path)
        endpoint = normalize_route(parsed_path.path)
        client_ip = self.client_address[0]

        ctx = RequestContext(
            request_id=request_id,
            method="POST",
            endpoint=endpoint,
            client_ip=client_ip,
            start_time=start_time
        )

        if endpoint in PROTECTED_ENDPOINTS and not is_authorized(self.headers):
            self.reject_unauthorized(ctx)
            return

        if endpoint == "/api/v1/events":
            body = self.read_json_body()

            if body is None:
                log_request(ctx, 400, "Invalid JSON body")

                self.send_json(400, {
                    "status": "error",
                    "service": APP_NAME,
                    "api_version": API_VERSION,
                    "error": "Invalid JSON body",
                    "request_id": request_id
                }, request_id)
                return

            event_type = body.get("event_type")
            severity = body.get("severity", "low")
            source = body.get("source", client_ip)
            message = body.get("message")
            metadata = body.get("metadata", {})

            if not event_type or not message:
                log_request(ctx, 400, "Missing required event fields")

                self.send_json(400, {
                    "status": "error",
                    "service": APP_NAME,
                    "api_version": API_VERSION,
                    "error": "Missing required fields",
                    "required": ["event_type", "message"],
                    "optional": ["severity", "source", "metadata"],
                    "request_id": request_id
                }, request_id)
                return

            allowed_severities = ["low", "medium", "high", "critical"]
            severity = str(severity).lower()

            if severity not in allowed_severities:
                log_request(ctx, 400, f"Invalid severity: {severity}")

                self.send_json(400, {
                    "status": "error",
                    "service": APP_NAME,
                    "api_version": API_VERSION,
                    "error": "Invalid severity",
                    "allowed": allowed_severities,
                    "request_id": request_id
                }, request_id)
                return

            if not isinstance(metadata, dict):
                log_request(ctx, 400, "Invalid metadata format")

                self.send_json(400, {
                    "status": "error",
                    "service": APP_NAME,
                    "api_version": API_VERSION,
                    "error": "metadata must be a JSON object",
                    "request_id": request_id
                }, request_id)
                return

            event = create_security_event(
                event_type=event_type,
                severity=severity,
                source=source,
                message=message,
                metadata=metadata
            )

            log_request(ctx, 201, f"Security event created: {event_type}")

            self.send_json(201, {
                "status": "created",
                "service": APP_NAME,
                "api_version": API_VERSION,
                "message": "Security event created",
                "event": event,
                "request_id": request_id
            }, request_id)
            return

        log_request(ctx, 404, "POST endpoint not found")

        create_security_event(
            event_type="unknown_post_endpoint",
            severity="low",
            source=client_ip,
            message=f"Unknown POST endpoint requested: {endpoint}",
            metadata={
                "method": "POST",
                "path": endpoint
            }
        )

        self.send_json(404, {
            "status": "error",
            "service": APP_NAME,
            "api_version": API_VERSION,
            "error": "Endpoint not found",
            "path": endpoint,
            "request_id": request_id
        }, request_id)


# =========================
# Server Runner
# =========================

def run_server():
    host = "localhost"
    port = 8000

    server = HTTPServer((host, port), ZeroSOCHandler)

    print(f"{APP_NAME} backend running at http://{host}:{port}")
    print("Available endpoints:")
    print("  /health")
    print("  /status")
    print("  /system")
    print("  /api/v1/health")
    print("  /api/v1/status")
    print("  /api/v1/system")
    print("  /api/v1/events")
    print("  /api/v1/events/summary")
    print("  /api/v1/devices")
    print("  /api/v1/logs/recent")
    print("  /api/v1/metrics")
    print("")
    print("Protected endpoints require header:")
    print(f"  {API_KEY_HEADER}: {API_KEY}")

    server.serve_forever()


if __name__ == "__main__":
    init_database()

    server = HTTPServer(("0.0.0.0", 8000), ZeroSOCHandler)
    print("ZeroSOC backend running on http://0.0.0.0:8000")
    print(f"SQLite database: {DB_FILE}")
    server.serve_forever()