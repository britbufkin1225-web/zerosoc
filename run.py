from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import time
import platform
import socket
import shutil
import sys
import logging
import uuid
from datetime import datetime
from urllib.parse import urlparse, parse_qs


# =========================
# App Config
# =========================

APP_NAME = "ZeroSOC"
API_VERSION = "v1"
START_TIME = time.time()


# =========================
# In-Memory Security Events
# =========================

SECURITY_EVENTS = []
MAX_SECURITY_EVENTS = 100


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
    This is for checking if the backend service is alive.
    """
    return {
        "status": "ok",
        "service": APP_NAME,
        "api_version": API_VERSION,
        "uptime_seconds": get_uptime_seconds(),
        "current_time": datetime.now().isoformat()
    }


def create_security_event(event_type, severity, source, message, metadata=None):
    """
    Creates a structured security event and stores it in memory.
    Keeps only the most recent MAX_SECURITY_EVENTS events.
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

    SECURITY_EVENTS.append(event)

    if len(SECURITY_EVENTS) > MAX_SECURITY_EVENTS:
        SECURITY_EVENTS.pop(0)

    return event


def get_system_info():
    """
    Deeper host/machine health information.
    This is heavier than /status and belongs under /system.
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
    """
    Reads the most recent structured request logs.
    Returns an empty list if the log file does not exist yet.
    """
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
    """
    Builds basic request metrics from the structured request log file.
    """
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
        """
        Safely reads and parses a JSON request body.
        Returns an empty dictionary if the body is missing.
        Returns None if the body is invalid JSON.
        """
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

        severity_filter = query_params.get("severity", [None])[0]
        limit = query_params.get("limit", [10])[0]

        try:
            limit = int(limit)
        except ValueError:
            limit = 10

        if limit < 1:
            limit = 1

        if limit > MAX_SECURITY_EVENTS:
            limit = MAX_SECURITY_EVENTS

        events = SECURITY_EVENTS

        if severity_filter:
            events = [
                event for event in events
                if event.get("severity") == severity_filter
            ]

        recent_events = events[-limit:]

        log_request(ctx, 200, "Security events requested")

        self.send_json(200, {
            "endpoint": ctx.endpoint,
            "data": {
                "count": len(recent_events),
                "total_stored": len(SECURITY_EVENTS),
                "max_stored": MAX_SECURITY_EVENTS,
                "severity_filter": severity_filter,
                "events": recent_events
            },
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

        self.send_json(404, {
            "status": "error",
            "service": APP_NAME,
            "api_version": API_VERSION,
            "error": "Endpoint not found",
            "path": endpoint,
            "request_id": request_id
        }, request_id)

    def do_GET(self):
        start_time = time.time()
        request_id = str(uuid.uuid4())

        parsed_path = urlparse(self.path)
        path = normalize_route(parsed_path.path)
        client_ip = self.client_address[0]

        ctx = RequestContext(
            request_id=request_id,
            method="GET",
            endpoint=path,
            client_ip=client_ip,
            start_time=start_time
        )

        routes = {
            "/health": self.handle_health,
            "/api/v1/health": self.handle_health,

            "/status": self.handle_status,
            "/api/v1/status": self.handle_status,

            "/system": self.handle_system,
            "/api/v1/system": self.handle_system,

            "/api/v1/events": self.handle_events,
            "/api/v1/devices": self.handle_devices,
            "/api/v1/logs/recent": self.handle_recent_logs,
            "/api/v1/metrics": self.handle_metrics,
        }

        handler = routes.get(path)

        if handler is None:
            log_request(ctx, 404, "Endpoint not found")

            self.send_json(404, {
                "status": "error",
                "service": APP_NAME,
                "api_version": API_VERSION,
                "error": "Endpoint not found",
                "path": path,
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
                "path": path,
                "details": str(error),
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
    print("  /api/v1/devices")
    print("  /api/v1/logs/recent")
    print("  /api/v1/metrics")

    server.serve_forever()


if __name__ == "__main__":
    run_server()