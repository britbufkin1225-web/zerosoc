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


# =========================
# App Config
# =========================

APP_NAME = "ZeroSOC"
API_VERSION = "v1"
START_TIME = time.time()


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
        log_request(ctx, 200, "Events endpoint requested")

        self.send_json(200, {
            "endpoint": ctx.endpoint,
            "data": {
                "events": [],
                "message": "Events endpoint ready. Database integration coming next."
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

    def do_GET(self):
        start_time = time.time()
        request_id = str(uuid.uuid4())
        path = normalize_route(self.path)
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