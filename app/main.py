from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json
import os
import time
import uuid
import platform
import socket
import shutil
import sys
from datetime import datetime


START_TIME = time.time()


def get_cpu_temp_c():
    temp_path = "/sys/class/thermal/thermal_zone0/temp"

    try:
        if os.path.exists(temp_path):
            with open(temp_path, "r", encoding="utf-8") as file:
                raw_temp = file.read().strip()
                return round(int(raw_temp) / 1000, 1)
    except Exception:
        return None

    return None


def get_system_info():
    total, used, free = shutil.disk_usage("/")

    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "machine": platform.machine(),
        "python_version": sys.version.split()[0],
        "uptime_seconds": round(time.time() - START_TIME, 2),
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
    Normalize routes so /health and /health/ behave the same.
    """
    if not path:
        return "/"

    normalized = path.rstrip("/")

    if normalized == "":
        return "/"

    return normalized


class RequestContext:
    def __init__(self, request_id, ip, endpoint, method):
        self.request_id = request_id
        self.ip = ip
        self.endpoint = endpoint
        self.method = method


class ZeroSOCHandler(BaseHTTPRequestHandler):
    def send_json(self, status_code, data, request_id=None):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")

        if request_id:
            self.send_header("X-Request-ID", request_id)

        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def send_success(self, data, request_id=None, status_code=200):
        response = {
            "success": True,
            "data": data
        }

        if request_id:
            response["request_id"] = request_id

        self.send_json(status_code, response, request_id)

    def send_error(self, status_code, message, request_id=None, details=None):
        response = {
            "success": False,
            "error": {
                "message": message,
                "status_code": status_code
            }
        }

        if details:
            response["error"]["details"] = details

        if request_id:
            response["request_id"] = request_id

        self.send_json(status_code, response, request_id)

    def handle_health(self, ctx, query_params):
        self.send_success({
            "status": "ok",
            "service": "ZeroSOC",
            "timestamp": datetime.now().isoformat()
        }, ctx.request_id)

    def handle_status(self, ctx, query_params):
        self.send_success({
            "status": "ok",
            "service": "ZeroSOC",
            "endpoint": "/status",
            "uptime_seconds": round(time.time() - START_TIME, 2),
            "current_time": datetime.now().isoformat()
        }, ctx.request_id)

    def handle_system(self, ctx, query_params):
        self.send_success({
            "status": "ok",
            "service": "ZeroSOC",
            "endpoint": "/system",
            "system": get_system_info()
        }, ctx.request_id)

    def handle_events(self, ctx, query_params):
        self.send_success({
            "events": [],
            "message": "Events endpoint ready. Database integration coming next."
        }, ctx.request_id)

    def handle_devices(self, ctx, query_params):
        self.send_success({
            "devices": [],
            "message": "Devices endpoint ready. Network scanner integration coming next."
        }, ctx.request_id)

    def do_GET(self):
        request_id = str(uuid.uuid4())
        start_time = time.time()

        parsed_path = urlparse(self.path)
        endpoint = normalize_route(parsed_path.path)
        query_params = parse_qs(parsed_path.query)

        ip = self.client_address[0]

        ctx = RequestContext(
            request_id=request_id,
            ip=ip,
            endpoint=endpoint,
            method="GET"
        )

        routes = {
            "/health": self.handle_health,
            "/status": self.handle_status,
            "/system": self.handle_system,
            "/api/v1/events": self.handle_events,
            "/api/v1/devices": self.handle_devices
        }

        handler = routes.get(endpoint)

        if handler is None:
            latency_ms = round((time.time() - start_time) * 1000, 2)

            self.send_error(
                404,
                "Endpoint not found",
                request_id,
                details={
                    "endpoint": endpoint,
                    "latency_ms": latency_ms
                }
            )
            return

        try:
            handler(ctx, query_params)

        except Exception as error:
            latency_ms = round((time.time() - start_time) * 1000, 2)

            self.send_error(
                500,
                "Internal server error",
                request_id,
                details={
                    "endpoint": endpoint,
                    "latency_ms": latency_ms,
                    "error": str(error)
                }
            )


def run_server():
    host = "localhost"
    port = 8000

    server = HTTPServer((host, port), ZeroSOCHandler)

    print(f"ZeroSOC backend running at http://{host}:{port}")
    print("Available endpoints:")
    print("  /health")
    print("  /status")
    print("  /system")
    print("  /api/v1/events")
    print("  /api/v1/devices")

    server.serve_forever()


if __name__ == "__main__":
    run_server()