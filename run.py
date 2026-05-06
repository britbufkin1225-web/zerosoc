from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import time
import platform
import socket
import shutil
import sys
from datetime import datetime


# =========================
# App Config
# =========================

APP_NAME = "ZeroSOC"
API_VERSION = "v1"
START_TIME = time.time()


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


# =========================
# Request Handler
# =========================

class ZeroSOCHandler(BaseHTTPRequestHandler):
    def send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {
                "status": "ok",
                "service": APP_NAME,
                "message": "ZeroSOC backend is running",
                "current_time": datetime.now().isoformat()
            })
            return

        if self.path == "/status":
            self.send_json(200, {
                "endpoint": "/status",
                "data": get_status_info()
            })
            return

        if self.path == "/system":
            self.send_json(200, {
                "endpoint": "/system",
                "data": get_system_info()
            })
            return

        self.send_json(404, {
            "status": "error",
            "error": "Endpoint not found",
            "path": self.path
        })


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

    server.serve_forever()


if __name__ == "__main__":
    run_server()