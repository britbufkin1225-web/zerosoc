from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import time
import logging
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
                "service": "ZeroSOC",
                "timestamp": datetime.now().isoformat()
            })
            return

        if self.path == "/status":
            self.send_json(200, {
                "status": "ok",
                "service": "ZeroSOC",
                "endpoint": "/status",
                "uptime_seconds": round(time.time() - START_TIME, 2),
                "current_time": datetime.now().isoformat()
        })
            return

        if self.path == "/system":
            self.send_json(200, {
                "status": "ok",
                "service": "ZeroSOC",
                "endpoint": "/system",
                "system": get_system_info()
            })
            return

        self.send_json(404, {
            "status": "error",
            "error": "Endpoint not found"
        })


def run_server():
    host = "localhost"
    port = 8000

    server = HTTPServer((host, port), ZeroSOCHandler)

    print(f"ZeroSOC backend running at http://{host}:{port}")
    print("Available endpoints:")
    print("  /health")
    print("  /status")
    print("  /system")

    server.serve_forever()


if __name__ == "__main__":
    run_server()