from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import platform
import sys
import time
from datetime import datetime


START_TIME = time.time()


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
            uptime_seconds = round(time.time() - START_TIME, 2)

            self.send_json(200, {
                "status": "ok",
                "service": "ZeroSOC",
                "system": {
                    "platform": platform.system(),
                    "platform_version": platform.version(),
                    "python_version": sys.version.split()[0],
                    "uptime_seconds": uptime_seconds,
                    "current_time": datetime.now().isoformat()
                }
            })
            return

        self.send_json(404, {
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

    server.serve_forever()


if __name__ == "__main__":
    run_server()