from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime


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

        self.send_json(404, {
            "error": "Endpoint not found"
        })


def run_server():
    host = "localhost"
    port = 8000

    server = HTTPServer((host, port), ZeroSOCHandler)

    print(f"ZeroSOC backend running at http://{host}:{port}")
    print("Available endpoint: /health")

    server.serve_forever()


if __name__ == "__main__":
    run_server()