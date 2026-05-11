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
import subprocess
import ipaddress
import re
from datetime import datetime


# =========================
# App Config
# =========================

APP_NAME = "ZeroSOC"
API_VERSION = "v1"
START_TIME = time.time()


# =========================
# Network Scanner Settings
# =========================

SCAN_TIMEOUT_SECONDS = 1
MAX_SCAN_HOSTS = 254


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
    "/api/v1/network/scan",
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            hostname TEXT,
            status TEXT NOT NULL,
            mac_address TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
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
        filters.append("tag LIKE ?")
        params.append(f"%{tag}%")

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

def get_security_event_by_id(event_id):
    """
    Reads one security event from SQLite by ID.
    Returns None if the event does not exist.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            event_type,
            severity,
            message,
            tag
        FROM security_events
        WHERE id = ?
    """, (event_id,))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "source_ip": row["source_ip"],
        "event_type": row["event_type"],
        "severity": row["severity"],
        "message": row["message"],
        "tags": row["tag"].split(",") if row["tag"] else []
    }

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

    if "unknown device" in combined_text:
        tags.add("unknown-device")
        tags.add("suspicious")
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
# Network Scanner Helpers
# =========================

def get_arp_table():
    """
    Reads the local ARP table and returns a dictionary mapping:
    IP address -> MAC address
    """
    arp_entries = {}

    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5
        )

        output = result.stdout

        for line in output.splitlines():
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac_match = re.search(
                r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}",
                line
            )

            if ip_match and mac_match:
                ip_address = ip_match.group(1)
                mac_address = mac_match.group(0).replace("-", ":").lower()

                arp_entries[ip_address] = mac_address

    except Exception:
        return {}

    return arp_entries


def get_local_ip():
    """
    Finds the local IP address of the machine running ZeroSOC.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_local_network():
    """
    Builds a /24 network range from the local IP.
    Example:
    192.168.1.45 -> 192.168.1.0/24
    """
    local_ip = get_local_ip()

    if local_ip == "127.0.0.1":
        return None

    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return network


def ping_host(ip_address):
    """
    Pings one host and returns True if it responds.
    Works on Windows, Linux, macOS, and Raspberry Pi OS.
    """
    system_name = platform.system().lower()

    if system_name == "windows":
        command = [
            "ping",
            "-n",
            "1",
            "-w",
            str(SCAN_TIMEOUT_SECONDS * 1000),
            ip_address
        ]
    else:
        command = [
            "ping",
            "-c",
            "1",
            "-W",
            str(SCAN_TIMEOUT_SECONDS),
            ip_address
        ]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0
    except Exception:
        return False


def get_hostname_for_ip(ip_address):
    """
    Attempts to resolve a hostname from an IP address.
    Returns None if unavailable.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except Exception:
        return None


def scan_network():
    """
    Scans the local /24 network and returns active devices.
    Adds MAC addresses from the local ARP table when available.
    """
    network = get_local_network()

    if network is None:
        return {
            "error": "Unable to determine local network",
            "devices": []
        }

    devices = []

    for host in list(network.hosts())[:MAX_SCAN_HOSTS]:
        ip_address = str(host)

        if ping_host(ip_address):
            hostname = get_hostname_for_ip(ip_address)

            devices.append({
                "ip_address": ip_address,
                "hostname": hostname,
                "status": "online",
                "mac_address": None,
                "last_seen": datetime.now().isoformat()
            })

    arp_table = get_arp_table()

    for device in devices:
        ip_address = device["ip_address"]
        device["mac_address"] = arp_table.get(ip_address)

    return {
        "network": str(network),
        "device_count": len(devices),
        "devices": devices
    }

def save_network_devices(devices):
    """
    Saves discovered devices to SQLite.
    If the device already exists, updates last_seen.
    """
    arp_table = get_arp_table()
    now = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    for device in devices:
        ip_address = device.get("ip_address")
        hostname = device.get("hostname")
        status = device.get("status", "online")
        mac_address = device.get("mac_address") or get_arp_table().get(ip_address)

        cursor.execute(
            "SELECT id FROM network_devices WHERE ip_address = ?",
            (ip_address,)
        )

        existing_device = cursor.fetchone()

        if existing_device:
            cursor.execute("""
                UPDATE network_devices
                SET hostname = ?, status = ?, mac_address = ?, last_seen = ?
                WHERE ip_address = ?
            """, (
                hostname,
                status,
                mac_address,
                now,
                ip_address
            ))
        else:
            cursor.execute("""
                INSERT INTO network_devices (
                    ip_address,
                    hostname,
                    status,
                    mac_address,
                    first_seen,
                    last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ip_address,
                hostname,
                status,
                mac_address,
                now,
                now
            ))

    conn.commit()
    conn.close()

def process_network_devices(devices):
    """
    Checks scanned devices against SQLite.
    New devices are saved first.
    Security events are created after the device database write is complete.
    This avoids SQLite database locking.
    """
    now = datetime.now().isoformat()
    unknown_devices = []
    processed_devices = []
    events_to_create = []

    conn = get_db_connection()
    cursor = conn.cursor()

    for device in devices:
        ip_address = device.get("ip_address")
        hostname = device.get("hostname")
        status = device.get("status", "online")
        mac_address = device.get("mac_address")

        existing_device = None

        if mac_address:
            cursor.execute("""
                SELECT id FROM network_devices
                WHERE mac_address = ?
            """, (mac_address,))
            existing_device = cursor.fetchone()

        if existing_device is None and ip_address:
            cursor.execute("""
                SELECT id FROM network_devices
                WHERE ip_address = ?
            """, (ip_address,))
            existing_device = cursor.fetchone()

        if existing_device is None:
            device["known"] = False
            device["device_status"] = "new"

            unknown_devices.append(device)

            events_to_create.append({
                "event_type": "unknown-device",
                "severity": "medium",
                "source": "network-scanner",
                "message": (
                    f"Unknown device detected on network: "
                    f"IP={ip_address}, MAC={mac_address}, HOSTNAME={hostname}"
                ),
                "metadata": {
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "hostname": hostname
                }
            })

            cursor.execute("""
                INSERT INTO network_devices (
                    ip_address,
                    hostname,
                    status,
                    mac_address,
                    first_seen,
                    last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ip_address,
                hostname,
                status,
                mac_address,
                now,
                now
            ))

        else:
            device["known"] = True
            device["device_status"] = "known"

            cursor.execute("""
                UPDATE network_devices
                SET hostname = ?, status = ?, mac_address = ?, last_seen = ?
                WHERE ip_address = ? OR mac_address = ?
            """, (
                hostname,
                status,
                mac_address,
                now,
                ip_address,
                mac_address
            ))

        processed_devices.append(device)

    conn.commit()
    conn.close()

    for event_data in events_to_create:
        create_security_event(
            event_type=event_data["event_type"],
            severity=event_data["severity"],
            source=event_data["source"],
            message=event_data["message"],
            metadata=event_data["metadata"]
        )

    return {
        "devices": processed_devices,
        "unknown_devices": unknown_devices
    }

def get_recent_network_devices(limit=50):
    """
    Returns recently seen network devices from SQLite.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            ip_address,
            hostname,
            status,
            mac_address,
            first_seen,
            last_seen
        FROM network_devices
        ORDER BY last_seen DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    devices = []

    for row in rows:
        devices.append({
            "ip_address": row["ip_address"],
            "hostname": row["hostname"],
            "status": row["status"],
            "mac_address": row["mac_address"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"]
        })

    return devices

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
# POST Route Handlers
# =========================

def handle_create_event(handler, ctx, data):
    """
    Handles POST /api/v1/events.
    Creates a new security event.
    """
    event_type = data.get("event_type", "manual")
    severity = data.get("severity", "low")
    message = data.get("message", "No message provided")
    source = data.get("source", "api")

    event = create_security_event(
        event_type=event_type,
        severity=severity,
        source=source,
        message=message
    )

    log_request(ctx, 201, "Security event created")

    handler.send_json_response(201, {
        "status": "created",
        "event": event
    })


def handle_unknown_post_route(handler, ctx):
    """
    Handles unknown POST routes.
    """
    log_request(ctx, 404, "POST endpoint not found")

    handler.send_json_response(404, {
        "error": "POST endpoint not found",
        "endpoint": ctx.endpoint
    })


# =========================
# Request Handler
# =========================

# =========================
# Request Handler
# =========================

class ZeroSOCHandler(BaseHTTPRequestHandler):
    def send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def handle_health(self):
        self.send_json(200, {
            "status": "ok",
            "service": APP_NAME,
            "api_version": API_VERSION,
            "endpoint": self.path,
            "message": "ZeroSOC backend is running",
            "current_time": datetime.now().isoformat()
        })

    def handle_status(self):
        self.send_json(200, {
            "endpoint": self.path,
            "data": get_status_info()
        })

    def handle_system(self):
        self.send_json(200, {
            "endpoint": self.path,
            "data": get_system_info()
        })

    def handle_not_found(self):
        self.send_json(404, {
            "status": "error",
            "service": APP_NAME,
            "api_version": API_VERSION,
            "error": "Endpoint not found",
            "path": self.path
        })

    def get_routes(self):
        return {
            "/health": self.handle_health,
            "/status": self.handle_status,
            "/system": self.handle_system,
            "/api/v1/health": self.handle_health,
            "/api/v1/status": self.handle_status,
            "/api/v1/system": self.handle_system
        }

    def do_GET(self):
        routes = self.get_routes()
        handler = routes.get(self.path)

        if handler is None:
            self.handle_not_found()
            return

        handler()
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
    print("  /api/v1/events/{id}")
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