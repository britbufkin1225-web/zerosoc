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
    "/api/v1/alerts",
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            request_id TEXT NOT NULL,
            method TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            latency_ms REAL NOT NULL,
            message TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp
        ON request_logs (timestamp)
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

    try:
        limit = int(limit)
    except ValueError:
        limit = 50

    limit = max(1, min(limit, 100))

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

def get_events_summary():
    """
    Builds a summary of stored security events.
    Returns total events, counts by severity, counts by event type,
    counts by individual tag, and latest event.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    summary = {
        "total_events": 0,
        "by_severity": {},
        "by_event_type": {},
        "by_tag": {},
        "latest_event": None
    }

    try:
        # Total event count
        cursor.execute("SELECT COUNT(*) AS total FROM security_events")
        row = cursor.fetchone()
        summary["total_events"] = row["total"] if row else 0

        # Count by severity
        cursor.execute("""
            SELECT severity, COUNT(*) AS count
            FROM security_events
            GROUP BY severity
        """)
        for row in cursor.fetchall():
            severity = row["severity"] or "unknown"
            summary["by_severity"][severity] = row["count"]

        # Count by event type
        cursor.execute("""
            SELECT event_type, COUNT(*) AS count
            FROM security_events
            GROUP BY event_type
        """)
        for row in cursor.fetchall():
            event_type = row["event_type"] or "unknown"
            summary["by_event_type"][event_type] = row["count"]

        # Count individual tags
        cursor.execute("""
            SELECT tag
            FROM security_events
            WHERE tag IS NOT NULL AND tag != ''
        """)
        for row in cursor.fetchall():
            raw_tag = row["tag"]

            tags = [tag.strip() for tag in raw_tag.split(",") if tag.strip()]

            for tag in tags:
                summary["by_tag"][tag] = summary["by_tag"].get(tag, 0) + 1

        # Latest event
        cursor.execute("""
            SELECT id, timestamp, event_type, severity, tag, message
            FROM security_events
            ORDER BY timestamp DESC
            LIMIT 1
        """)
        latest = cursor.fetchone()

        if latest:
            summary["latest_event"] = {
                "id": latest["id"],
                "timestamp": latest["timestamp"],
                "event_type": latest["event_type"],
                "severity": latest["severity"],
                "tag": latest["tag"],
                "message": latest["message"]
            }

    finally:
        conn.close()

    return summary


def get_alerts(limit=20):
    """
    Builds active alerts from high-priority security events.
    Alerts are derived from high/critical severity events and events tagged
    for review so they stay in sync with the event store.
    """
    try:
        limit = int(limit)
    except ValueError:
        limit = 20

    limit = max(1, min(limit, 100))

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
        WHERE severity IN ('critical', 'high')
           OR tag LIKE '%needs-review%'
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    alerts = []

    for row in rows:
        tags = row["tag"].split(",") if row["tag"] else []

        alerts.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "event_type": row["event_type"],
            "severity": row["severity"],
            "message": row["message"],
            "tags": tags,
            "status": "open"
        })

    return alerts


def get_alert_summary(alerts):
    severity_counts = {}

    for alert in alerts:
        severity = alert.get("severity") or "unknown"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "total_alerts": len(alerts),
        "open_alerts": len(alerts),
        "severity_counts": severity_counts
    }


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
    save_request_log(log_entry)


def save_request_log(log_entry):
    """
    Stores one request log entry in SQLite.
    File logging remains the fallback source if this table is unavailable.
    """
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO request_logs (
                timestamp,
                request_id,
                method,
                endpoint,
                client_ip,
                status_code,
                latency_ms,
                message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_entry["timestamp"],
            log_entry["request_id"],
            log_entry["method"],
            log_entry["endpoint"],
            log_entry["client_ip"],
            log_entry["status_code"],
            log_entry["latency_ms"],
            log_entry["message"]
        ))

        conn.commit()
    except sqlite3.Error:
        return
    finally:
        if conn:
            conn.close()


def get_recent_logs_from_db(limit=10):
    try:
        limit = int(limit)
    except ValueError:
        limit = 10

    limit = max(1, min(limit, 100))

    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                timestamp,
                request_id,
                method,
                endpoint,
                client_ip,
                status_code,
                latency_ms,
                message
            FROM request_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
    except sqlite3.Error:
        return None
    finally:
        if conn:
            conn.close()

    logs = []

    for row in reversed(rows):
        logs.append({
            "timestamp": row["timestamp"],
            "request_id": row["request_id"],
            "method": row["method"],
            "endpoint": row["endpoint"],
            "client_ip": row["client_ip"],
            "status_code": row["status_code"],
            "latency_ms": row["latency_ms"],
            "message": row["message"]
        })

    return logs


def get_recent_logs(limit=10):
    db_logs = get_recent_logs_from_db(limit=limit)

    if db_logs is not None and (db_logs or not os.path.exists(REQUEST_LOG_FILE)):
        return db_logs

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


def empty_request_metrics():
    return {
        "total_requests_logged": 0,
        "status_code_counts": {},
        "recent_error_count": 0,
        "average_latency_ms": 0
    }


def get_request_metrics_from_db():
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT status_code, latency_ms
            FROM request_logs
        """)

        rows = cursor.fetchall()
    except sqlite3.Error:
        return None
    finally:
        if conn:
            conn.close()

    if not rows:
        return empty_request_metrics()

    status_code_counts = {}
    error_count = 0
    total_latency = 0
    latency_count = 0

    for row in rows:
        status_code = str(row["status_code"])
        status_code_counts[status_code] = status_code_counts.get(status_code, 0) + 1

        if status_code.startswith("4") or status_code.startswith("5"):
            error_count += 1

        latency = row["latency_ms"]

        if isinstance(latency, int) or isinstance(latency, float):
            total_latency += latency
            latency_count += 1

    average_latency = 0

    if latency_count > 0:
        average_latency = round(total_latency / latency_count, 2)

    return {
        "total_requests_logged": len(rows),
        "status_code_counts": status_code_counts,
        "recent_error_count": error_count,
        "average_latency_ms": average_latency
    }


def get_request_metrics():
    db_metrics = get_request_metrics_from_db()

    if (
        db_metrics is not None
        and (
            db_metrics["total_requests_logged"] > 0
            or not os.path.exists(REQUEST_LOG_FILE)
        )
    ):
        return db_metrics

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

    handler.send_json_response(
        201,
        data={
            "status": "created",
            "event": event
        },
        request_id=ctx.request_id
    )


def handle_unknown_post_route(handler, ctx):
    """
    Handles unknown POST routes.
    """
    log_request(ctx, 404, "POST endpoint not found")

    handler.send_json_response(
        404,
        error={
            "message": "POST endpoint not found",
            "endpoint": ctx.endpoint
        },
        request_id=ctx.request_id
    )
    
    
# =========================
# Request Handler
# =========================

class ZeroSOCHandler(BaseHTTPRequestHandler):
    def send_json_response(self, status_code, data=None, error=None, request_id=None):
        """
        Sends a consistent JSON API response.
        """

        response = {
            "success": 200 <= status_code < 400,
            "status_code": status_code,
            "request_id": request_id,
            "data": data,
            "error": error
        }

        response_body = json.dumps(response, indent=2).encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))

        if request_id:
            self.send_header("X-Request-ID", request_id)

        self.end_headers()
        self.wfile.write(response_body)
        
    def requires_auth(self, endpoint):
        if endpoint in PROTECTED_ENDPOINTS:
            return True

        if endpoint.startswith("/api/v1/events/"):
            return True

        return False
        
    def handle_events(self, ctx, query_params):
        """
        Handles GET /api/v1/events.
        Returns recent security events with optional filters.
        """
        limit = query_params.get("limit", ["50"])[0]
        severity = query_params.get("severity", [None])[0]
        tag = query_params.get("tag", [None])[0]

        events = get_security_events(
            limit=limit,
            severity=severity,
            tag=tag
        )

        log_request(ctx, 200, "Security events requested")

        self.send_json_response(
            200,
            data={
                "events": events,
                "count": len(events),
                "filters": {
                    "limit": int(limit) if str(limit).isdigit() else 50,
                    "severity": severity,
                    "tag": tag
                }
            },
            request_id=ctx.request_id
        ) 
        
    def handle_events_summary(self, ctx):
        summary = get_events_summary()

        log_request(ctx, 200, "Security events summary requested")

        self.send_json_response(
            200,
            data=summary,
            request_id=ctx.request_id
        )

    def handle_alerts(self, ctx, query_params):
        limit = query_params.get("limit", ["20"])[0]
        alerts = get_alerts(limit=limit)

        log_request(ctx, 200, "Alerts requested")

        self.send_json_response(
            200,
            data={
                "alerts": alerts,
                "count": len(alerts),
                "summary": get_alert_summary(alerts),
                "filters": {
                    "limit": int(limit) if str(limit).isdigit() else 20
                }
            },
            request_id=ctx.request_id
        )
        
    def handle_event_by_id(self, ctx, endpoint):
        event_id = endpoint.replace("/api/v1/events/", "").strip()

        if not event_id:
            log_request(ctx, 400, "Missing event ID")

            self.send_json_response(
                400,
                 error={
                    "message": "Missing event ID"
                },
                request_id=ctx.request_id
            )
            return

        event = get_security_event_by_id(event_id)

        if event is None:
            log_request(ctx, 404, "Security event not found")

            self.send_json_response(
                404,
                error={
                    "message": "Security event not found",
                    "event_id": event_id
                },
                request_id=ctx.request_id
            )
            return

        log_request(ctx, 200, "Security event requested by ID")

        self.send_json_response(
            200,
            data={
                "event": event
            },
            request_id=ctx.request_id
        )
        
    def handle_devices(self, ctx):
        devices = get_recent_network_devices(limit=50)

        log_request(ctx, 200, "Network devices requested")

        self.send_json_response(
            200,
            data={
                "devices": devices,
                "count": len(devices)
            },
            request_id=ctx.request_id
        )
        
    def handle_network_scan(self, ctx):
        scan_result = scan_network()

        if "error" in scan_result:
            log_request(ctx, 500, "Network scan failed")

            self.send_json_response(
                500,
                error={
                    "message": scan_result["error"]
                },
                request_id=ctx.request_id
            )
            return

        processed = process_network_devices(scan_result["devices"])

        log_request(ctx, 200, "Network scan completed")

        self.send_json_response(
            200,
            data={
                "network": scan_result["network"],
                "device_count": len(processed["devices"]),
                "unknown_device_count": len(processed["unknown_devices"]),
                "devices": processed["devices"],
                "unknown_devices": processed["unknown_devices"]
            },
            request_id=ctx.request_id
        )
        
    def handle_metrics(self, ctx):
        request_metrics = get_request_metrics()
        event_summary = get_security_event_summary()
        devices = get_recent_network_devices(limit=50)

        log_request(ctx, 200, "Metrics requested")

        self.send_json_response(
            200,
            data={
                "service": APP_NAME,
                "api_version": API_VERSION,
                "uptime_seconds": get_uptime_seconds(),
                "requests": request_metrics,
                "events": event_summary,
                "devices": {
                    "total_recent_devices": len(devices)
                }
            },
            request_id=ctx.request_id
        )
        
    def handle_recent_logs(self, ctx):
        logs = get_recent_logs(limit=10)

        log_request(ctx, 200, "Recent request logs requested")

        self.send_json_response(
            200,
            data={
                "logs": logs,
                "count": len(logs)
            },
            request_id=ctx.request_id
        )

    def handle_health(self, ctx):
        log_request(ctx, 200, "Health check")

        self.send_json_response(
            200,
            data={
                "status": "ok",
                "service": APP_NAME,
                "api_version": API_VERSION,
                "endpoint": ctx.endpoint,
                "message": "ZeroSOC backend is running",
                "current_time": datetime.now().isoformat()
            },
            request_id=ctx.request_id
        )

    def handle_status(self, ctx):
        log_request(ctx, 200, "Status info requested")

        self.send_json_response(
            200,
            data=get_status_info(),
            request_id=ctx.request_id
        )

    def handle_system(self, ctx):
        log_request(ctx, 200, "System info requested")

        self.send_json_response(
            200,
            data=get_system_info(),
            request_id=ctx.request_id
        )

    def handle_not_found(self, ctx):
        log_request(ctx, 404, "Endpoint not found")

        self.send_json_response(
            404,
            error={
                "message": "Endpoint not found",
                "endpoint": ctx.endpoint
            },
            request_id=ctx.request_id
        )

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        super().end_headers()

    def get_routes(self):
        return {
            "/health": self.handle_health,
            "/status": self.handle_status,
            "/system": self.handle_system,
            "/api/v1/health": self.handle_health,
            "/api/v1/status": self.handle_status,
            "/api/v1/system": self.handle_system,
            "/api/v1/logs/recent": self.handle_recent_logs
        }

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        endpoint = normalize_route(parsed_path.path)
        query_params = parse_qs(parsed_path.query)

        request_id = str(uuid.uuid4())
        client_ip = self.client_address[0]

        ctx = RequestContext(
            request_id=request_id,
            method="GET",
            endpoint=endpoint,
            client_ip=client_ip,
            start_time=time.time()
        )

        if self.requires_auth(endpoint) and not is_authorized(self.headers):
            log_request(ctx, 401, "Unauthorized request")
            self.send_json_response(
                401,
                error={
                    "message": "Missing or invalid API key"
                },
                request_id=request_id
            )
            return

        if endpoint in ["/health", "/api/v1/health"]:
            self.handle_health(ctx)
            return

        if endpoint in ["/status", "/api/v1/status"]:
            self.handle_status(ctx)
            return

        if endpoint in ["/system", "/api/v1/system"]:
            self.handle_system(ctx)
            return

        if endpoint == "/api/v1/logs/recent":
            self.handle_recent_logs(ctx)
            return

        if endpoint == "/api/v1/events/summary":
            self.handle_events_summary(ctx)
            return

        if endpoint == "/api/v1/alerts":
            self.handle_alerts(ctx, query_params)
            return

        if endpoint == "/api/v1/events":
            self.handle_events(ctx, query_params)
            return

        if endpoint.startswith("/api/v1/events/"):
            self.handle_event_by_id(ctx, endpoint)
            return

        if endpoint == "/api/v1/devices":
            self.handle_devices(ctx)
            return

        if endpoint == "/api/v1/network/scan":
            self.handle_network_scan(ctx)
            return

        if endpoint == "/api/v1/metrics":
            self.handle_metrics(ctx)
            return

        self.handle_not_found(ctx)
        
    def do_POST(self):
        parsed_path = urlparse(self.path)
        endpoint = normalize_route(parsed_path.path)

        request_id = str(uuid.uuid4())
        client_ip = self.client_address[0]

        ctx = RequestContext(
            request_id=request_id,
            method="POST",
            endpoint=endpoint,
            client_ip=client_ip,
            start_time=time.time()
        )

        if self.requires_auth(endpoint) and not is_authorized(self.headers):
            log_request(ctx, 401, "Unauthorized POST request")

            self.send_json_response(
                401,
                error={
                    "message": "Missing or invalid API key"
                },
                request_id=request_id
            )
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")

            if not body:
                raise ValueError("Request body is empty")

            data = json.loads(body)

        except json.JSONDecodeError:
            log_request(ctx, 400, "Invalid JSON body")

            self.send_json_response(
                400,
                error={
                    "message": "Invalid JSON body"
                },
                request_id=request_id
            )
            return

        except ValueError as error:
            log_request(ctx, 400, str(error))

            self.send_json_response(
                400,
                error={
                    "message": str(error)
                },
                request_id=request_id
            )
            return

        if endpoint == "/api/v1/events":
            handle_create_event(self, ctx, data)
            return

        handle_unknown_post_route(self, ctx) 
        
# =========================
# Server Runner
# =========================

def run_server():
    init_database()

    host = "0.0.0.0"
    port = 8000

    server = HTTPServer((host, port), ZeroSOCHandler)

    print(f"{APP_NAME} backend running at http://{host}:{port}")
    print(f"SQLite database: {DB_FILE}")
    print("")
    print("Available endpoints:")
    print("  /api/v1/health")
    print("  /api/v1/status")
    print("  /api/v1/system")
    print("  /api/v1/events")
    print("  /api/v1/events/{id}")
    print("  /api/v1/events/summary")
    print("  /api/v1/alerts")
    print("  /api/v1/devices")
    print("  /api/v1/network/scan")
    print("  /api/v1/logs/recent")
    print("  /api/v1/metrics")
    print("")
    print("Protected endpoints require header:")
    print(f"  {API_KEY_HEADER}: {API_KEY}")

    server.serve_forever()


if __name__ == "__main__":
    run_server()

    server = HTTPServer(("0.0.0.0", 8000), ZeroSOCHandler)
    print("ZeroSOC backend running on http://0.0.0.0:8000")
    print(f"SQLite database: {DB_FILE}")
    server.serve_forever()
