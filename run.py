from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import csv
import html
import io
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
from datetime import datetime, timedelta


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
    "/api/v1/events/export",
    "/api/v1/events/summary",
    "/api/v1/alerts",
    "/api/v1/devices",
    "/api/v1/devices/export",
    "/api/v1/network/scan",
    "/api/v1/metrics"
}

ALERT_STATUSES = {"open", "acknowledged", "resolved"}
ALERT_SEVERITIES = {"critical", "high", "medium", "low"}
ALERT_PRIORITY_LABELS = {"urgent", "high", "medium", "low"}
ALERT_SLA_HOURS = {
    "critical": 1,
    "high": 4,
    "medium": 24,
    "low": 72
}
ALERT_SLA_STATUSES = {"on-track", "due-soon", "overdue", "resolved", "unknown"}
ALERT_WEBHOOK_URL = os.getenv("ZEROSOC_ALERT_WEBHOOK_URL", "").strip()
ALERT_WEBHOOK_TIMEOUT_SECONDS = 5

try:
    ALERT_NOTIFICATION_COOLDOWN_SECONDS = int(os.getenv(
        "ZEROSOC_ALERT_NOTIFICATION_COOLDOWN_SECONDS",
        "900"
    ))
except ValueError:
    ALERT_NOTIFICATION_COOLDOWN_SECONDS = 900

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


def ensure_table_column(cursor, table_name, column_name, column_definition):
    cursor.execute(f"PRAGMA table_info({table_name})")
    existing_columns = {row["name"] for row in cursor.fetchall()}

    if column_name not in existing_columns:
        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )


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
        CREATE TABLE IF NOT EXISTS alert_states (
            alert_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_states (
            incident_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'open',
            owner TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            archived_at TEXT NOT NULL DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS report_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    ensure_table_column(
        cursor,
        "alert_notifications",
        "details",
        "TEXT NOT NULL DEFAULT ''"
    )

    ensure_table_column(
        cursor,
        "alert_reports",
        "archived_at",
        "TEXT NOT NULL DEFAULT ''"
    )

    ensure_table_column(
        cursor,
        "incident_states",
        "status",
        "TEXT NOT NULL DEFAULT 'open'"
    )

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp
        ON request_logs (timestamp)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_notifications_created_at
        ON alert_notifications (created_at)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_reports_created_at
        ON alert_reports (created_at)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incident_states_updated_at
        ON incident_states (updated_at)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incident_activity_created_at
        ON incident_activity (created_at)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incident_activity_incident_id
        ON incident_activity (incident_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_report_activity_created_at
        ON report_activity (created_at)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_report_activity_report_id
        ON report_activity (report_id)
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


def get_security_events(
    limit=50,
    severity=None,
    tag=None,
    event_type=None,
    source=None,
    search=None,
    since_hours=None
):
    """
    Reads security events from the SQLite database.
    Supports optional filtering by severity, tag, event type, source,
    and a free-text search across source, type, message, and tags.
    """

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 50

    limit = max(1, min(limit, 100))
    severity = str(severity or "").strip().lower()
    tag = str(tag or "").strip()
    event_type = str(event_type or "").strip()
    source = str(source or "").strip()
    search = str(search or "").strip()

    try:
        since_hours = int(since_hours) if since_hours not in (None, "", "all") else None
    except (TypeError, ValueError):
        since_hours = None

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

    if event_type:
        filters.append("event_type = ?")
        params.append(event_type)

    if source:
        filters.append("source_ip = ?")
        params.append(source)

    if search:
        filters.append("""
            (
                source_ip LIKE ?
                OR event_type LIKE ?
                OR message LIKE ?
                OR tag LIKE ?
            )
        """)
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term, search_term])

    if since_hours is not None and since_hours > 0:
        filters.append("timestamp >= ?")
        params.append((datetime.now() - timedelta(hours=since_hours)).isoformat())

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


def events_to_csv(events):
    output = io.StringIO()
    fieldnames = [
        "id",
        "timestamp",
        "source_ip",
        "event_type",
        "severity",
        "message",
        "tags"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for event in events:
        writer.writerow({
            "id": event.get("id", ""),
            "timestamp": event.get("timestamp", ""),
            "source_ip": event.get("source_ip", ""),
            "event_type": event.get("event_type", ""),
            "severity": event.get("severity", ""),
            "message": event.get("message", ""),
            "tags": ",".join(event.get("tags", []))
        })

    return output.getvalue()

def parse_iso_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def is_network_device_stale(device, stale_after_hours=24, now=None):
    last_seen = parse_iso_datetime(device.get("last_seen"))

    if last_seen is None:
        return False

    reference_time = now or datetime.now(last_seen.tzinfo)
    return reference_time - last_seen > timedelta(hours=stale_after_hours)

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


def get_alert_sla(alert, now=None):
    created_at = parse_iso_datetime(alert.get("timestamp"))
    status = str(alert.get("status") or "open").lower()
    severity = str(alert.get("severity") or "low").lower()
    sla_hours = ALERT_SLA_HOURS.get(severity, ALERT_SLA_HOURS["low"])

    if created_at is None:
        return {
            "age_minutes": None,
            "sla_hours": sla_hours,
            "sla_due_at": None,
            "sla_status": "unknown",
            "is_overdue": False
        }

    reference_time = now or datetime.now(created_at.tzinfo)
    age_minutes = max(0, round((reference_time - created_at).total_seconds() / 60, 1))
    due_at = created_at + timedelta(hours=sla_hours)

    if status == "resolved":
        sla_status = "resolved"
        is_overdue = False
    elif reference_time > due_at:
        sla_status = "overdue"
        is_overdue = True
    elif due_at - reference_time <= timedelta(hours=1):
        sla_status = "due-soon"
        is_overdue = False
    else:
        sla_status = "on-track"
        is_overdue = False

    return {
        "age_minutes": age_minutes,
        "sla_hours": sla_hours,
        "sla_due_at": due_at.isoformat(),
        "sla_status": sla_status,
        "is_overdue": is_overdue
    }


def get_alerts(
    limit=20,
    status="active",
    severity=None,
    search=None,
    priority=None,
    sla_status=None
):
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
    status = str(status or "active").strip().lower()
    severity = str(severity or "").strip().lower()
    search = str(search or "").strip()
    priority = str(priority or "").strip().lower()
    sla_status = str(sla_status or "").strip().lower()
    has_derived_filters = priority in ALERT_PRIORITY_LABELS or sla_status in ALERT_SLA_STATUSES
    query_limit = 100 if has_derived_filters else limit

    conn = get_db_connection()
    cursor = conn.cursor()

    status_clause = "AND COALESCE(alert_states.status, 'open') != 'resolved'"
    params = []

    if status == "all":
        status_clause = ""
    elif status in ALERT_STATUSES:
        status_clause = "AND COALESCE(alert_states.status, 'open') = ?"
        params.append(status)
    elif status != "active":
        status_clause = "AND COALESCE(alert_states.status, 'open') != 'resolved'"

    severity_clause = ""

    if severity in ALERT_SEVERITIES:
        severity_clause = "AND security_events.severity = ?"
        params.append(severity)

    search_clause = ""

    if search:
        search_clause = """
            AND (
                security_events.source_ip LIKE ?
                OR security_events.message LIKE ?
                OR security_events.event_type LIKE ?
            )
        """
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term])

    params.append(query_limit)

    cursor.execute(f"""
        SELECT
            security_events.id,
            security_events.timestamp,
            security_events.source_ip,
            security_events.event_type,
            security_events.severity,
            security_events.message,
            security_events.tag,
            COALESCE(alert_states.status, 'open') AS alert_status,
            alert_states.note AS alert_note,
            alert_states.updated_at AS alert_updated_at
        FROM security_events
        LEFT JOIN alert_states
            ON alert_states.alert_id = security_events.id
        WHERE (
            security_events.severity IN ('critical', 'high')
            OR security_events.tag LIKE '%needs-review%'
        )
        {status_clause}
        {severity_clause}
        {search_clause}
        ORDER BY security_events.timestamp DESC
        LIMIT ?
    """, params)

    rows = cursor.fetchall()
    conn.close()

    alerts = []

    for row in rows:
        tags = row["tag"].split(",") if row["tag"] else []
        alert = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "event_type": row["event_type"],
            "severity": row["severity"],
            "message": row["message"],
            "tags": tags,
            "status": row["alert_status"],
            "note": row["alert_note"] or "",
            "status_updated_at": row["alert_updated_at"]
        }
        priority_data = calculate_alert_priority(alert)
        alert["priority_score"] = priority_data["score"]
        alert["priority_label"] = priority_data["label"]
        alert.update(get_alert_sla(alert))
        alert["incident_key"] = build_incident_key(alert)

        if priority in ALERT_PRIORITY_LABELS and alert["priority_label"] != priority:
            continue

        if sla_status in ALERT_SLA_STATUSES and alert["sla_status"] != sla_status:
            continue

        alerts.append(alert)

        if len(alerts) >= limit:
            break

    return alerts


def calculate_alert_priority(alert):
    severity_scores = {
        "critical": 90,
        "high": 70,
        "medium": 45,
        "low": 20
    }
    status_adjustments = {
        "open": 10,
        "acknowledged": -10,
        "resolved": -35
    }

    severity = str(alert.get("severity") or "low").lower()
    status = str(alert.get("status") or "open").lower()
    tags = alert.get("tags") or []
    message = str(alert.get("message") or "").lower()
    event_type = str(alert.get("event_type") or "").lower()

    score = severity_scores.get(severity, 20)
    score += status_adjustments.get(status, 0)

    if "needs-review" in tags:
        score += 10

    if any(term in message for term in ["repeated", "multiple", "brute", "spray"]):
        score += 8

    if any(term in event_type for term in ["malware", "auth", "unknown-device"]):
        score += 5

    score = max(0, min(score, 100))

    if score >= 85:
        label = "urgent"
    elif score >= 65:
        label = "high"
    elif score >= 40:
        label = "medium"
    else:
        label = "low"

    return {
        "score": score,
        "label": label
    }


def build_incident_key(alert):
    source = str(alert.get("source_ip") or "unknown-source").strip().lower()
    event_type = str(alert.get("event_type") or "unknown-event").strip().lower()
    return f"{source}:{event_type}"


def get_incident_states():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT incident_id, status, owner, note, updated_at
        FROM incident_states
    """)

    rows = cursor.fetchall()
    conn.close()

    return {
        row["incident_id"]: {
            "status": row["status"] or "open",
            "owner": row["owner"] or "",
            "note": row["note"] or "",
            "updated_at": row["updated_at"] or ""
        }
        for row in rows
    }


def save_incident_activity(incident_id, action, details="", created_at=None):
    created_at = created_at or datetime.now().isoformat()
    action = str(action or "").strip().lower()
    details = str(details or "").strip()

    if not action:
        action = "updated"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incident_activity (
            incident_id,
            action,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        incident_id,
        action,
        details,
        created_at
    ))

    activity_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": activity_id,
        "incident_id": incident_id,
        "action": action,
        "details": details,
        "created_at": created_at
    }


def get_incident_activity(limit=20, incident_id=None, action=None):
    try:
        limit = int(limit)
    except ValueError:
        limit = 20

    limit = max(1, min(limit, 100))
    action = str(action or "").strip().lower()

    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            id,
            incident_id,
            action,
            details,
            created_at
        FROM incident_activity
    """
    where_clauses = []
    params = []

    if incident_id:
        where_clauses.append("incident_id = ?")
        params.append(incident_id)

    if action and action != "all":
        where_clauses.append("action = ?")
        params.append(action)

    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row["id"],
            "incident_id": row["incident_id"],
            "action": row["action"],
            "details": row["details"],
            "created_at": row["created_at"]
        }
        for row in rows
    ]


def incident_activity_to_csv(activity):
    output = io.StringIO()
    fieldnames = [
        "id",
        "incident_id",
        "action",
        "details",
        "created_at"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for item in activity:
        writer.writerow({
            "id": item.get("id", ""),
            "incident_id": item.get("incident_id", ""),
            "action": item.get("action", ""),
            "details": item.get("details", ""),
            "created_at": item.get("created_at", "")
        })

    return output.getvalue()


def update_incident_state(incident_id, owner=None, note=None, status=None):
    incident_id = str(incident_id or "").strip()

    if not incident_id:
        raise ValueError("Incident ID is required")

    allowed_statuses = {"open", "investigating", "contained", "resolved"}
    states = get_incident_states()
    existing = states.get(incident_id, {})
    previous = {
        "status": existing.get("status", "open"),
        "owner": existing.get("owner", ""),
        "note": existing.get("note", "")
    }
    status = str(status if status is not None else previous["status"]).strip().lower()

    if status not in allowed_statuses:
        raise ValueError("Incident status must be open, investigating, contained, or resolved")

    owner = str(owner if owner is not None else existing.get("owner", "")).strip()
    note = str(note if note is not None else existing.get("note", "")).strip()
    updated_at = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incident_states (
            incident_id,
            status,
            owner,
            note,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(incident_id) DO UPDATE SET
            status = excluded.status,
            owner = excluded.owner,
            note = excluded.note,
            updated_at = excluded.updated_at
    """, (
        incident_id,
        status,
        owner,
        note,
        updated_at
    ))

    conn.commit()
    conn.close()

    if status != previous["status"]:
        save_incident_activity(
            incident_id,
            "status_updated",
            f"Status changed to {status}",
            created_at=updated_at
        )

    if owner != previous["owner"]:
        save_incident_activity(
            incident_id,
            "owner_updated",
            f"Owner changed to {owner or 'unassigned'}",
            created_at=updated_at
        )

    if note != previous["note"]:
        save_incident_activity(
            incident_id,
            "note_updated",
            "Incident note updated",
            created_at=updated_at
        )

    return {
        "incident_id": incident_id,
        "status": status,
        "owner": owner,
        "note": note,
        "updated_at": updated_at
    }


def group_alerts_into_incidents(alerts):
    incidents = {}
    incident_states = get_incident_states()

    for alert in alerts:
        incident_key = alert.get("incident_key") or build_incident_key(alert)
        state = incident_states.get(incident_key, {})
        incident = incidents.setdefault(incident_key, {
            "id": incident_key,
            "source_ip": alert.get("source_ip") or "unknown",
            "event_type": alert.get("event_type") or "unknown",
            "alert_count": 0,
            "open_alerts": 0,
            "overdue_alerts": 0,
            "highest_priority_score": 0,
            "highest_priority_label": "low",
            "latest_timestamp": alert.get("timestamp"),
            "alert_ids": [],
            "status": state.get("status", "open"),
            "owner": state.get("owner", ""),
            "note": state.get("note", ""),
            "state_updated_at": state.get("updated_at", "")
        })

        incident["alert_count"] += 1
        incident["alert_ids"].append(alert.get("id"))

        if alert.get("status") != "resolved":
            incident["open_alerts"] += 1

        if alert.get("is_overdue"):
            incident["overdue_alerts"] += 1

        if (alert.get("priority_score") or 0) > incident["highest_priority_score"]:
            incident["highest_priority_score"] = alert.get("priority_score") or 0
            incident["highest_priority_label"] = alert.get("priority_label") or "low"

        if str(alert.get("timestamp") or "") > str(incident.get("latest_timestamp") or ""):
            incident["latest_timestamp"] = alert.get("timestamp")

    return sorted(
        incidents.values(),
        key=lambda incident: (
            incident["highest_priority_score"],
            incident["alert_count"],
            incident["latest_timestamp"] or ""
        ),
        reverse=True
    )


def incidents_to_csv(incidents):
    output = io.StringIO()
    fieldnames = [
        "id",
        "source_ip",
        "event_type",
        "status",
        "alert_count",
        "open_alerts",
        "overdue_alerts",
        "highest_priority_score",
        "highest_priority_label",
        "latest_timestamp",
        "owner",
        "note",
        "state_updated_at",
        "alert_ids"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for incident in incidents:
        writer.writerow({
            "id": incident.get("id", ""),
            "source_ip": incident.get("source_ip", ""),
            "event_type": incident.get("event_type", ""),
            "status": incident.get("status", ""),
            "alert_count": incident.get("alert_count", ""),
            "open_alerts": incident.get("open_alerts", ""),
            "overdue_alerts": incident.get("overdue_alerts", ""),
            "highest_priority_score": incident.get("highest_priority_score", ""),
            "highest_priority_label": incident.get("highest_priority_label", ""),
            "latest_timestamp": incident.get("latest_timestamp", ""),
            "owner": incident.get("owner", ""),
            "note": incident.get("note", ""),
            "state_updated_at": incident.get("state_updated_at", ""),
            "alert_ids": ",".join(incident.get("alert_ids", []))
        })

    return output.getvalue()


def get_alert_summary(alerts):
    severity_counts = {}
    status_counts = {}
    priority_counts = {}
    sla_counts = {}

    for alert in alerts:
        severity = alert.get("severity") or "unknown"
        status = alert.get("status") or "open"
        priority = alert.get("priority_label") or "low"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
        sla_status = alert.get("sla_status") or "unknown"
        sla_counts[sla_status] = sla_counts.get(sla_status, 0) + 1

    incidents = group_alerts_into_incidents(alerts)

    return {
        "total_alerts": len(alerts),
        "open_alerts": status_counts.get("open", 0),
        "acknowledged_alerts": status_counts.get("acknowledged", 0),
        "resolved_alerts": status_counts.get("resolved", 0),
        "incident_count": len(incidents),
        "highest_priority_score": max([alert.get("priority_score", 0) for alert in alerts], default=0),
        "overdue_alerts": sla_counts.get("overdue", 0),
        "due_soon_alerts": sla_counts.get("due-soon", 0),
        "status_counts": status_counts,
        "severity_counts": severity_counts,
        "priority_counts": priority_counts,
        "sla_counts": sla_counts
    }


def alerts_to_csv(alerts):
    output = io.StringIO()
    fieldnames = [
        "id",
        "timestamp",
        "source_ip",
        "event_type",
        "severity",
        "priority_score",
        "priority_label",
        "age_minutes",
        "sla_hours",
        "sla_due_at",
        "sla_status",
        "is_overdue",
        "incident_key",
        "status",
        "message",
        "note",
        "tags",
        "status_updated_at"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for alert in alerts:
        writer.writerow({
            "id": alert.get("id", ""),
            "timestamp": alert.get("timestamp", ""),
            "source_ip": alert.get("source_ip", ""),
            "event_type": alert.get("event_type", ""),
            "severity": alert.get("severity", ""),
            "priority_score": alert.get("priority_score", ""),
            "priority_label": alert.get("priority_label", ""),
            "age_minutes": alert.get("age_minutes", ""),
            "sla_hours": alert.get("sla_hours", ""),
            "sla_due_at": alert.get("sla_due_at", ""),
            "sla_status": alert.get("sla_status", ""),
            "is_overdue": alert.get("is_overdue", False),
            "incident_key": alert.get("incident_key", ""),
            "status": alert.get("status", ""),
            "message": alert.get("message", ""),
            "note": alert.get("note", ""),
            "tags": ",".join(alert.get("tags", [])),
            "status_updated_at": alert.get("status_updated_at", "")
        })

    return output.getvalue()


def save_alert_report(alert_id, title, summary, status="draft"):
    event = get_security_event_by_id(alert_id)

    if not is_alert_event(event):
        return None

    title = str(title or "").strip()
    summary = str(summary or "").strip()
    status = str(status or "draft").strip().lower()

    if not title:
        title = f"Investigation report for alert {alert_id}"

    if not summary:
        summary = "No investigation summary provided."

    if status not in {"draft", "final"}:
        status = "draft"

    now = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alert_reports (
            alert_id,
            title,
            summary,
            status,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        title,
        summary,
        status,
        now,
        now
    ))

    report_id = cursor.lastrowid
    conn.commit()
    conn.close()

    save_report_activity(
        report_id,
        "created",
        f"Report saved as {status}"
    )

    return {
        "id": report_id,
        "alert_id": alert_id,
        "title": title,
        "summary": summary,
        "status": status,
        "created_at": now,
        "updated_at": now,
        "archived_at": ""
    }


def save_report_activity(report_id, action, details="", created_at=None):
    created_at = created_at or datetime.now().isoformat()
    action = str(action or "").strip().lower()
    details = str(details or "").strip()

    if not action:
        action = "updated"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO report_activity (
            report_id,
            action,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        report_id,
        action,
        details,
        created_at
    ))

    activity_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": activity_id,
        "report_id": report_id,
        "action": action,
        "details": details,
        "created_at": created_at
    }


def get_report_activity(limit=20, report_id=None, action=None):
    try:
        limit = int(limit)
    except ValueError:
        limit = 20

    limit = max(1, min(limit, 100))
    action = str(action or "").strip().lower()

    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            report_activity.id,
            report_activity.report_id,
            report_activity.action,
            report_activity.details,
            report_activity.created_at,
            alert_reports.title,
            alert_reports.status,
            alert_reports.archived_at
        FROM report_activity
        LEFT JOIN alert_reports
            ON alert_reports.id = report_activity.report_id
    """
    where_clauses = []
    params = []

    if report_id:
        where_clauses.append("report_activity.report_id = ?")
        params.append(report_id)

    if action and action != "all":
        where_clauses.append("report_activity.action = ?")
        params.append(action)

    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)

    query += " ORDER BY report_activity.created_at DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row["id"],
            "report_id": row["report_id"],
            "action": row["action"],
            "details": row["details"],
            "created_at": row["created_at"],
            "report_title": row["title"] or f"Report {row['report_id']}",
            "report_status": row["status"] or "",
            "archived_at": row["archived_at"] or ""
        }
        for row in rows
    ]


def report_activity_to_csv(activity):
    output = io.StringIO()
    fieldnames = [
        "id",
        "report_id",
        "report_title",
        "report_status",
        "action",
        "details",
        "created_at",
        "archived_at"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for item in activity:
        writer.writerow({
            "id": item.get("id", ""),
            "report_id": item.get("report_id", ""),
            "report_title": item.get("report_title", ""),
            "report_status": item.get("report_status", ""),
            "action": item.get("action", ""),
            "details": item.get("details", ""),
            "created_at": item.get("created_at", ""),
            "archived_at": item.get("archived_at", "")
        })

    return output.getvalue()


def get_alert_reports(limit=20, alert_id=None, status=None, search=None, include_archived=False):
    try:
        limit = int(limit)
    except ValueError:
        limit = 20

    limit = max(1, min(limit, 100))
    status = str(status or "").strip().lower()

    if status not in {"draft", "final"}:
        status = None

    search = str(search or "").strip()
    archive_filter = str(include_archived).strip().lower()
    include_archived = archive_filter in {"1", "true", "yes", "all", "archived", "only"}
    archived_only = archive_filter in {"archived", "only"}

    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            id,
            alert_id,
            title,
            summary,
            status,
            created_at,
            updated_at,
            archived_at
        FROM alert_reports
    """
    where_clauses = []
    params = []

    if archived_only:
        where_clauses.append("archived_at IS NOT NULL AND archived_at != ''")
    elif not include_archived:
        where_clauses.append("(archived_at IS NULL OR archived_at = '')")

    if alert_id:
        where_clauses.append("alert_id = ?")
        params.append(alert_id)

    if status:
        where_clauses.append("status = ?")
        params.append(status)

    if search:
        where_clauses.append("(title LIKE ? OR summary LIKE ?)")
        search_param = f"%{search}%"
        params.extend([search_param, search_param])

    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    reports = []

    for row in rows:
        reports.append({
            "id": row["id"],
            "alert_id": row["alert_id"],
            "title": row["title"],
            "summary": row["summary"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "archived_at": row["archived_at"] or ""
        })

    return reports


def get_alert_report_export_bundle(report_id):
    report = get_alert_report_by_id(report_id)

    if report is None:
        return None

    alert = get_security_event_by_id(report["alert_id"])

    return {
        "exported_at": datetime.now().isoformat(),
        "type": "zerosoc-alert-investigation-report",
        "version": API_VERSION,
        "report": report,
        "alert": alert
    }


def get_alert_report_by_id(report_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            alert_id,
            title,
            summary,
            status,
            created_at,
            updated_at,
            archived_at
        FROM alert_reports
        WHERE id = ?
    """, (report_id,))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return {
        "id": row["id"],
        "alert_id": row["alert_id"],
        "title": row["title"],
        "summary": row["summary"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "archived_at": row["archived_at"] or ""
    }


def update_alert_report_status(report_id, status):
    status = str(status or "").strip().lower()

    if status not in {"draft", "final"}:
        raise ValueError("Report status must be draft or final")

    report = get_alert_report_by_id(report_id)

    if report is None:
        return None

    updated_at = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE alert_reports
        SET status = ?, updated_at = ?
        WHERE id = ?
    """, (
        status,
        updated_at,
        report_id
    ))

    conn.commit()
    conn.close()

    report["status"] = status
    report["updated_at"] = updated_at

    save_report_activity(
        report_id,
        "status_updated",
        f"Status changed to {status}",
        created_at=updated_at
    )

    return report


def update_alert_report_details(report_id, title=None, summary=None):
    report = get_alert_report_by_id(report_id)

    if report is None:
        return None

    title = str(title if title is not None else report["title"]).strip()
    summary = str(summary if summary is not None else report["summary"]).strip()

    if not title:
        title = f"Investigation report for alert {report['alert_id']}"

    if not summary:
        summary = "No investigation summary provided."

    updated_at = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE alert_reports
        SET title = ?, summary = ?, updated_at = ?
        WHERE id = ?
    """, (
        title,
        summary,
        updated_at,
        report_id
    ))

    conn.commit()
    conn.close()

    report["title"] = title
    report["summary"] = summary
    report["updated_at"] = updated_at

    save_report_activity(
        report_id,
        "details_updated",
        "Report title or summary updated",
        created_at=updated_at
    )

    return report


def archive_alert_report(report_id):
    report = get_alert_report_by_id(report_id)

    if report is None:
        return None

    archived_at = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE alert_reports
        SET archived_at = ?, updated_at = ?
        WHERE id = ?
    """, (
        archived_at,
        archived_at,
        report_id
    ))

    conn.commit()
    conn.close()

    report["archived_at"] = archived_at
    report["updated_at"] = archived_at

    save_report_activity(
        report_id,
        "archived",
        "Report moved to archive",
        created_at=archived_at
    )

    return report


def restore_alert_report(report_id):
    report = get_alert_report_by_id(report_id)

    if report is None:
        return None

    restored_at = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE alert_reports
        SET archived_at = '', updated_at = ?
        WHERE id = ?
    """, (
        restored_at,
        report_id
    ))

    conn.commit()
    conn.close()

    report["archived_at"] = ""
    report["updated_at"] = restored_at

    save_report_activity(
        report_id,
        "restored",
        "Report restored from archive",
        created_at=restored_at
    )

    return report


def get_alert_report_summary():
    conn = get_db_connection()
    cursor = conn.cursor()

    summary = {
        "total_reports": 0,
        "active_reports": 0,
        "archived_reports": 0,
        "draft_reports": 0,
        "final_reports": 0,
        "status_counts": {},
        "latest_report": None
    }

    cursor.execute("SELECT COUNT(*) AS total FROM alert_reports")
    row = cursor.fetchone()
    summary["total_reports"] = row["total"] if row else 0

    cursor.execute("""
        SELECT COUNT(*) AS count
        FROM alert_reports
        WHERE archived_at IS NOT NULL AND archived_at != ''
    """)
    row = cursor.fetchone()
    summary["archived_reports"] = row["count"] if row else 0
    summary["active_reports"] = summary["total_reports"] - summary["archived_reports"]

    cursor.execute("""
        SELECT status, COUNT(*) AS count
        FROM alert_reports
        WHERE archived_at IS NULL OR archived_at = ''
        GROUP BY status
    """)

    for row in cursor.fetchall():
        status = row["status"] or "unknown"
        summary["status_counts"][status] = row["count"]

    cursor.execute("""
        SELECT
            id,
            alert_id,
            title,
            summary,
            status,
            created_at,
            updated_at,
            archived_at
        FROM alert_reports
        WHERE archived_at IS NULL OR archived_at = ''
        ORDER BY created_at DESC
        LIMIT 1
    """)
    latest = cursor.fetchone()
    conn.close()

    summary["draft_reports"] = summary["status_counts"].get("draft", 0)
    summary["final_reports"] = summary["status_counts"].get("final", 0)

    if latest:
        summary["latest_report"] = {
            "id": latest["id"],
            "alert_id": latest["alert_id"],
            "title": latest["title"],
            "summary": latest["summary"],
            "status": latest["status"],
            "created_at": latest["created_at"],
            "updated_at": latest["updated_at"],
            "archived_at": latest["archived_at"] or ""
        }

    return summary


def build_alert_notification_message(alert):
    severity = str(alert.get("severity") or "unknown").upper()
    event_type = alert.get("event_type") or "unknown event"
    source_ip = alert.get("source_ip") or "unknown source"
    message = alert.get("message") or "No message provided"

    return f"[{severity}] {event_type} from {source_ip}: {message}"


def save_alert_notification(alert_id, channel, status, message, details="", created_at=None):
    created_at = created_at or datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alert_notifications (
            alert_id,
            channel,
            status,
            message,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        channel,
        status,
        message,
        details,
        created_at
    ))

    notification_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": notification_id,
        "alert_id": alert_id,
        "channel": channel,
        "status": status,
        "message": message,
        "details": details,
        "created_at": created_at
    }


def get_alert_notifications(limit=20):
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
            alert_id,
            channel,
            status,
            message,
            details,
            created_at
        FROM alert_notifications
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    notifications = []

    for row in rows:
        notifications.append({
            "id": row["id"],
            "alert_id": row["alert_id"],
            "channel": row["channel"],
            "status": row["status"],
            "message": row["message"],
            "details": row["details"],
            "created_at": row["created_at"]
        })

    return notifications


def get_alert_notification_summary():
    conn = get_db_connection()
    cursor = conn.cursor()

    summary = {
        "total_notifications": 0,
        "delivered_notifications": 0,
        "failed_notifications": 0,
        "skipped_notifications": 0,
        "status_counts": {},
        "channel_counts": {},
        "latest_notification": None
    }

    cursor.execute("SELECT COUNT(*) AS total FROM alert_notifications")
    row = cursor.fetchone()
    summary["total_notifications"] = row["total"] if row else 0

    cursor.execute("""
        SELECT status, COUNT(*) AS count
        FROM alert_notifications
        GROUP BY status
    """)

    for row in cursor.fetchall():
        status = row["status"] or "unknown"
        summary["status_counts"][status] = row["count"]

    cursor.execute("""
        SELECT channel, COUNT(*) AS count
        FROM alert_notifications
        GROUP BY channel
    """)

    for row in cursor.fetchall():
        channel = row["channel"] or "unknown"
        summary["channel_counts"][channel] = row["count"]

    cursor.execute("""
        SELECT
            id,
            alert_id,
            channel,
            status,
            message,
            details,
            created_at
        FROM alert_notifications
        ORDER BY created_at DESC
        LIMIT 1
    """)
    latest = cursor.fetchone()
    conn.close()

    summary["delivered_notifications"] = summary["status_counts"].get("delivered", 0)
    summary["failed_notifications"] = summary["status_counts"].get("failed", 0)
    summary["skipped_notifications"] = summary["status_counts"].get("skipped", 0)

    if latest:
        summary["latest_notification"] = {
            "id": latest["id"],
            "alert_id": latest["alert_id"],
            "channel": latest["channel"],
            "status": latest["status"],
            "message": latest["message"],
            "details": latest["details"],
            "created_at": latest["created_at"]
        }

    return summary


def render_alert_report_html(report):
    alert = get_security_event_by_id(report["alert_id"]) or {}
    tags = ", ".join(alert.get("tags", [])) if alert.get("tags") else "N/A"

    def esc(value):
        return html.escape(str(value or "N/A"))

    generated_at = datetime.now().isoformat()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{esc(report["title"])} - ZeroSOC Investigation Report</title>
    <style>
        body {{
            color: #111827;
            font-family: Arial, Helvetica, sans-serif;
            line-height: 1.55;
            margin: 40px;
        }}
        header {{
            border-bottom: 2px solid #111827;
            margin-bottom: 24px;
            padding-bottom: 16px;
        }}
        h1 {{
            margin: 0 0 8px;
        }}
        h2 {{
            border-bottom: 1px solid #d1d5db;
            margin-top: 28px;
            padding-bottom: 6px;
        }}
        .meta-grid {{
            display: grid;
            gap: 8px;
            grid-template-columns: repeat(2, 1fr);
        }}
        .meta-row {{
            border: 1px solid #d1d5db;
            padding: 10px;
        }}
        .label {{
            color: #4b5563;
            display: block;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }}
        @media print {{
            body {{
                margin: 24px;
            }}
            button {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <h1>{esc(report["title"])}</h1>
        <p>ZeroSOC investigation report generated {esc(generated_at)}</p>
        <button onclick="window.print()">Print report</button>
    </header>

    <section>
        <h2>Report Summary</h2>
        <p>{esc(report["summary"])}</p>
    </section>

    <section>
        <h2>Report Metadata</h2>
        <div class="meta-grid">
            <div class="meta-row"><span class="label">Report ID</span>{esc(report["id"])}</div>
            <div class="meta-row"><span class="label">Status</span>{esc(report["status"])}</div>
            <div class="meta-row"><span class="label">Created</span>{esc(report["created_at"])}</div>
            <div class="meta-row"><span class="label">Updated</span>{esc(report["updated_at"])}</div>
        </div>
    </section>

    <section>
        <h2>Alert Context</h2>
        <div class="meta-grid">
            <div class="meta-row"><span class="label">Alert ID</span>{esc(report["alert_id"])}</div>
            <div class="meta-row"><span class="label">Timestamp</span>{esc(alert.get("timestamp"))}</div>
            <div class="meta-row"><span class="label">Source IP</span>{esc(alert.get("source_ip"))}</div>
            <div class="meta-row"><span class="label">Event Type</span>{esc(alert.get("event_type"))}</div>
            <div class="meta-row"><span class="label">Severity</span>{esc(alert.get("severity"))}</div>
            <div class="meta-row"><span class="label">Tags</span>{esc(tags)}</div>
        </div>
        <h2>Alert Message</h2>
        <p>{esc(alert.get("message"))}</p>
    </section>
</body>
</html>"""


def get_recent_delivered_alert_notification(alert_id, channel, cooldown_seconds):
    try:
        cooldown_seconds = int(cooldown_seconds)
    except (TypeError, ValueError):
        cooldown_seconds = ALERT_NOTIFICATION_COOLDOWN_SECONDS

    cooldown_seconds = max(0, cooldown_seconds)

    if cooldown_seconds == 0:
        return None

    cutoff = (datetime.now() - timedelta(seconds=cooldown_seconds)).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            alert_id,
            channel,
            status,
            message,
            details,
            created_at
        FROM alert_notifications
        WHERE alert_id = ?
            AND channel = ?
            AND status = 'delivered'
            AND created_at >= ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (
        alert_id,
        channel,
        cutoff
    ))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return {
        "id": row["id"],
        "alert_id": row["alert_id"],
        "channel": row["channel"],
        "status": row["status"],
        "message": row["message"],
        "details": row["details"],
        "created_at": row["created_at"]
    }


def build_alert_webhook_payload(alert, message):
    return {
        "service": APP_NAME,
        "api_version": API_VERSION,
        "notification_type": "unresolved_alert",
        "notification_message": message,
        "alert": {
            "id": alert.get("id"),
            "timestamp": alert.get("timestamp"),
            "source_ip": alert.get("source_ip"),
            "event_type": alert.get("event_type"),
            "severity": alert.get("severity"),
            "message": alert.get("message"),
            "tags": alert.get("tags", []),
            "status": alert.get("status"),
            "note": alert.get("note", "")
        }
    }


def send_alert_webhook(alert, message, webhook_url=None):
    webhook_url = str(webhook_url or ALERT_WEBHOOK_URL or "").strip()

    if not webhook_url:
        return "skipped", "ZEROSOC_ALERT_WEBHOOK_URL is not configured"

    payload = build_alert_webhook_payload(alert, message)
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        webhook_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"{APP_NAME}/{API_VERSION}"
        },
        method="POST"
    )

    try:
        with urlopen(request, timeout=ALERT_WEBHOOK_TIMEOUT_SECONDS) as response:
            return "delivered", f"Webhook accepted with HTTP {response.status}"
    except HTTPError as error:
        return "failed", f"Webhook returned HTTP {error.code}"
    except URLError as error:
        return "failed", f"Webhook request failed: {error.reason}"
    except TimeoutError:
        return "failed", "Webhook request timed out"
    except OSError as error:
        return "failed", f"Webhook request failed: {error}"


def deliver_alert_notification(
    alert,
    channel="local",
    webhook_url=None,
    cooldown_seconds=None
):
    channel = str(channel or "local").strip().lower() or "local"
    message = build_alert_notification_message(alert)
    cooldown_seconds = (
        ALERT_NOTIFICATION_COOLDOWN_SECONDS
        if cooldown_seconds is None
        else cooldown_seconds
    )
    recent_notification = get_recent_delivered_alert_notification(
        alert_id=alert["id"],
        channel=channel,
        cooldown_seconds=cooldown_seconds
    )

    if recent_notification:
        details = (
            "Suppressed duplicate notification; "
            f"last delivered at {recent_notification['created_at']}"
        )

        return save_alert_notification(
            alert_id=alert["id"],
            channel=channel,
            status="skipped",
            message=message,
            details=details
        )

    if channel == "webhook":
        status, details = send_alert_webhook(
            alert=alert,
            message=message,
            webhook_url=webhook_url
        )
    else:
        status = "delivered"
        details = "Stored in local notification log"

    return save_alert_notification(
        alert_id=alert["id"],
        channel=channel,
        status=status,
        message=message,
        details=details
    )


def notify_unresolved_alerts(channel="local", webhook_url=None, cooldown_seconds=None):
    channel = str(channel or "local").strip().lower() or "local"
    alerts = get_alerts(limit=100, status="active")
    notifications = []
    cooldown_seconds = (
        ALERT_NOTIFICATION_COOLDOWN_SECONDS
        if cooldown_seconds is None
        else cooldown_seconds
    )

    for alert in alerts:
        notifications.append(deliver_alert_notification(
            alert=alert,
            channel=channel,
            webhook_url=webhook_url,
            cooldown_seconds=cooldown_seconds
        ))

    return {
        "channel": channel,
        "unresolved_alert_count": len(alerts),
        "delivered_count": len([
            notification for notification in notifications
            if notification["status"] == "delivered"
        ]),
        "failed_count": len([
            notification for notification in notifications
            if notification["status"] == "failed"
        ]),
        "skipped_count": len([
            notification for notification in notifications
            if notification["status"] == "skipped"
        ]),
        "cooldown_seconds": cooldown_seconds,
        "notifications": notifications
    }


def is_alert_event(event):
    if event is None:
        return False

    severity = str(event.get("severity") or "").lower()
    tags = event.get("tags") or []

    return severity in {"critical", "high"} or "needs-review" in tags


def update_alert_status(alert_id, status, note=None):
    status = str(status or "").strip().lower()

    if status not in ALERT_STATUSES:
        raise ValueError("Alert status must be one of: open, acknowledged, resolved")

    event = get_security_event_by_id(alert_id)

    if not is_alert_event(event):
        return None

    if note is None:
        existing_note = ""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT note FROM alert_states WHERE alert_id = ?",
            (alert_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            existing_note = row["note"] or ""

        note = existing_note
    else:
        note = str(note or "").strip()

    updated_at = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alert_states (
            alert_id,
            status,
            note,
            updated_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(alert_id) DO UPDATE SET
            status = excluded.status,
            note = excluded.note,
            updated_at = excluded.updated_at
    """, (
        alert_id,
        status,
        note,
        updated_at
    ))

    conn.commit()
    conn.close()

    event["status"] = status
    event["note"] = note
    event["status_updated_at"] = updated_at

    return event


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

def get_recent_network_devices(limit=50, status=None, search=None, stale_after_hours=24):
    """
    Returns recently seen network devices from SQLite.
    Supports optional status filtering and free-text search across
    IP address, hostname, MAC address, and status.
    """
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 50

    limit = max(1, min(limit, 100))
    status = str(status or "").strip().lower()
    search = str(search or "").strip()

    try:
        stale_after_hours = int(stale_after_hours)
    except (TypeError, ValueError):
        stale_after_hours = 24

    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            ip_address,
            hostname,
            status,
            mac_address,
            first_seen,
            last_seen
        FROM network_devices
    """
    filters = []
    params = []

    if status:
        filters.append("status = ?")
        params.append(status)

    if search:
        filters.append("""
            (
                ip_address LIKE ?
                OR hostname LIKE ?
                OR mac_address LIKE ?
                OR status LIKE ?
            )
        """)
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term, search_term])

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY last_seen DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)

    rows = cursor.fetchall()
    conn.close()

    devices = []

    for row in rows:
        device = {
            "ip_address": row["ip_address"],
            "hostname": row["hostname"],
            "status": row["status"],
            "mac_address": row["mac_address"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"]
        }
        device["is_stale"] = is_network_device_stale(device, stale_after_hours=stale_after_hours)
        devices.append(device)

    return devices


def get_network_device_summary(devices):
    status_counts = {}
    stale_devices = 0
    latest_device = None

    for device in devices:
        status = device.get("status") or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1

        if device.get("is_stale"):
            stale_devices += 1

        if (
            latest_device is None
            or str(device.get("last_seen") or "") > str(latest_device.get("last_seen") or "")
        ):
            latest_device = device

    return {
        "total_devices": len(devices),
        "online_devices": status_counts.get("online", 0),
        "offline_devices": status_counts.get("offline", 0),
        "stale_devices": stale_devices,
        "status_counts": status_counts,
        "latest_device": latest_device
    }


def network_devices_to_csv(devices):
    output = io.StringIO()
    fieldnames = [
        "ip_address",
        "hostname",
        "status",
        "mac_address",
        "first_seen",
        "last_seen",
        "is_stale"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for device in devices:
        writer.writerow({
            "ip_address": device.get("ip_address", ""),
            "hostname": device.get("hostname", ""),
            "status": device.get("status", ""),
            "mac_address": device.get("mac_address", ""),
            "first_seen": device.get("first_seen", ""),
            "last_seen": device.get("last_seen", ""),
            "is_stale": device.get("is_stale", False)
        })

    return output.getvalue()

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

    def send_csv_response(self, filename, csv_body, request_id=None):
        response_body = csv_body.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{filename}"'
        )

        if request_id:
            self.send_header("X-Request-ID", request_id)

        self.end_headers()
        self.wfile.write(response_body)

    def send_json_file_response(self, filename, data, request_id=None):
        response_body = json.dumps(data, indent=2).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{filename}"'
        )

        if request_id:
            self.send_header("X-Request-ID", request_id)

        self.end_headers()
        self.wfile.write(response_body)

    def send_html_response(self, html_body, request_id=None):
        response_body = html_body.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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

        if endpoint.startswith("/api/v1/alerts/"):
            return True

        return False
        
    def get_event_filters(self, query_params, default_limit="50"):
        limit = query_params.get("limit", [default_limit])[0]

        return {
            "limit": limit,
            "severity": query_params.get("severity", [None])[0],
            "tag": query_params.get("tag", [None])[0],
            "event_type": query_params.get("event_type", [None])[0],
            "source": query_params.get("source", [None])[0],
            "q": query_params.get("q", [None])[0],
            "since_hours": query_params.get("since_hours", [None])[0]
        }

    def handle_events(self, ctx, query_params):
        """
        Handles GET /api/v1/events.
        Returns recent security events with optional filters.
        """
        filters = self.get_event_filters(query_params)

        events = get_security_events(
            limit=filters["limit"],
            severity=filters["severity"],
            tag=filters["tag"],
            event_type=filters["event_type"],
            source=filters["source"],
            search=filters["q"],
            since_hours=filters["since_hours"]
        )

        log_request(ctx, 200, "Security events requested")

        self.send_json_response(
            200,
            data={
                "events": events,
                "count": len(events),
                "filters": {
                    "limit": int(filters["limit"]) if str(filters["limit"]).isdigit() else 50,
                    "severity": filters["severity"],
                    "tag": filters["tag"],
                    "event_type": filters["event_type"],
                    "source": filters["source"],
                    "q": filters["q"],
                    "since_hours": filters["since_hours"]
                }
            },
            request_id=ctx.request_id
        )

    def handle_events_export(self, ctx, query_params):
        filters = self.get_event_filters(query_params, default_limit="100")
        events = get_security_events(
            limit=filters["limit"],
            severity=filters["severity"],
            tag=filters["tag"],
            event_type=filters["event_type"],
            source=filters["source"],
            search=filters["q"],
            since_hours=filters["since_hours"]
        )

        log_request(ctx, 200, "Security events CSV exported")
        self.send_csv_response("zerosoc-security-events.csv", events_to_csv(events), ctx.request_id)
        
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
        status = query_params.get("status", ["active"])[0]
        severity = query_params.get("severity", [None])[0]
        search = query_params.get("q", [None])[0]
        priority = query_params.get("priority", [None])[0]
        sla_status = query_params.get("sla_status", [None])[0]
        alerts = get_alerts(
            limit=limit,
            status=status,
            severity=severity,
            search=search,
            priority=priority,
            sla_status=sla_status
        )

        log_request(ctx, 200, "Alerts requested")

        self.send_json_response(
            200,
            data={
                "alerts": alerts,
                "incidents": group_alerts_into_incidents(alerts),
                "count": len(alerts),
                "summary": get_alert_summary(alerts),
                "filters": {
                    "limit": int(limit) if str(limit).isdigit() else 20,
                    "status": status,
                    "severity": severity,
                    "q": search,
                    "priority": priority,
                    "sla_status": sla_status
                }
            },
            request_id=ctx.request_id
        )

    def handle_alert_status_update(self, ctx, endpoint, data):
        alert_id = endpoint.replace("/api/v1/alerts/", "").replace("/status", "").strip("/")

        if not alert_id:
            log_request(ctx, 400, "Missing alert ID")

            self.send_json_response(
                400,
                error={
                    "message": "Missing alert ID"
                },
                request_id=ctx.request_id
            )
            return

        try:
            alert = update_alert_status(
                alert_id=alert_id,
                status=data.get("status"),
                note=data.get("note")
            )
        except ValueError as error:
            log_request(ctx, 400, str(error))

            self.send_json_response(
                400,
                error={
                    "message": str(error)
                },
                request_id=ctx.request_id
            )
            return

        if alert is None:
            log_request(ctx, 404, "Alert not found")

            self.send_json_response(
                404,
                error={
                    "message": "Alert not found",
                    "alert_id": alert_id
                },
                request_id=ctx.request_id
            )
            return

        log_request(ctx, 200, "Alert status updated")

        self.send_json_response(
            200,
            data={
                "status": "updated",
                "alert": alert
            },
            request_id=ctx.request_id
        )

    def handle_alert_export(self, ctx, query_params):
        limit = query_params.get("limit", ["100"])[0]
        status = query_params.get("status", ["active"])[0]
        severity = query_params.get("severity", [None])[0]
        search = query_params.get("q", [None])[0]
        priority = query_params.get("priority", [None])[0]
        sla_status = query_params.get("sla_status", [None])[0]
        alerts = get_alerts(
            limit=limit,
            status=status,
            severity=severity,
            search=search,
            priority=priority,
            sla_status=sla_status
        )
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        csv_body = alerts_to_csv(alerts)

        log_request(ctx, 200, "Alerts CSV exported")

        self.send_csv_response(
            filename=f"zerosoc-alerts-{timestamp}.csv",
            csv_body=csv_body,
            request_id=ctx.request_id
        )

    def handle_alert_incident_export(self, ctx, query_params):
        limit = query_params.get("limit", ["100"])[0]
        status = query_params.get("status", ["active"])[0]
        severity = query_params.get("severity", [None])[0]
        search = query_params.get("q", [None])[0]
        priority = query_params.get("priority", [None])[0]
        sla_status = query_params.get("sla_status", [None])[0]
        alerts = get_alerts(
            limit=limit,
            status=status,
            severity=severity,
            search=search,
            priority=priority,
            sla_status=sla_status
        )
        incidents = group_alerts_into_incidents(alerts)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        log_request(ctx, 200, "Alert incidents CSV exported")

        self.send_csv_response(
            filename=f"zerosoc-alert-incidents-{timestamp}.csv",
            csv_body=incidents_to_csv(incidents),
            request_id=ctx.request_id
        )

    def handle_alert_incident_state_update(self, ctx, endpoint, data):
        incident_id = (
            endpoint
            .replace("/api/v1/alerts/incidents/", "")
            .replace("/state", "")
            .strip("/")
        )
        incident_id = unquote(incident_id)

        try:
            incident_state = update_incident_state(
                incident_id=incident_id,
                owner=data.get("owner"),
                note=data.get("note"),
                status=data.get("status")
            )
        except ValueError as error:
            log_request(ctx, 400, str(error))

            self.send_json_response(
                400,
                error={
                    "message": str(error)
                },
                request_id=ctx.request_id
            )
            return

        log_request(ctx, 200, "Alert incident state updated")

        self.send_json_response(
            200,
            data={
                "status": "updated",
                "incident": incident_state
            },
            request_id=ctx.request_id
        )

    def handle_alert_incident_activity(self, ctx, query_params):
        limit = query_params.get("limit", ["20"])[0]
        incident_id = query_params.get("incident_id", [None])[0]
        action = query_params.get("action", [None])[0]
        activity = get_incident_activity(
            limit=limit,
            incident_id=incident_id,
            action=action
        )

        log_request(ctx, 200, "Alert incident activity requested")

        self.send_json_response(
            200,
            data={
                "activity": activity,
                "count": len(activity),
                "filters": {
                    "limit": int(limit) if str(limit).isdigit() else 20,
                    "incident_id": incident_id,
                    "action": action
                }
            },
            request_id=ctx.request_id
        )

    def handle_alert_incident_activity_export(self, ctx, query_params):
        limit = query_params.get("limit", ["100"])[0]
        incident_id = query_params.get("incident_id", [None])[0]
        action = query_params.get("action", [None])[0]
        activity = get_incident_activity(
            limit=limit,
            incident_id=incident_id,
            action=action
        )
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        log_request(ctx, 200, "Alert incident activity CSV exported")

        self.send_csv_response(
            filename=f"zerosoc-incident-activity-{timestamp}.csv",
            csv_body=incident_activity_to_csv(activity),
            request_id=ctx.request_id
        )

    def handle_alert_reports(self, ctx, query_params):
        limit = query_params.get("limit", ["20"])[0]
        alert_id = query_params.get("alert_id", [None])[0]
        status = query_params.get("status", [None])[0]
        search = query_params.get("q", [None])[0]
        include_archived = query_params.get("include_archived", ["false"])[0]
        reports = get_alert_reports(
            limit=limit,
            alert_id=alert_id,
            status=status,
            search=search,
            include_archived=include_archived
        )

        log_request(ctx, 200, "Alert reports requested")

        self.send_json_response(
            200,
            data={
                "reports": reports,
                "count": len(reports),
                "summary": get_alert_report_summary(),
                "filters": {
                    "limit": int(limit) if str(limit).isdigit() else 20,
                    "alert_id": alert_id,
                    "status": status,
                    "q": search,
                    "include_archived": include_archived
                }
            },
            request_id=ctx.request_id
        )

    def handle_alert_report_print(self, ctx, endpoint):
        report_id = (
            endpoint
            .replace("/api/v1/alerts/reports/", "")
            .replace("/print", "")
            .strip("/")
        )

        if not report_id:
            log_request(ctx, 400, "Missing report ID")

            self.send_json_response(
                400,
                error={
                    "message": "Missing report ID"
                },
                request_id=ctx.request_id
            )
            return

        report = get_alert_report_by_id(report_id)

        if report is None:
            log_request(ctx, 404, "Alert report not found")

            self.send_json_response(
                404,
                error={
                    "message": "Alert report not found",
                    "report_id": report_id
                },
                request_id=ctx.request_id
            )
            return

        log_request(ctx, 200, "Alert investigation report print view requested")

        self.send_html_response(
            render_alert_report_html(report),
            request_id=ctx.request_id
        )

    def handle_alert_report_export(self, ctx, endpoint):
        report_id = (
            endpoint
            .replace("/api/v1/alerts/reports/", "")
            .replace("/export", "")
            .strip("/")
        )

        if not report_id:
            log_request(ctx, 400, "Missing report ID")

            self.send_json_response(
                400,
                error={
                    "message": "Missing report ID"
                },
                request_id=ctx.request_id
            )
            return

        bundle = get_alert_report_export_bundle(report_id)

        if bundle is None:
            log_request(ctx, 404, "Alert report not found")

            self.send_json_response(
                404,
                error={
                    "message": "Alert report not found",
                    "report_id": report_id
                },
                request_id=ctx.request_id
            )
            return

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        log_request(ctx, 200, "Alert investigation report export requested")

        save_report_activity(
            report_id,
            "exported",
            "Report handoff bundle exported"
        )

        self.send_json_file_response(
            filename=f"zerosoc-report-{report_id}-{timestamp}.json",
            data=bundle,
            request_id=ctx.request_id
        )

    def handle_alert_report_activity(self, ctx, query_params):
        limit = query_params.get("limit", ["20"])[0]
        report_id = query_params.get("report_id", [None])[0]
        action = query_params.get("action", [None])[0]
        activity = get_report_activity(limit=limit, report_id=report_id, action=action)

        log_request(ctx, 200, "Alert report activity requested")

        self.send_json_response(
            200,
            data={
                "activity": activity,
                "count": len(activity),
                "filters": {
                    "limit": int(limit) if str(limit).isdigit() else 20,
                    "report_id": report_id,
                    "action": action
                }
            },
            request_id=ctx.request_id
        )

    def handle_alert_report_activity_export(self, ctx, query_params):
        limit = query_params.get("limit", ["100"])[0]
        report_id = query_params.get("report_id", [None])[0]
        action = query_params.get("action", [None])[0]
        activity = get_report_activity(limit=limit, report_id=report_id, action=action)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        log_request(ctx, 200, "Alert report activity CSV exported")

        self.send_csv_response(
            filename=f"zerosoc-report-activity-{timestamp}.csv",
            csv_body=report_activity_to_csv(activity),
            request_id=ctx.request_id
        )

    def handle_alert_report_archive(self, ctx, endpoint, data):
        report_id = (
            endpoint
            .replace("/api/v1/alerts/reports/", "")
            .replace("/archive", "")
            .strip("/")
        )

        if not report_id:
            log_request(ctx, 400, "Missing report ID")

            self.send_json_response(
                400,
                error={
                    "message": "Missing report ID"
                },
                request_id=ctx.request_id
            )
            return

        report = archive_alert_report(report_id)

        if report is None:
            log_request(ctx, 404, "Alert report not found")

            self.send_json_response(
                404,
                error={
                    "message": "Alert report not found",
                    "report_id": report_id
                },
                request_id=ctx.request_id
            )
            return

        log_request(ctx, 200, "Alert investigation report archived")

        self.send_json_response(
            200,
            data={
                "status": "archived",
                "report": report,
                "summary": get_alert_report_summary()
            },
            request_id=ctx.request_id
        )

    def handle_alert_report_restore(self, ctx, endpoint, data):
        report_id = (
            endpoint
            .replace("/api/v1/alerts/reports/", "")
            .replace("/restore", "")
            .strip("/")
        )

        if not report_id:
            log_request(ctx, 400, "Missing report ID")

            self.send_json_response(
                400,
                error={
                    "message": "Missing report ID"
                },
                request_id=ctx.request_id
            )
            return

        report = restore_alert_report(report_id)

        if report is None:
            log_request(ctx, 404, "Alert report not found")

            self.send_json_response(
                404,
                error={
                    "message": "Alert report not found",
                    "report_id": report_id
                },
                request_id=ctx.request_id
            )
            return

        log_request(ctx, 200, "Alert investigation report restored")

        self.send_json_response(
            200,
            data={
                "status": "restored",
                "report": report,
                "summary": get_alert_report_summary()
            },
            request_id=ctx.request_id
        )

    def handle_alert_report_status_update(self, ctx, endpoint, data):
        report_id = (
            endpoint
            .replace("/api/v1/alerts/reports/", "")
            .replace("/status", "")
            .strip("/")
        )

        if not report_id:
            log_request(ctx, 400, "Missing report ID")

            self.send_json_response(
                400,
                error={
                    "message": "Missing report ID"
                },
                request_id=ctx.request_id
            )
            return

        try:
            report = update_alert_report_status(
                report_id=report_id,
                status=data.get("status")
            )
        except ValueError as error:
            log_request(ctx, 400, str(error))

            self.send_json_response(
                400,
                error={
                    "message": str(error)
                },
                request_id=ctx.request_id
            )
            return

        if report is None:
            log_request(ctx, 404, "Alert report not found")

            self.send_json_response(
                404,
                error={
                    "message": "Alert report not found",
                    "report_id": report_id
                },
                request_id=ctx.request_id
            )
            return

        log_request(ctx, 200, "Alert investigation report status updated")

        self.send_json_response(
            200,
            data={
                "status": "updated",
                "report": report,
                "summary": get_alert_report_summary()
            },
            request_id=ctx.request_id
        )

    def handle_alert_report_details_update(self, ctx, endpoint, data):
        report_id = (
            endpoint
            .replace("/api/v1/alerts/reports/", "")
            .replace("/details", "")
            .strip("/")
        )

        if not report_id:
            log_request(ctx, 400, "Missing report ID")

            self.send_json_response(
                400,
                error={
                    "message": "Missing report ID"
                },
                request_id=ctx.request_id
            )
            return

        report = update_alert_report_details(
            report_id=report_id,
            title=data.get("title"),
            summary=data.get("summary")
        )

        if report is None:
            log_request(ctx, 404, "Alert report not found")

            self.send_json_response(
                404,
                error={
                    "message": "Alert report not found",
                    "report_id": report_id
                },
                request_id=ctx.request_id
            )
            return

        log_request(ctx, 200, "Alert investigation report details updated")

        self.send_json_response(
            200,
            data={
                "status": "updated",
                "report": report,
                "summary": get_alert_report_summary()
            },
            request_id=ctx.request_id
        )

    def handle_alert_report_create(self, ctx, endpoint, data):
        alert_id = endpoint.replace("/api/v1/alerts/", "").replace("/report", "").strip("/")

        if not alert_id:
            log_request(ctx, 400, "Missing alert ID")

            self.send_json_response(
                400,
                error={
                    "message": "Missing alert ID"
                },
                request_id=ctx.request_id
            )
            return

        report = save_alert_report(
            alert_id=alert_id,
            title=data.get("title"),
            summary=data.get("summary"),
            status=data.get("status", "draft")
        )

        if report is None:
            log_request(ctx, 404, "Alert not found")

            self.send_json_response(
                404,
                error={
                    "message": "Alert not found",
                    "alert_id": alert_id
                },
                request_id=ctx.request_id
            )
            return

        log_request(ctx, 201, "Alert investigation report saved")

        self.send_json_response(
            201,
            data={
                "status": "created",
                "report": report
            },
            request_id=ctx.request_id
        )

    def handle_alert_notifications(self, ctx, query_params):
        limit = query_params.get("limit", ["20"])[0]
        notifications = get_alert_notifications(limit=limit)

        log_request(ctx, 200, "Alert notifications requested")

        self.send_json_response(
            200,
            data={
                "notifications": notifications,
                "count": len(notifications),
                "summary": get_alert_notification_summary(),
                "filters": {
                    "limit": int(limit) if str(limit).isdigit() else 20
                }
            },
            request_id=ctx.request_id
        )

    def handle_alert_notification_delivery(self, ctx, data):
        result = notify_unresolved_alerts(
            channel=data.get("channel", "local"),
            cooldown_seconds=data.get("cooldown_seconds")
        )

        log_request(ctx, 200, "Unresolved alert notifications delivered")

        self.send_json_response(
            200,
            data=result,
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
        
    def get_device_filters(self, query_params, default_limit="50"):
        limit = query_params.get("limit", [default_limit])[0]

        return {
            "limit": limit,
            "status": query_params.get("status", [None])[0],
            "q": query_params.get("q", [None])[0]
        }

    def handle_devices(self, ctx, query_params=None):
        filters = self.get_device_filters(query_params or {})
        devices = get_recent_network_devices(
            limit=filters["limit"],
            status=filters["status"],
            search=filters["q"]
        )

        log_request(ctx, 200, "Network devices requested")

        self.send_json_response(
            200,
            data={
                "devices": devices,
                "count": len(devices),
                "summary": get_network_device_summary(devices),
                "filters": {
                    "limit": int(filters["limit"]) if str(filters["limit"]).isdigit() else 50,
                    "status": filters["status"],
                    "q": filters["q"]
                }
            },
            request_id=ctx.request_id
        )

    def handle_devices_export(self, ctx, query_params):
        filters = self.get_device_filters(query_params, default_limit="100")
        devices = get_recent_network_devices(
            limit=filters["limit"],
            status=filters["status"],
            search=filters["q"]
        )

        log_request(ctx, 200, "Network devices CSV exported")
        self.send_csv_response("zerosoc-network-devices.csv", network_devices_to_csv(devices), ctx.request_id)
        
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
                "unknown_devices": processed["unknown_devices"],
                "summary": get_network_device_summary(processed["devices"])
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

        if endpoint == "/api/v1/events/export":
            self.handle_events_export(ctx, query_params)
            return

        if endpoint == "/api/v1/alerts":
            self.handle_alerts(ctx, query_params)
            return

        if endpoint == "/api/v1/alerts/export":
            self.handle_alert_export(ctx, query_params)
            return

        if endpoint == "/api/v1/alerts/incidents/export":
            self.handle_alert_incident_export(ctx, query_params)
            return

        if endpoint == "/api/v1/alerts/incidents/activity/export":
            self.handle_alert_incident_activity_export(ctx, query_params)
            return

        if endpoint == "/api/v1/alerts/incidents/activity":
            self.handle_alert_incident_activity(ctx, query_params)
            return

        if endpoint == "/api/v1/alerts/reports":
            self.handle_alert_reports(ctx, query_params)
            return

        if endpoint == "/api/v1/alerts/reports/activity/export":
            self.handle_alert_report_activity_export(ctx, query_params)
            return

        if endpoint == "/api/v1/alerts/reports/activity":
            self.handle_alert_report_activity(ctx, query_params)
            return

        if endpoint.startswith("/api/v1/alerts/reports/") and endpoint.endswith("/print"):
            self.handle_alert_report_print(ctx, endpoint)
            return

        if endpoint.startswith("/api/v1/alerts/reports/") and endpoint.endswith("/export"):
            self.handle_alert_report_export(ctx, endpoint)
            return

        if endpoint == "/api/v1/alerts/notifications":
            self.handle_alert_notifications(ctx, query_params)
            return

        if endpoint == "/api/v1/events":
            self.handle_events(ctx, query_params)
            return

        if endpoint.startswith("/api/v1/events/"):
            self.handle_event_by_id(ctx, endpoint)
            return

        if endpoint == "/api/v1/devices/export":
            self.handle_devices_export(ctx, query_params)
            return

        if endpoint == "/api/v1/devices":
            self.handle_devices(ctx, query_params)
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

        if endpoint == "/api/v1/alerts/notifications":
            self.handle_alert_notification_delivery(ctx, data)
            return

        if endpoint.startswith("/api/v1/alerts/incidents/") and endpoint.endswith("/state"):
            self.handle_alert_incident_state_update(ctx, endpoint, data)
            return

        if endpoint.startswith("/api/v1/alerts/reports/") and endpoint.endswith("/status"):
            self.handle_alert_report_status_update(ctx, endpoint, data)
            return

        if endpoint.startswith("/api/v1/alerts/reports/") and endpoint.endswith("/details"):
            self.handle_alert_report_details_update(ctx, endpoint, data)
            return

        if endpoint.startswith("/api/v1/alerts/reports/") and endpoint.endswith("/archive"):
            self.handle_alert_report_archive(ctx, endpoint, data)
            return

        if endpoint.startswith("/api/v1/alerts/reports/") and endpoint.endswith("/restore"):
            self.handle_alert_report_restore(ctx, endpoint, data)
            return

        if endpoint.startswith("/api/v1/alerts/") and endpoint.endswith("/report"):
            self.handle_alert_report_create(ctx, endpoint, data)
            return

        if endpoint.startswith("/api/v1/alerts/") and endpoint.endswith("/status"):
            self.handle_alert_status_update(ctx, endpoint, data)
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
    print("  /api/v1/logs/recent")
    print("  /api/v1/metrics")
    print("")
    print("Security events:")
    print("  GET  /api/v1/events")
    print("  GET  /api/v1/events/export")
    print("  GET  /api/v1/events/{id}")
    print("  GET  /api/v1/events/summary")
    print("  POST /api/v1/events")
    print("")
    print("Alerts:")
    print("  GET  /api/v1/alerts")
    print("  GET  /api/v1/alerts/export")
    print("  POST /api/v1/alerts/{id}/status")
    print("")
    print("Alert incidents:")
    print("  GET  /api/v1/alerts/incidents/export")
    print("  GET  /api/v1/alerts/incidents/activity")
    print("  GET  /api/v1/alerts/incidents/activity/export")
    print("  POST /api/v1/alerts/incidents/{incident_id}/state")
    print("")
    print("Alert reports:")
    print("  GET  /api/v1/alerts/reports")
    print("  GET  /api/v1/alerts/reports/activity")
    print("  GET  /api/v1/alerts/reports/activity/export")
    print("  GET  /api/v1/alerts/reports/{id}/print")
    print("  GET  /api/v1/alerts/reports/{id}/export")
    print("  POST /api/v1/alerts/{id}/report")
    print("  POST /api/v1/alerts/reports/{id}/status")
    print("  POST /api/v1/alerts/reports/{id}/details")
    print("  POST /api/v1/alerts/reports/{id}/archive")
    print("  POST /api/v1/alerts/reports/{id}/restore")
    print("")
    print("Alert notifications:")
    print("  GET  /api/v1/alerts/notifications")
    print("  POST /api/v1/alerts/notifications")
    print("")
    print("Network devices:")
    print("  GET  /api/v1/devices")
    print("  GET  /api/v1/devices/export")
    print("  GET  /api/v1/network/scan")
    server.serve_forever()


if __name__ == "__main__":
    run_server()