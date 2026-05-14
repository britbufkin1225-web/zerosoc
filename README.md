# ZeroSOC

ZeroSOC is a lightweight cybersecurity monitoring dashboard built with Python, SQLite, and a simple web frontend. It is designed as a small home-lab SOC-style project that can monitor local system health, track API activity, store security events, scan local network devices, and display key information in a browser dashboard.

The project is intended to run on lightweight hardware such as a Raspberry Pi Zero 2 W, while also being easy to develop and test on a Windows machine.

---

## Project Overview

ZeroSOC is being built as a cybersecurity and backend development portfolio project.

The goal is to demonstrate practical backend engineering, API design, local persistence, request logging, basic security controls, network visibility, and dashboard presentation in one compact project.

ZeroSOC currently includes:

- Python backend server
- Protected API endpoints
- API key authentication
- SQLite database storage
- Structured request logging
- Security event collection
- Event auto-tagging
- Event summary reporting
- Local network device scanning
- Unknown device detection
- Web dashboard with status cards
- Event summary dashboard section
- Active alerts section
- Investigation reports section
- Resolved alerts section
- Basic frontend using HTML, CSS, and JavaScript

---

## Screenshots

---

### Dashboard Main View

![ZeroSOC Dashboard Main View](screenshots/dashboard-main.png)

The main dashboard view shows the ZeroSOC header, API status indicator, summary cards, system status, and backend metrics.

### Event Summary and Active Alerts

![ZeroSOC Event Summary and Active Alerts](screenshots/dashboard-events-alerts.png)

The event summary section displays total security events, severity breakdowns, event types, tags, and active alert controls.

### Investigation Reports and Resolved Alerts

![ZeroSOC Investigation Reports and Resolved Alerts](screenshots/dashboard-reports-alerts.png)

The reports and resolved alerts section shows investigation report controls, report activity tracking, and resolved alert history.

### API Health Response

![ZeroSOC API Health Response](screenshots/api-health.png)

The health endpoint confirms that the ZeroSOC backend is running and returning structured API responses.

### Events Summary API Response

![ZeroSOC Events Summary API Response](screenshots/events-summary.png)

The events summary API response shows aggregated security event data returned from the backend.

---

## Tech Stack

| Area | Technology |
|---|---|
| Backend | Python |
| Server | `http.server` / `BaseHTTPRequestHandler` |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Logging | JSON-style request logs |
| Security | API key authentication |
| Platform Target | Raspberry Pi Zero 2 W / Windows development machine |
| Version Control | Git and GitHub |

---

## Core Features

### System Health Monitoring

ZeroSOC exposes system status data through API endpoints. This includes basic service status, host information, uptime, platform details, and disk usage.

### API Key Authentication

Protected endpoints require an API key using the `X-API-Key` header.

Example:

```powershell
Invoke-RestMethod http://localhost:8000/api/v1/system -Headers @{"X-API-Key"="dev-zero-soc-key"}