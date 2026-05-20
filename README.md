# ZeroSOC

ZeroSOC is a lightweight cybersecurity monitoring dashboard built with Python, SQLite, and a simple web frontend. It is designed as a small home-lab SOC-style project that can monitor local system health, track API activity, store security events, scan local network devices, group alerts into incidents, track investigation reports, and display key information in a browser dashboard.

The project is intended to run on lightweight hardware such as a Raspberry Pi Zero 2 W, while also being easy to develop and test on a Windows machine.

---

## Project Overview

ZeroSOC is being built as a cybersecurity and backend development portfolio project.

The goal is to demonstrate practical backend engineering, API design, local persistence, request logging, basic security controls, network visibility, alert workflows, incident tracking, and dashboard presentation in one compact project.

ZeroSOC currently includes:

- Python backend server
- Protected API endpoints
- API key authentication
- SQLite database storage
- Structured request logging
- Security event collection
- Event auto-tagging
- Event severity classification
- Event summary reporting
- Time-window filtering for security event review
- Local network device scanning
- Unknown device detection
- Automatic alert creation from notable events
- Alert status workflow
- Alert SLA tracking with overdue and due-soon states
- Priority and SLA filtering for alert queues
- Incident grouping
- Incident overdue-alert rollups
- Investigation report tracking
- CSV export support for alerts, incidents, security events, network devices, and investigation activity
- Web dashboard using HTML, CSS, and JavaScript
- Brighter daylight dashboard theme with accessible focus states and responsive filter toolbars
- Dashboard summary cards
- System status panel
- Metrics panel
- Event summary dashboard section
- Security event analytics charts
- Searchable and filterable security events table
- Exportable security event evidence CSVs
- Active alerts section
- Alert notifications section
- Investigation reports section
- Report activity tracking
- Resolved alerts section
- Searchable, filterable, and exportable network devices table
- Device freshness summaries with stale-device visibility
- Dashboard-triggered network scans

---

## Dashboard Preview

ZeroSOC includes a browser-based dashboard that displays backend API data in a refined dark-gray SOC-style interface with improved contrast, readable cards, accessible focus states, visible action buttons, and responsive filter toolbars.

The updated dashboard theme includes:

- Dark gray dashboard layout with improved contrast
- Clearer summary cards
- More readable system and metrics panels
- Improved alert and export button visibility
- Better hover and focus states
- Searchable and filterable event sections
- Security event analytics charts
- Active alert, incident, notification, report, and resolved-alert workflow sections
- Network device visibility
- Dashboard-triggered network scan controls

---

## Screenshots

### Dashboard Overview

![ZeroSOC Dashboard Overview](screenshots/dashboard-overview.png)

The dashboard overview shows the updated ZeroSOC theme, header, local SOC overview label, API status indicator, refresh control, summary cards, system status panel, and backend metrics.

### Event Summary and Security Event Analytics

![ZeroSOC Event Summary and Security Event Analytics](screenshots/event-summary-analytics.png)

The event summary and analytics section shows total security events, severity counts, event type breakdowns, tag summaries, and dashboard charts for events by severity and event type.

### Alerts, Incidents, and Notifications

![ZeroSOC Alerts, Incidents, and Notifications](screenshots/alerts-incidents-notifications.png)

The alerts workflow section shows active alert filters, priority filters, SLA filters, alert search, CSV export controls, incident groups, incident activity, and alert notifications.

### Investigation Reports and Resolved Alerts

![ZeroSOC Investigation Reports and Resolved Alerts](screenshots/reports-resolved-alerts.png)

The investigation and resolution section shows investigation report filters, report activity tracking, export controls, resolved alert history, SLA resolution details, and reopen actions.

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
| Charts | Chart.js |
| Logging | JSON-style request logs |
| Security | API key authentication |
| Platform Target | Raspberry Pi Zero 2 W / Windows development machine |
| Version Control | Git and GitHub |

---

## Core Features

### System Health Monitoring

ZeroSOC exposes system status data through API endpoints. This includes basic service status, host information, uptime, platform details, Python version, disk usage, and current backend runtime information.

### API Key Authentication

Protected endpoints require an API key using the `X-API-Key` header.

Example:

```powershell
Invoke-RestMethod http://localhost:8000/api/v1/system -Headers @{"X-API-Key"="dev-zero-soc-key"}