# ZeroSOC

ZeroSOC is a lightweight cybersecurity monitoring dashboard built with Python, SQLite, and a simple web frontend. It is designed as a small home-lab SOC-style project that monitors local system health, tracks API activity, stores security events, scans local network devices, groups alerts into incidents, tracks investigation reports, and displays operational data in a browser dashboard.

The project is intended to run on lightweight hardware such as a Raspberry Pi Zero 2 W, while also being easy to develop and test on a Windows machine.

---

## Project Overview

ZeroSOC is being built as a cybersecurity and backend development portfolio project.

The goal is to demonstrate practical backend engineering, API design, local persistence, request logging, basic security controls, network visibility, alert workflows, incident tracking, investigation reporting, and dashboard presentation in one compact project.

ZeroSOC currently includes:

- Python backend server
- Versioned API routes
- Protected API endpoints
- API key authentication
- SQLite database storage
- Structured request logging
- Request ID tracking
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
- Incident activity tracking
- Investigation report tracking
- Alert notification tracking
- CSV export support for alerts, incidents, security events, network devices, and investigation activity
- JSON export support for investigation report handoff bundles
- Web dashboard using HTML, CSS, JavaScript, and Chart.js

---

## Dashboard Preview

ZeroSOC includes a browser-based dashboard that displays backend API data in a clean light-gray SOC-style interface with readable cards, accessible focus states, visible action buttons, responsive filter toolbars, and dashboard summary sections.

The dashboard includes:

- API status indicator
- Refresh control
- Summary cards
- System status panel
- Metrics panel
- Event summary section
- Security event analytics charts
- Searchable and filterable security events table
- Exportable security event CSVs
- Active alerts section
- Alert priority and SLA filters
- Incident groups
- Incident activity tracking
- Alert notifications panel
- Investigation reports panel
- Report activity tracking
- Resolved alerts section
- Searchable and filterable network devices table
- Device freshness summaries
- Dashboard-triggered network scans

---

## Screenshots

### Dashboard Overview

![ZeroSOC Dashboard Overview](screenshots/dashboard-overview.png)

The dashboard overview shows the ZeroSOC header, local SOC overview label, API status indicator, refresh control, summary cards, system status panel, and backend metrics.

### Event Summary and Security Event Analytics

![ZeroSOC Event Summary and Security Event Analytics](screenshots/event-summary-analytics.png)

The event summary and analytics section shows total security events, severity counts, event type breakdowns, tag summaries, and charts for events by severity and event type.

### Alerts, Incidents, and Notifications

![ZeroSOC Alerts, Incidents, and Notifications](screenshots/alerts-incidents-notifications.png)

The alerts workflow section shows active alert filters, priority filters, SLA filters, alert search, CSV export controls, incident groups, incident activity, and alert notifications.

### Investigation Reports and Resolved Alerts

![ZeroSOC Investigation Reports and Resolved Alerts](screenshots/reports-resolved-alerts.png)

The investigation and resolution section shows investigation report filters, report activity tracking, export controls, resolved alert history, SLA resolution details, and reopen actions.

### Security Events and Network Devices

![ZeroSOC Security Events and Network Devices](screenshots/events-devices.png)

The event and device sections show searchable security events, time-range filtering, event export controls, device inventory, device status filtering, network scan controls, and device CSV export support.

### API Health Response

![ZeroSOC API Health Response](screenshots/api-health.png)

The health endpoint confirms that the ZeroSOC backend is running and returning structured API responses.

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

ZeroSOC exposes system status data through API endpoints. This includes service status, host information, uptime, platform details, Python version, disk usage, and current backend runtime information.

### API Key Authentication

Protected endpoints require an API key using the `X-API-Key` header.

Example:

```powershell
Invoke-RestMethod "http://localhost:8000/api/v1/system" -Headers @{"X-API-Key"="dev-zero-soc-key"}
```

### Request Logging

ZeroSOC records API request activity using structured logs. Request logs include request ID, method, endpoint, client IP, status code, latency, timestamp, and message.

### Security Event Collection

Security events can be created, stored, filtered, summarized, exported, and reviewed through the API and dashboard.

Security event data includes:

- Event ID
- Timestamp
- Source IP
- Event type
- Severity
- Message
- Tags

### Event Auto-Tagging

ZeroSOC automatically assigns tags to events based on severity, event type, source, and message content.

Example tags include:

- `high-priority`
- `needs-review`
- `failed-login`
- `authentication`
- `network`
- `possible-recon`
- `unknown-device`
- `malware-related`
- `system`
- `storage`

### Alert Workflow

High-priority and review-worthy events are surfaced as alerts. Alerts can be filtered, acknowledged, resolved, reopened, exported, and grouped into incidents.

Alert workflow features include:

- Active alerts
- Resolved alerts
- Alert status updates
- Acknowledgement notes
- Priority scoring
- SLA tracking
- Overdue and due-soon states
- Alert CSV export

### Incident Grouping

Alerts are grouped into incident-style views by source and event type. Incident groups can be assigned an owner, given notes, updated by status, and exported.

Incident features include:

- Incident grouping
- Incident owner tracking
- Incident status tracking
- Incident notes
- Incident activity history
- Incident activity export
- Incident CSV export

### Investigation Reports

ZeroSOC supports lightweight investigation reports tied to alerts.

Report features include:

- Create report from alert
- Edit report title and summary
- Mark report as draft or final
- Print report view
- Export report handoff JSON
- Archive and restore reports
- Report activity tracking
- Report activity CSV export

### Alert Notifications

ZeroSOC tracks alert notifications locally and supports optional webhook delivery.

Notification features include:

- Local notification log
- Optional webhook delivery
- Notification cooldown
- Delivered, failed, and skipped notification states
- Notification history in the dashboard

### Network Device Monitoring

ZeroSOC can scan the local network, identify active devices, store discovered devices, and create security events for unknown devices.

Device data includes:

- IP address
- Hostname
- MAC address
- Status
- First seen timestamp
- Last seen timestamp
- Stale device status

### Dashboard UI

The dashboard displays backend data through a browser-based interface using HTML, CSS, JavaScript, and Chart.js.

Dashboard features include:

- System status
- API metrics
- Event summaries
- Security event analytics charts
- Active alert queue
- Incident groups
- Incident activity
- Alert notifications
- Investigation reports
- Report activity
- Resolved alerts
- Searchable security events
- Searchable network devices
- CSV export controls
- Dashboard-triggered network scans

---

## API Endpoints

ZeroSOC exposes public service-check endpoints and protected SOC data endpoints.

Protected endpoints require:

```text
X-API-Key: dev-zero-soc-key
```

### Public Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/health` | Basic backend health check |
| GET | `/api/v1/status` | Lightweight service status |

### Protected Core Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/system` | Host system health and machine details |
| GET | `/api/v1/metrics` | Request, event, and device metrics |
| GET | `/api/v1/logs/recent` | Recent API request logs |

### Security Event Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/events` | List recent security events with optional filters |
| GET | `/api/v1/events/export` | Export security events as CSV |
| GET | `/api/v1/events/summary` | Security event summary and counts |
| GET | `/api/v1/events/{id}` | Retrieve a single security event by ID |
| POST | `/api/v1/events` | Create a manual security event |

### Alert Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/alerts` | List active, acknowledged, or resolved alerts |
| GET | `/api/v1/alerts/export` | Export alerts as CSV |
| POST | `/api/v1/alerts/{id}/status` | Update alert status or acknowledgement note |

### Incident Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/alerts/incidents/export` | Export grouped alert incidents as CSV |
| GET | `/api/v1/alerts/incidents/activity` | List incident activity history |
| GET | `/api/v1/alerts/incidents/activity/export` | Export incident activity as CSV |
| POST | `/api/v1/alerts/incidents/{incident_id}/state` | Update incident owner, note, or status |

### Investigation Report Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/alerts/reports` | List investigation reports |
| GET | `/api/v1/alerts/reports/activity` | List investigation report activity |
| GET | `/api/v1/alerts/reports/activity/export` | Export report activity as CSV |
| GET | `/api/v1/alerts/reports/{id}/print` | Open printable investigation report view |
| GET | `/api/v1/alerts/reports/{id}/export` | Export investigation report handoff JSON |
| POST | `/api/v1/alerts/{id}/report` | Create an investigation report for an alert |
| POST | `/api/v1/alerts/reports/{id}/status` | Update report status |
| POST | `/api/v1/alerts/reports/{id}/details` | Update report title or summary |
| POST | `/api/v1/alerts/reports/{id}/archive` | Archive an investigation report |
| POST | `/api/v1/alerts/reports/{id}/restore` | Restore an archived investigation report |

### Notification Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/alerts/notifications` | List alert notification history |
| POST | `/api/v1/alerts/notifications` | Log or send notifications for unresolved alerts |

### Network Device Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/devices` | List known network devices |
| GET | `/api/v1/devices/export` | Export network devices as CSV |
| GET | `/api/v1/network/scan` | Run local network scan and detect unknown devices |

---

## Query Filters

### Security Events

`GET /api/v1/events` supports optional filters:

| Query Parameter | Description |
|---|---|
| `limit` | Maximum number of events to return |
| `severity` | Filter by severity: `critical`, `high`, `medium`, `low` |
| `tag` | Filter by event tag |
| `event_type` | Filter by event type |
| `source` | Filter by source IP |
| `q` | Search source, type, message, or tags |
| `since_hours` | Return events from the last N hours |

Examples:

```text
/api/v1/events?severity=high
/api/v1/events?since_hours=24
/api/v1/events?q=login
```

### Alerts

`GET /api/v1/alerts` supports optional filters:

| Query Parameter | Description |
|---|---|
| `limit` | Maximum number of alerts to return |
| `status` | Filter by `active`, `open`, `acknowledged`, `resolved`, or `all` |
| `severity` | Filter by severity |
| `priority` | Filter by `urgent`, `high`, `medium`, or `low` |
| `sla_status` | Filter by `on-track`, `due-soon`, `overdue`, `resolved`, or `unknown` |
| `q` | Search source, message, or event type |

Examples:

```text
/api/v1/alerts?status=active
/api/v1/alerts?priority=urgent
/api/v1/alerts?sla_status=overdue
```

### Network Devices

`GET /api/v1/devices` supports optional filters:

| Query Parameter | Description |
|---|---|
| `limit` | Maximum number of devices to return |
| `status` | Filter by device status |
| `q` | Search IP, hostname, MAC address, or status |

Examples:

```text
/api/v1/devices?status=online
/api/v1/devices?q=192
```

---

## Running Locally

### 1. Clone the repository

```bash
git clone https://github.com/britufkin1225-web/zerosoc.git
cd zerosoc
```

### 2. Run the backend

```bash
python run.py
```

Backend URL:

```text
http://localhost:8000
```

### 3. Run the dashboard locally

From the project root:

```bash
python -m http.server 5500
```

Dashboard URL:

```text
http://localhost:5500/dashboard/
```

---

## Local Testing Checklist

### Public Browser Tests

These can be opened directly in the browser:

```text
http://localhost:8000/api/v1/health
http://localhost:8000/api/v1/status
```

Expected:

- `success: true`
- `status_code: 200`
- JSON response body

### Protected API Tests

Protected routes require the API key header. Use PowerShell:

```powershell
$headers = @{ "X-API-Key" = "dev-zero-soc-key" }

Invoke-RestMethod -Uri "http://localhost:8000/api/v1/system" -Headers $headers
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/metrics" -Headers $headers
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/logs/recent" -Headers $headers
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/events" -Headers $headers
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/events/summary" -Headers $headers
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/alerts" -Headers $headers
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/devices" -Headers $headers
```

Expected:

- No `401` when the API key header is included
- No `500` server errors
- JSON responses return normally

### Dashboard Smoke Test

After starting the backend and dashboard server, verify:

- API indicator shows online
- Summary cards load
- System status loads
- Metrics load
- Event summary loads
- Security event charts render
- Alert filters work
- Event search works
- Event severity filter works
- Event time-range filter works
- Export Events button downloads CSV
- Export Alerts button downloads CSV
- Export Incidents button downloads CSV
- Report filters work
- Export Report Activity downloads CSV
- Device search works
- Device status filter works
- Export Devices button downloads CSV
- Run Scan button starts a network scan without breaking the dashboard

## Project Documentation

Additional project documentation is available in the `docs/` folder.

| Document | Purpose |
|---|---|
| [`backend-api-test-checklist.md`](docs/backend-api-test-checklist.md) | Checklist for testing backend API endpoints |
| [`dashboard-smoke-test-checklist.md`](docs/dashboard-smoke-test-checklist.md) | Checklist for testing dashboard functionality |
| [`screenshots-inventory.md`](docs/screenshots-inventory.md) | Tracks README screenshot files and screenshot status |
| [`known-limitations-and-next-upgrades.md`](docs/known-limitations-and-next-upgrades.md) | Tracks current limitations and future upgrade ideas |

---

## Project Timeline

### Phase 1: Project Foundation

- [x] Create GitHub repository
- [x] Add initial folder structure
- [x] Add `run.py`
- [x] Add `requirements.txt`
- [x] Add `.env.example`
- [x] Add `.gitignore`
- [x] Add README

### Phase 2: Core Backend API

- [x] Build lightweight Python HTTP server
- [x] Add JSON responses
- [x] Add `/api/v1/health`
- [x] Add `/api/v1/status`
- [x] Add `/api/v1/system`
- [x] Add route normalization
- [x] Add structured 404 responses

### Phase 3: System Visibility

- [x] Add hostname reporting
- [x] Add OS/platform reporting
- [x] Add Python version reporting
- [x] Add uptime tracking
- [x] Add disk usage reporting
- [x] Add Raspberry Pi-compatible CPU temperature support
- [x] Split `/status` and `/system` responsibilities

### Phase 4: API Security and Logging

- [x] Add API key authentication
- [x] Add protected endpoint list
- [x] Add request IDs
- [x] Add structured request logging
- [x] Store request logs
- [x] Add recent logs endpoint
- [x] Add metrics endpoint

### Phase 5: Security Events

- [x] Add security event storage
- [x] Add event auto-tagging
- [x] Add event filtering
- [x] Add event summary endpoint
- [x] Add event by ID endpoint
- [x] Add event CSV export
- [x] Add manual event creation endpoint

### Phase 6: Alerts and Incidents

- [x] Generate alerts from high-priority events
- [x] Add alert status workflow
- [x] Add alert priority scoring
- [x] Add alert SLA tracking
- [x] Add alert filtering
- [x] Add alert CSV export
- [x] Add incident grouping
- [x] Add incident state updates
- [x] Add incident activity tracking
- [x] Add incident CSV exports

### Phase 7: Reports and Notifications

- [x] Add investigation report creation
- [x] Add report editing
- [x] Add report status updates
- [x] Add report print view
- [x] Add report JSON export
- [x] Add report archive/restore
- [x] Add report activity tracking
- [x] Add alert notification logging
- [x] Add optional webhook notification support

### Phase 8: Local Network Monitoring

- [x] Add local network scanner
- [x] Add ARP/MAC detection
- [x] Add device inventory
- [x] Add unknown device detection
- [x] Add device search and status filtering
- [x] Add stale device visibility
- [x] Add device CSV export

### Phase 9: Dashboard UI

- [x] Build dashboard frontend
- [x] Add summary cards
- [x] Add system health panel
- [x] Add metrics panel
- [x] Add event summary section
- [x] Add security event analytics charts
- [x] Add alert workflow panels
- [x] Add incident workflow panels
- [x] Add notification panel
- [x] Add investigation reports panel
- [x] Add resolved alerts panel
- [x] Add network devices panel
- [x] Add dashboard export controls
- [x] Add dashboard-triggered network scan
- [x] Improve dashboard styling and readability
- [x] Add safer frontend event bindings

### Phase 10: Raspberry Pi Deployment

- [ ] Deploy backend to Raspberry Pi Zero 2 W
- [ ] Enable SSH access
- [ ] Install project requirements
- [ ] Run backend on Raspberry Pi
- [ ] Test dashboard against Raspberry Pi backend
- [ ] Add systemd service
- [ ] Start ZeroSOC automatically on boot

### Phase 11: Portfolio Polish

- [x] Add screenshots
- [x] Add endpoint documentation
- [x] Add local testing checklist
- [x] Add dashboard smoke test checklist
- [ ] Add architecture diagram
- [ ] Add Raspberry Pi deployment guide
- [ ] Add final demo walkthrough

---

## Current Status

ZeroSOC is currently in the stabilization, testing, documentation, and portfolio polish stage.

Backend functionality is mostly complete for a portfolio-ready first version. The current focus is:

- Testing all endpoints
- Keeping dashboard controls stable
- Updating README documentation
- Adding final screenshots
- Preparing for Raspberry Pi deployment
- Improving project organization later

---

## Known Limitations

- The project currently uses Python’s built-in HTTP server rather than a production web framework.
- The development API key defaults to `dev-zero-soc-key`.
- Browser testing cannot directly send the protected API key header from the address bar.
- Protected routes should be tested through PowerShell, API tools, or the dashboard.
- Network scanning may be slow depending on the local subnet and host response times.
- CPU temperature may return `null` on Windows because Raspberry Pi thermal paths are not available.
- The backend is currently contained mainly in `run.py`; future cleanup should split logic into modules.
- Webhook notifications require `ZEROSOC_ALERT_WEBHOOK_URL` to be configured.
- Raspberry Pi deployment has not been completed yet.

---

## Future Improvements

Planned future improvements include:

- Split backend logic into modules
- Add Raspberry Pi deployment instructions
- Add systemd service setup
- Add environment-based production configuration
- Improve dashboard error handling
- Add pagination for larger event/device lists
- Add architecture diagram
- Add demo walkthrough
- Add additional screenshots
- Optional future migration to FastAPI

---

## Suggested Future Project Structure

```text
app/
  __init__.py
  config.py
  database.py
  auth.py
  logging_utils.py
  system.py
  events.py
  alerts.py
  incidents.py
  reports.py
  notifications.py
  devices.py
  scanner.py
  handlers.py

dashboard/
  index.html
  style.css
  app.js

screenshots/
  dashboard-overview.png
  event-summary-analytics.png
  alerts-incidents-notifications.png
  reports-resolved-alerts.png
  events-devices.png
  api-health.png
  events-summary.png

data/
  zerosoc.db

logs/
  requests.log

run.py
README.md
requirements.txt
.env.example
.gitignore
```

---

## Portfolio Value

ZeroSOC demonstrates practical skills in:

- Backend API development
- API authentication
- Request logging
- SQLite persistence
- Security event modeling
- Event classification and tagging
- SOC-style alert workflows
- Incident grouping
- Investigation reporting
- Local network monitoring
- Dashboard frontend development
- Data export workflows
- GitHub project documentation

---

## License

This project is intended as a personal cybersecurity/backend portfolio project.