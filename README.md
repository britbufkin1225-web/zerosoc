# ZeroSOC

ZeroSOC is a lightweight cybersecurity monitoring dashboard built with Python, SQLite, and a simple web frontend. It is designed as a small home-lab SOC-style project that monitors local system health, tracks API activity, stores security events, scans local network devices, groups alerts into incidents, tracks investigation reports, and displays operational data in a browser dashboard.

The project is intended to run on lightweight hardware such as a Raspberry Pi Zero 2 W, while also being easy to develop and test on a Windows machine.

## Current Status

ZeroSOC is currently in the stabilization, testing, documentation, and portfolio polish stage.

The backend API, SQLite persistence layer, security event system, alert workflow, incident grouping, investigation reporting, local network device monitoring, and browser dashboard are functional for a portfolio-ready first version.

Current work is focused on:

- Testing all API endpoints
- Verifying dashboard controls
- Keeping screenshots updated
- Preparing Raspberry Pi deployment
- Improving project documentation
- Adding the final architecture diagram and demo walkthrough
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
## What This Demonstrates

ZeroSOC demonstrates practical cybersecurity and backend development skills through a working local SOC-style monitoring dashboard.

Key demonstrated skills include:

- Backend API design using Python
- API key authentication for protected routes
- SQLite database storage for security events and network devices
- Request logging and request ID tracking
- Security event classification and auto-tagging
- Alert workflow design with SLA and priority tracking
- Incident grouping and investigation report workflows
- Local network scanning and unknown-device detection
- Frontend dashboard development using HTML, CSS, JavaScript, and Chart.js
- GitHub documentation with screenshots, endpoint references, and test checklists

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

## Architecture Overview

ZeroSOC uses a lightweight local architecture designed for home-lab monitoring and portfolio demonstration.

The system includes a Python backend API, SQLite database storage, local request logging, network scanning logic, and a browser-based dashboard frontend. The dashboard communicates with the backend API to display system status, security events, alerts, incidents, investigation reports, notifications, and network device data.

```text
Browser Dashboard
HTML / CSS / JavaScript / Chart.js
        |
        | HTTP API Requests
        v
Python Backend API
http.server / BaseHTTPRequestHandler
        |
        | Reads and writes data
        v
SQLite Database
Security Events / Alerts / Incidents / Reports / Devices
        |
        | Local runtime files
        v
Logs and Exports
Request Logs / CSV Exports / JSON Report Bundles

Local System + Network
System Health / Metrics / Network Scan / ARP Data
        |
        v
SOC Logic
Auto-Tagging / Alert Creation / Unknown Device Detection
```

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

Additional project documentation is available in the `docs/` folder. These files support testing, screenshot tracking, and future project cleanup.

| Document | Purpose |
|---|---|
| [`backend-api-test-checklist.md`](docs/backend-api-test-checklist.md) | Step-by-step checklist for testing public and protected backend API endpoints |
| [`dashboard-smoke-test-checklist.md`](docs/dashboard-smoke-test-checklist.md) | Checklist for verifying dashboard loading, controls, filters, charts, exports, and scan actions |
| [`screenshots-inventory.md`](docs/screenshots-inventory.md) | Tracks README screenshot files, screenshot names, and screenshot update status |
| [`known-limitations-and-next-upgrades.md`](docs/known-limitations-and-next-upgrades.md) | Tracks current project limitations, cleanup ideas, and planned future upgrades |

---

## Project Timeline

### Phase 1: Project Foundation

The foundation phase established the initial project repository, file structure, and baseline documentation needed to begin building ZeroSOC as a portfolio-ready cybersecurity/backend project.

#### Completed Work

- [x] Created GitHub repository
- [x] Added initial project folder structure
- [x] Added main backend entry point with `run.py`
- [x] Added dependency tracking with `requirements.txt`
- [x] Added environment variable example file with `.env.example`
- [x] Added ignored local/runtime files with `.gitignore`
- [x] Added initial README documentation

---

### Phase 2: Core Backend API

Phase 2 focused on building the main backend API layer for ZeroSOC. This phase established the server structure, protected API routes, request handling, response formatting, and backend endpoints used by the dashboard.

The goal of this phase was to create a stable backend foundation that could collect system data, expose security information, support frontend dashboard requests, and prepare the project for SOC-style features.

#### Completed Work

- [x] Built the Python backend server
- [x] Created versioned API routes under `/api/v1`
- [x] Added centralized GET route handling
- [x] Added centralized POST route handling
- [x] Added API key authentication for protected endpoints
- [x] Added consistent JSON response formatting
- [x] Added request IDs to backend responses
- [x] Added structured request logging
- [x] Created system health and status endpoints
- [x] Created backend metrics endpoint
- [x] Created security event endpoints
- [x] Added event creation through POST requests
- [x] Added security event summary reporting
- [x] Added network device endpoints
- [x] Added local network scan endpoint

#### Core API Features

| Feature | Description |
|---|---|
| API Versioning | Routes are organized under `/api/v1` |
| API Key Authentication | Protected endpoints require the `X-API-Key` header |
| Centralized Routing | GET and POST requests are handled through cleaner route logic |
| JSON Responses | API responses follow a consistent JSON structure |
| Request Logging | Backend requests are logged with method, endpoint, status, latency, and request ID |
| System Monitoring | Backend exposes system health, status, and metrics |
| Network Visibility | Backend can scan and store local network device information |

---

### Phase 3: Security Events and SOC Logic

Phase 3 focused on turning ZeroSOC from a basic backend API into a small SOC-style monitoring system. This phase introduced security event storage, event classification, severity tracking, event summaries, and logic for detecting notable activity.

The goal of this phase was to create a structured way for ZeroSOC to record security-related activity, organize events by severity and type, and prepare the dashboard to display useful SOC-style information.

#### Completed Work

- [x] Added SQLite storage for security events
- [x] Created a structured security event model
- [x] Added support for creating security events through the API
- [x] Added event IDs using UUIDs
- [x] Added timestamps for each event
- [x] Added event severity levels
- [x] Added event type classification
- [x] Added event source IP tracking
- [x] Added event message storage
- [x] Added automatic event tagging
- [x] Added event summary reporting
- [x] Added severity count summaries
- [x] Added event type summaries
- [x] Added tag summaries
- [x] Added time-window filtering for event review
- [x] Connected network scan results to SOC event generation

#### SOC Logic Features

| Feature | Description |
|---|---|
| Event Storage | Security events are stored persistently in SQLite |
| Event Creation | Events can be created through backend logic or API requests |
| Auto-Tagging | Events are automatically labeled based on severity, type, and message content |
| Event Summaries | Events are grouped by severity, type, source IP, and tag |
| Time Filtering | Events can be reviewed by time window |
| Dashboard Support | Event data is structured so the frontend can display counts, alerts, and analytics |

---

### Phase 4: Alerts, Incidents, Reports, and Notifications

Phase 4 focused on expanding ZeroSOC from event tracking into a more complete SOC-style workflow. This phase added alert handling, incident grouping, investigation reports, notification tracking, SLA states, and exportable investigation data.

The goal of this phase was to make ZeroSOC feel less like a raw event database and more like a lightweight security operations workflow tool.

#### Completed Work

- [x] Added automatic alert creation from notable events
- [x] Added active and resolved alert tracking
- [x] Added alert acknowledgement workflow
- [x] Added alert status updates
- [x] Added alert priority scoring
- [x] Added SLA tracking
- [x] Added overdue and due-soon SLA states
- [x] Added priority and SLA filtering
- [x] Added incident grouping
- [x] Added incident owner tracking
- [x] Added incident notes
- [x] Added incident activity tracking
- [x] Added investigation report creation
- [x] Added report editing
- [x] Added report status updates
- [x] Added report print view
- [x] Added report JSON export
- [x] Added report archive and restore
- [x] Added report activity tracking
- [x] Added alert notification logging
- [x] Added optional webhook notification support
- [x] Added CSV exports for alerts, incidents, reports, and activity logs

#### SOC Workflow Features

| Feature | Description |
|---|---|
| Alerts | Surfaces review-worthy security events |
| Alert Status | Tracks active, acknowledged, and resolved alerts |
| SLA Tracking | Marks alerts as on-track, due-soon, overdue, or resolved |
| Incident Groups | Groups related alerts by source and event type |
| Investigation Reports | Creates lightweight reports tied to alerts |
| Notifications | Tracks local and optional webhook alert notifications |
| Exports | Supports CSV and JSON exports for review and handoff |

---

### Phase 5: Network Device Scanning

Phase 5 focused on adding local network visibility to ZeroSOC. This phase introduced logic for detecting devices on the local network, collecting basic device information, storing discovered devices, and creating SOC-style events when new or unknown devices appear.

The goal of this phase was to connect the backend API to real local network activity so ZeroSOC could provide lightweight network awareness in a home-lab environment.

#### Completed Work

- [x] Added local IP address detection
- [x] Added local `/24` network range calculation
- [x] Added host scanning logic
- [x] Added ping-based device checks
- [x] Added hostname lookup for discovered devices
- [x] Added ARP table parsing
- [x] Added MAC address detection when available
- [x] Added SQLite storage for network devices
- [x] Added first-seen and last-seen tracking
- [x] Added known device listing endpoint
- [x] Added network scan endpoint
- [x] Added unknown device detection
- [x] Added device search and status filtering
- [x] Added stale device visibility
- [x] Added device CSV export
- [x] Connected new device discovery to security event creation

#### Network Device Fields

| Field | Description |
|---|---|
| `id` | Internal device record ID |
| `ip_address` | Device IP address |
| `hostname` | Detected hostname, when available |
| `status` | Device status, such as online or stale |
| `mac_address` | MAC address from ARP data, when available |
| `first_seen` | First time the device was detected |
| `last_seen` | Most recent time the device was detected |

---

### Phase 6: Dashboard Frontend

Phase 6 focused on building the browser-based dashboard for ZeroSOC. This phase turned backend API data into a visual interface that displays system status, backend metrics, security events, alerts, incidents, reports, notifications, resolved alerts, and network device information.

The goal of this phase was to make ZeroSOC easier to demonstrate as a cybersecurity/backend portfolio project by giving the API a clean visual layer.

#### Completed Work

- [x] Built the dashboard frontend
- [x] Connected dashboard panels to backend API endpoints
- [x] Added API status indicator
- [x] Added refresh control
- [x] Added summary cards
- [x] Added system health panel
- [x] Added backend metrics panel
- [x] Added event summary section
- [x] Added security event analytics charts
- [x] Added active alerts section
- [x] Added incident workflow panels
- [x] Added notification panel
- [x] Added investigation reports panel
- [x] Added report activity panel
- [x] Added resolved alerts panel
- [x] Added security events table
- [x] Added network devices panel
- [x] Added dashboard export controls
- [x] Added dashboard-triggered network scan
- [x] Improved dashboard styling and readability
- [x] Added safer frontend event bindings
- [x] Captured dashboard screenshots for the README

#### Dashboard Sections

| Section | Purpose |
|---|---|
| Dashboard Overview | Shows the main dashboard header, API status, summary cards, system status, and metrics |
| Event Summary and Analytics | Displays event counts, severity breakdowns, and event type summaries |
| Alerts and Incidents | Shows active alert filters, grouped incidents, alert activity, and notifications |
| Investigation Reports | Displays investigation workflow data, report filters, and report activity |
| Resolved Alerts | Shows resolved alert history, SLA-style details, and reopen actions |
| Security Events | Displays searchable and filterable security event records |
| Network Devices | Shows discovered devices, scan controls, and network inventory information |

---

### Phase 7: README, Screenshots, and Portfolio Polish

Phase 7 focused on preparing ZeroSOC for GitHub presentation and portfolio review. This phase cleaned up the README structure, updated project documentation, aligned screenshots with the current dashboard theme, and organized the project into clear development phases.

The goal of this phase was to make the project easy to understand for reviewers, hiring managers, clients, or anyone viewing the repository for the first time.

#### Completed Work

- [x] Updated the README project summary
- [x] Added clear project goals
- [x] Added project phase breakdowns
- [x] Added API endpoint documentation
- [x] Added dashboard screenshot section
- [x] Added local testing checklist
- [x] Added dashboard smoke test checklist
- [x] Added project documentation links
- [x] Added known limitations section
- [x] Added future improvements section
- [x] Added architecture overview section
- [ ] Add architecture diagram image
- [ ] Add Raspberry Pi deployment guide
- [ ] Add final demo walkthrough

---

## Phase 8: Raspberry Pi Deployment

Phase 8 focuses on preparing ZeroSOC to run on Raspberry Pi hardware, especially the Raspberry Pi Zero 2 W.

### Goals

- Prepare ZeroSOC for Raspberry Pi deployment
- Document required setup steps
- Run the backend server on Raspberry Pi OS
- Access the dashboard from another device on the local network
- Verify SQLite storage, request logs, security events, and network scanning on target hardware

### Deployment Target

ZeroSOC is intended to run on lightweight hardware such as a Raspberry Pi Zero 2 W using Raspberry Pi OS Lite.

### Basic Deployment Steps

1. Install Raspberry Pi OS Lite.
2. Connect the Raspberry Pi to the local network.
3. Install Python and required dependencies.
4. Clone the ZeroSOC repository.
5. Set the API key environment variable.
6. Start the ZeroSOC backend server.
7. Open the dashboard from a browser on the local network.
8. Test the API endpoints, logs, security events, and network device scanning.

### Status

Planned / in progress.

#### Planned Work

- [ ] Deploy backend to Raspberry Pi Zero 2 W
- [ ] Enable SSH access
- [ ] Install project requirements
- [ ] Run backend on Raspberry Pi
- [ ] Test dashboard against Raspberry Pi backend
- [ ] Add systemd service
- [ ] Start ZeroSOC automatically on boot
- [ ] Document Raspberry Pi deployment steps

## Known Limitations

ZeroSOC is currently a portfolio-ready local SOC dashboard, but it is not intended to be a production security platform.

Current limitations include:

- The backend uses Python’s built-in `http.server` instead of a production web framework.
- The default development API key is `dev-zero-soc-key` and should be changed before real deployment.
- Protected API routes cannot be tested directly from the browser address bar because they require the `X-API-Key` header.
- Protected endpoints should be tested through PowerShell, API tools, or the dashboard frontend.
- Network scans may take time depending on subnet size, device response behavior, and local firewall settings.
- CPU temperature may return `null` on Windows because Raspberry Pi thermal paths are not available.
- Most backend logic is currently contained in `run.py`; future cleanup should split the code into modules.
- Webhook notifications require `ZEROSOC_ALERT_WEBHOOK_URL` to be configured.
- Raspberry Pi deployment has not been completed yet.

---

## Future Improvements

Planned improvements for future versions include:

- Split backend logic into smaller modules
- Add Raspberry Pi deployment instructions
- Add systemd service setup for automatic startup
- Add environment-based production configuration
- Improve dashboard error handling
- Add pagination for larger event, alert, report, and device lists
- Add user accounts and login support
- Add trusted device allowlist support
- Add stronger unknown device detection rules
- Add email notification support
- Improve webhook notification configuration
- Add historical event charts
- Add longer-term metrics tracking
- Add additional unit tests
- Add API route tests
- Add GitHub Actions for automated checks
- Add architecture diagram
- Add final demo walkthrough
- Add additional screenshots as the dashboard evolves
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