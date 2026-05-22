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

- [x] Create GitHub repository
- [x] Add initial project folder structure
- [x] Add main backend entry point with `run.py`
- [x] Add dependency tracking with `requirements.txt`
- [x] Add environment variable example file with `.env.example`
- [x] Add ignored local/runtime files with `.gitignore`
- [x] Add initial README documentation

### Phase 2: Core Backend API

Phase 2 focused on building the main backend API layer for ZeroSOC. This phase established the server structure, protected API routes, request handling, response formatting, and backend endpoints used by the dashboard.

The goal of this phase was to create a stable backend foundation that could collect system data, expose security information, support frontend dashboard requests, and prepare the project for future SOC-style features.

### Completed Work

- Built the Python backend server
- Created versioned API routes under `/api/v1`
- Added centralized GET route handling
- Added centralized POST route handling
- Added API key authentication for protected endpoints
- Added consistent JSON response formatting
- Added request IDs to backend responses
- Added structured request logging
- Created system health and status endpoints
- Created backend metrics endpoint
- Created security event endpoints
- Added event creation through POST requests
- Added security event summary reporting
- Added network device endpoints
- Added local network scan endpoint

### Core API Features

| Feature | Description |
|---|---|
| API Versioning | Routes are organized under `/api/v1` |
| API Key Authentication | Protected endpoints require the `X-API-Key` header |
| Centralized Routing | GET and POST requests are handled through clean route logic |
| JSON Responses | API responses follow a consistent JSON structure |
| Request Logging | Backend requests are logged with method, endpoint, status, and request ID |
| Security Events | Events can be stored, retrieved, filtered, and summarized |
| System Monitoring | Backend exposes system health, status, and metrics |
| Network Visibility | Backend can scan and store local network device information |

### Important API Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| GET | `/health` | Basic service health check | No |
| GET | `/api/v1/health` | Versioned health check | No |
| GET | `/api/v1/status` | Service status information | No |
| GET | `/api/v1/system` | System information | Yes |
| GET | `/api/v1/metrics` | Backend metrics | Yes |
| GET | `/api/v1/logs` | Request logs | Yes |
| GET | `/api/v1/logs/recent` | Recent request logs | Yes |
| GET | `/api/v1/events` | List security events | Yes |
| GET | `/api/v1/events/summary` | Security event summary | Yes |
| POST | `/api/v1/events` | Create a new security event | Yes |
| GET | `/api/v1/devices` | List known network devices | Yes |
| GET | `/api/v1/network/scan` | Run local network scan | Yes |

### Portfolio Value

This phase demonstrates backend development fundamentals including API design, authentication, structured routing, logging, JSON response formatting, data retrieval, and endpoint organization. It also shows that ZeroSOC is more than a static dashboard because the frontend is powered by real backend API data.


## Phase 3: Security Events and SOC Logic

Phase 3 focused on turning ZeroSOC from a basic backend API into a small SOC-style monitoring system. This phase introduced security event storage, event classification, severity tracking, event summaries, and logic for detecting notable activity on the local network.

The goal of this phase was to create a structured way for ZeroSOC to record security-related activity, organize events by severity and type, and prepare the dashboard to display useful SOC-style information.

### Completed Work

- Added SQLite storage for security events
- Created a structured security event model
- Added support for creating security events through the API
- Added event IDs using UUIDs
- Added timestamps for each event
- Added event severity levels
- Added event type classification
- Added event source IP tracking
- Added event message storage
- Added automatic event tagging
- Added event summary reporting
- Added severity count summaries
- Added event type summaries
- Added tag summaries
- Added unknown device event creation
- Connected network scan results to SOC event generation

### Security Event Fields

| Field | Description |
|---|---|
| `id` | Unique event identifier |
| `timestamp` | Time the event was created |
| `source_ip` | IP address related to the event |
| `event_type` | Category of security event |
| `severity` | Event severity level |
| `message` | Human-readable event description |
| `tag` | Auto-generated classification label |

### Severity Levels

| Severity | Purpose |
|---|---|
| `critical` | High-impact event requiring immediate attention |
| `high` | Serious event that should be reviewed quickly |
| `medium` | Notable event that may require investigation |
| `low` | Informational or lower-risk event |

### SOC Logic Features

| Feature | Description |
|---|---|
| Event Storage | Security events are stored persistently in SQLite |
| Event Creation | Events can be created through backend logic or API requests |
| Auto-Tagging | Events are automatically labeled based on severity, type, and message content |
| Event Summaries | Events are grouped by severity, type, source IP, and tag |
| Unknown Device Detection | New network devices can automatically generate medium-severity events |
| Dashboard Support | Event data is structured so the frontend can display alerts, counts, and summaries |

### Example Event Types

- `auth`
- `network`
- `scan`
- `system`
- `unknown-device`
- `firewall`
- `malware-related`
- `ssh`
- `storage`
- `hardware-health`

### Portfolio Value

This phase demonstrates practical cybersecurity backend logic. ZeroSOC does not only store raw data; it classifies security events, tracks severity, summarizes activity, and creates SOC-style signals from local network behavior.

This makes the project more relevant for cybersecurity, backend development, and entry-level SOC analyst portfolio review.

## Phase 4: Network Device Scanning

Phase 4 focused on adding local network visibility to ZeroSOC. This phase introduced logic for detecting devices on the local network, collecting basic device information, storing discovered devices, and creating SOC-style events when new or unknown devices appear.

The goal of this phase was to connect the backend API to real local network activity so ZeroSOC could provide lightweight network awareness in a home-lab environment.

### Completed Work

- Added local IP address detection
- Added local `/24` network range calculation
- Added host scanning logic
- Added ping-based device checks
- Added hostname lookup for discovered devices
- Added ARP table parsing
- Added MAC address detection when available
- Added SQLite storage for network devices
- Added first-seen and last-seen tracking
- Added known device listing endpoint
- Added network scan endpoint
- Added unknown device detection
- Connected new device discovery to security event creation

### Network Device Fields

| Field | Description |
|---|---|
| `id` | Internal device record ID |
| `ip_address` | Device IP address |
| `hostname` | Detected hostname, when available |
| `status` | Device status, such as online |
| `mac_address` | MAC address from ARP data, when available |
| `first_seen` | First time the device was detected |
| `last_seen` | Most recent time the device was detected |

### Network Scanning Features

| Feature | Description |
|---|---|
| Local IP Detection | Determines the machine’s active local network IP |
| Network Range Calculation | Builds a `/24` network range from the local IP |
| Ping Scanning | Checks local hosts for reachability |
| Hostname Lookup | Attempts to resolve hostnames for detected devices |
| ARP Table Parsing | Reads local ARP data to identify MAC addresses |
| Device Persistence | Stores discovered devices in SQLite |
| Device Updates | Updates `last_seen` when known devices are seen again |
| Unknown Device Events | Creates security events when new devices are discovered |

### API Endpoint

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| GET | `/api/v1/network/scan` | Scans the local network and stores discovered devices | Yes |
| GET | `/api/v1/devices` | Lists known network devices | Yes |

### SOC Value

Network scanning gives ZeroSOC visibility beyond the local machine. By detecting devices on the network and recording when they first appear, the system can identify new or unexpected devices that may require review.

This is important because unknown devices are one of the simplest but most useful signals in a small home-lab SOC environment.

### Portfolio Value

This phase demonstrates practical backend integration with operating system tools, local networking, SQLite persistence, and security event generation.

It shows that ZeroSOC can collect real local network data, process it, store it, and turn it into SOC-style findings instead of simply displaying static information.

## Phase 5: Dashboard Frontend

Phase 5 focused on building the browser-based dashboard for ZeroSOC. This phase turned the backend API data into a visual interface that can display system status, backend metrics, security events, alerts, incidents, reports, and network device information.

The goal of this phase was to make ZeroSOC easier to demonstrate as a cybersecurity/backend portfolio project by giving the API a clean visual layer.

### Completed Work

- Built a simple web dashboard frontend
- Connected dashboard panels to backend API endpoints
- Added API status indicator
- Added refresh control
- Added top summary cards
- Added system status panel
- Added backend metrics panel
- Added security event summary section
- Added severity and event type analytics
- Added active alerts section
- Added incident grouping display
- Added investigation reports section
- Added resolved alerts section
- Added security event table
- Added network device inventory section
- Added export-style dashboard controls
- Updated dashboard theme to a gray, higher-contrast visual style
- Captured dashboard screenshots for the README

### Dashboard Sections

| Section | Purpose |
|---|---|
| Dashboard Overview | Shows the main ZeroSOC dashboard header, API status, summary cards, system status, and metrics |
| Event Summary and Analytics | Displays security event counts, severity breakdowns, and event type summaries |
| Alerts and Incidents | Shows active alerts, grouped incidents, alert filters, and notification-style activity |
| Investigation Reports | Displays investigation workflow data, reports, report filters, and report activity |
| Resolved Alerts | Shows resolved alert history, SLA-style details, and reopen actions |
| Security Events | Displays searchable and filterable security event records |
| Network Devices | Shows discovered devices, scan controls, and network inventory information |

### Dashboard Features

| Feature | Description |
|---|---|
| API Status Indicator | Shows whether the backend API is reachable |
| Refresh Control | Allows dashboard data to be reloaded from the backend |
| Summary Cards | Highlights important system, event, alert, and network counts |
| System Status Panel | Displays local system health information |
| Backend Metrics Panel | Shows backend activity and request-related metrics |
| Event Analytics | Summarizes security events by severity, type, and tag |
| Alert Filters | Allows alerts to be viewed by severity, priority, or status |
| Investigation Workflow | Displays reports and review activity |
| Device Inventory | Lists discovered local network devices |
| Screenshot Support | README screenshots document the final dashboard appearance |

### Visual Theme

The dashboard uses a gray-toned interface with stronger contrast than the earlier light theme. This makes the dashboard easier to read while still keeping a clean, professional appearance.

The updated visual style better matches the cybersecurity focus of the project and makes the dashboard more suitable for portfolio screenshots.

### Portfolio Value

This phase makes ZeroSOC demonstrable. Instead of only showing backend code or API responses, the project now has a visual interface that presents SOC-style information in a way that is easier for reviewers, clients, or hiring managers to understand.

The dashboard shows that ZeroSOC combines backend API development, frontend integration, security event logic, local network visibility, and dashboard presentation in one project.

### Phase 6: README, Screenshots, and Portfolio Polish

Phase 6 focused on preparing ZeroSOC for GitHub presentation and portfolio review. This phase cleaned up the README structure, updated the project documentation, aligned screenshots with the current dashboard theme, and organized the project into clear development phases.

The goal of this phase was to make the project easy to understand for reviewers, hiring managers, clients, or anyone viewing the repository for the first time.

### Completed Work

- Updated the README project summary
- Added clear project goals
- Added project phase breakdowns
- Updated the current status section
- Added core backend API details
- Added security event and SOC logic details
- Added network scanning documentation
- Added dashboard frontend documentation
- Added API endpoint table
- Added dashboard screenshot section
- Updated screenshot descriptions to match the new dashboard theme
- Organized screenshots by dashboard section
- Added portfolio-focused project value sections
- Cleaned up language for a more professional GitHub presentation

### README Sections

| Section | Purpose |
|---|---|
| Project Overview | Explains what ZeroSOC is and why it exists |
| Project Goals | Lists the main technical and cybersecurity goals |
| Current Status | Summarizes what currently works |
| Project Phases | Shows how the project was built step by step |
| API Endpoints | Documents available backend routes |
| Dashboard Screenshots | Shows the visual dashboard interface |
| Tech Stack | Lists the tools and technologies used |
| Portfolio Value | Explains what the project demonstrates professionally |
| Future Improvements | Shows planned next steps |

### Screenshot Categories

| Screenshot | Purpose |
|---|---|
| Dashboard Overview | Shows the main dashboard header, API status, summary cards, system status, and metrics |
| Security Event Analytics | Shows event counts, severity summaries, and event type analytics |
| Alerts and Incidents | Shows active alert filters, incident groups, and notification-style activity |
| Investigation Reports | Shows report workflow, investigation tracking, and resolved alert data |
| Security Events and Devices | Shows searchable event records and local network device inventory |

### Portfolio Polish Checklist

- README explains the project clearly
- Screenshots match the current dashboard design
- API endpoints are documented
- Project phases show steady development progress
- Cybersecurity value is easy to understand
- Backend value is easy to understand
- Dashboard value is easy to understand
- GitHub repository is organized and readable
- Screenshots are stored in the `screenshots/` folder
- Markdown image paths use correct file names
- Final commits are clean and descriptive

### Portfolio Value

This phase makes ZeroSOC easier to evaluate as a finished portfolio project. The documentation explains the project’s purpose, the screenshots show the working dashboard, and the phase breakdown demonstrates the development process from backend foundation to SOC-style dashboard.

A clean README matters because reviewers often judge the project before they ever run the code. Cruel, but accurate.
---

### Phase 7: README, Screenshots, and Portfolio Polish

Phase 7 focused on preparing ZeroSOC for GitHub presentation and portfolio review. This phase cleaned up the README structure, updated project documentation, aligned screenshots with the current dashboard theme, and organized the project into clear development phases.

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
- [ ] Add architecture diagram
- [ ] Add Raspberry Pi deployment guide
- [ ] Add final demo walkthrough

---

### Phase 8: Raspberry Pi Deployment

Phase 8 focuses on deploying ZeroSOC to the Raspberry Pi Zero 2 W target environment. This phase is planned/in progress and will confirm that the project can run outside the Windows development machine.

#### Planned Work

- [ ] Deploy backend to Raspberry Pi Zero 2 W
- [ ] Enable SSH access
- [ ] Install project requirements
- [ ] Run backend on Raspberry Pi
- [ ] Test dashboard against Raspberry Pi backend
- [ ] Add systemd service
- [ ] Start ZeroSOC automatically on boot
- [ ] Document Raspberry Pi deployment steps
---

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