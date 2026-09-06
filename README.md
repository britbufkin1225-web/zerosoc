# ZeroSOC

![Python](https://img.shields.io/badge/Python-3.x-blue) ![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey) ![Status](https://img.shields.io/badge/Status-Active%20Development-yellow) ![Project](https://img.shields.io/badge/Type-Cybersecurity%20Portfolio-blueviolet) ![License](https://img.shields.io/badge/License-MIT-green)

ZeroSOC is a compact cybersecurity and backend-engineering portfolio project for local development and authorized home-lab learning. It provides a standard-library Python HTTP API, SQLite persistence, a browser dashboard, security-event and alert workflows, host metrics, and local-network device discovery.

The project demonstrates secure API design, defensive request handling, SQLite persistence, SOC workflow modeling, automated testing, structured observability, and technical documentation. It is an educational system and technical demonstration—not a production SOC or a replacement for a SIEM, EDR, or SOAR platform.

## Contents

- [Project status](#project-status)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API endpoints](#api-endpoints)
- [Security controls](#security-controls)
- [Testing](#testing)
- [Portfolio highlights](#portfolio-highlights)
- [Screenshots](#screenshots)
- [Limitations and planned work](#limitations-and-planned-work)
- [License](#license)

## Project status

ZeroSOC is in active portfolio development. `run.py` is the canonical and supported backend entry point, and the latest completed security-hardening checkpoint is ZS-3.1.

The automated suite currently contains 145 tests. During the local ZS-6 implementation pass, all 145 passed in three consecutive full-suite runs after deterministic event ordering and counter regression coverage were added. Independent review and merge approval remain pending.

## Architecture

ZeroSOC deliberately keeps its active runtime small and auditable. The backend is consolidated in `run.py` and uses `http.server`, `sqlite3`, and other Python standard-library modules. The dashboard in `dashboard/` is static HTML, CSS, and JavaScript, with Chart.js loaded in the browser.

| Component | Current implementation |
| --- | --- |
| Backend API | `run.py` using `BaseHTTPRequestHandler` and `HTTPServer` |
| Persistence | SQLite runtime database under `data/` |
| Dashboard | `dashboard/index.html`, `dashboard/style.css`, and `dashboard/app.js` |
| Authentication | Shared API key supplied in `X-API-Key` |
| Observability | Request IDs, structured request logs, metrics, events, and exports |
| Network visibility | Local ARP/ping-based discovery and device inventory |

System flow:

```text
Dashboard/client → authenticated HTTP API → validation and SOC services → SQLite persistence and structured logging
```

![ZeroSOC architecture](screenshots/zerosoc-architecture-v2.png)

*Retained architecture overview of the API, SOC workflows, storage, observability, dashboard, and local-network discovery boundaries.*

## Quick start

### Prerequisites

- Git
- Python 3
- A modern web browser
- Two terminal windows

ZeroSOC has no third-party Python runtime packages. `requirements.txt` is intentionally a placeholder, so there is currently nothing to install from it.

> **Authorized use only:** ZeroSOC is an educational home-lab and portfolio project. Run network-discovery features only on systems and networks you own or are explicitly authorized to test.

### PowerShell

Clone the repository and enter its root directory:

```powershell
git clone https://github.com/britbufkin1225-web/zerosoc.git
Set-Location zerosoc
```

Create a long, random API key for this terminal session, then start the localhost-only backend:

```powershell
$env:ZEROSOC_API_KEY = "replace-with-a-long-random-secret"
python run.py
```

In a second PowerShell terminal, enter the same repository and serve the dashboard:

```powershell
Set-Location path\to\zerosoc
python -m http.server 5500
```

Open [http://localhost:5500/dashboard/](http://localhost:5500/dashboard/). The dashboard prompts for the same API key and sends it in the `X-API-Key` header. It can keep the key in tab-scoped `sessionStorage`; persistent `localStorage` is used only after a separate confirmation. Browser storage is convenient for a local demo but is not a secure credential vault.

From another PowerShell prompt, verify the public health route and one protected route:

```powershell
Invoke-RestMethod "http://localhost:8000/health"

$headers = @{ "X-API-Key" = $env:ZEROSOC_API_KEY }
Invoke-RestMethod "http://localhost:8000/api/v1/system" -Headers $headers
```

Press `Ctrl+C` in both server terminals to stop the dashboard and backend.

### Bash

```bash
git clone https://github.com/britbufkin1225-web/zerosoc.git
cd zerosoc
export ZEROSOC_API_KEY="replace-with-a-long-random-secret"
python3 run.py
```

In a second terminal:

```bash
cd path/to/zerosoc
python3 -m http.server 5500
curl http://localhost:8000/health
curl -H "X-API-Key: $ZEROSOC_API_KEY" http://localhost:8000/api/v1/system
```

The backend refuses to start when `ZEROSOC_API_KEY` is unset, blank, or whitespace-only. Never commit a real key. `.env.example` is reference material only; the standard-library application does **not** automatically load `.env` files.

For a persistent Raspberry Pi deployment that survives closed terminals, crashes, and reboots — two `systemd` services plus a Windows SSH-tunnel launcher — see [Raspberry Pi Deployment](docs/raspberry-pi-deployment.md).

## Configuration

The application reads configuration directly from the process environment.

| Variable | Required/default | Behavior |
| --- | --- | --- |
| `ZEROSOC_API_KEY` | Required | Shared secret for protected endpoints; compared in constant time and not logged. |
| `ZEROSOC_HOST` | `127.0.0.1` | Bind address; the default is localhost-only. |
| `ZEROSOC_ALLOWED_ORIGINS` | `http://localhost:5500,http://127.0.0.1:5500` | Comma-separated exact CORS origins; wildcard origins are not used. |
| `ZEROSOC_MAX_REQUEST_BYTES` | `65536` | Maximum request body in bytes; must be positive and no greater than 1 MiB. |
| `ZEROSOC_ALERT_WEBHOOK_URL` | Empty/disabled | Destination used only when webhook notification delivery is requested. |
| `ZEROSOC_ALERT_NOTIFICATION_COOLDOWN_SECONDS` | `900` | Cooldown between duplicate alert notifications. |

Keep the default `127.0.0.1` binding for normal use. Exposing the plain-HTTP service on another interface is an explicit advanced configuration choice: there is no TLS, and the shared key and response data are not encrypted in transit. ZeroSOC has been validated on a Raspberry Pi Zero 2 W, where both services bind `127.0.0.1` only and are reached over an SSH tunnel; see [Raspberry Pi Deployment](docs/raspberry-pi-deployment.md). Cross-device LAN deployment remains unvalidated.

## API endpoints

The API normalizes trailing slashes. `/health` and `/status` are public aliases for their versioned counterparts; `/system` is also an implemented alias for `/api/v1/system`, but it remains protected.

### Health, status, and observability

| Method | Endpoint | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health`, `/api/v1/health` | Public | Return service health. |
| GET | `/status`, `/api/v1/status` | Public | Return service status and uptime. |
| GET | `/system`, `/api/v1/system` | `X-API-Key` | Return host system details. |
| GET | `/api/v1/logs/recent` | `X-API-Key` | Return recent structured request logs. |
| GET | `/api/v1/metrics` | `X-API-Key` | Return request, event, and device metrics. |

### Events

| Method | Endpoint | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/api/v1/events` | `X-API-Key` | List and filter security events. |
| POST | `/api/v1/events` | `X-API-Key` | Validate and create a security event. |
| GET | `/api/v1/events/{id}` | `X-API-Key` | Return one event by ID. |
| GET | `/api/v1/events/summary` | `X-API-Key` | Summarize event counts, tags, and recent activity. |
| GET | `/api/v1/events/export` | `X-API-Key` | Export filtered events as CSV. |

Selected response examples (protected requests require `X-API-Key`):

`GET /api/v1/events?limit=1`

```json
{
  "success": true,
  "status_code": 200,
  "request_id": "0a2af67f-79cd-4e7a-8928-80ec41926a66",
  "data": {
    "events": [{
      "id": "d6d893d8-9a48-4c42-9e32-92d386fb44d2",
      "timestamp": "2026-08-14T09:30:00",
      "source_ip": "192.168.1.24",
      "event_type": "auth-failure",
      "severity": "medium",
      "message": "Repeated login failure",
      "tags": ["type:auth-failure", "source:192.168.1.24"]
    }],
    "count": 1,
    "filters": {
      "limit": 1,
      "severity": null,
      "tag": null,
      "event_type": null,
      "source": null,
      "q": null,
      "since_hours": null
    }
  },
  "error": null
}
```

`GET /api/v1/events/summary`

```json
{
  "success": true,
  "status_code": 200,
  "request_id": "41874962-3535-4891-aeab-b68a914899ee",
  "data": {
    "total_events": 3,
    "by_severity": {"high": 1, "medium": 2},
    "by_event_type": {"auth-failure": 2, "port-scan": 1},
    "by_tag": {
      "type:auth-failure": 2,
      "source:192.168.1.24": 2,
      "type:port-scan": 1,
      "source:192.168.1.50": 1,
      "needs-review": 1
    },
    "latest_event": {
      "id": "d6d893d8-9a48-4c42-9e32-92d386fb44d2",
      "timestamp": "2026-08-14T09:30:00",
      "event_type": "auth-failure",
      "severity": "medium",
      "tag": "type:auth-failure,source:192.168.1.24",
      "message": "Repeated login failure"
    }
  },
  "error": null
}
```

### Alerts and incidents

| Method | Endpoint | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/api/v1/alerts` | `X-API-Key` | List and filter alerts. |
| GET | `/api/v1/alerts/export` | `X-API-Key` | Export filtered alerts as CSV. |
| POST | `/api/v1/alerts/{id}/status` | `X-API-Key` | Update an alert status. |
| GET | `/api/v1/alerts/incidents/export` | `X-API-Key` | Export grouped incidents as CSV. |
| GET | `/api/v1/alerts/incidents/activity` | `X-API-Key` | List incident activity. |
| GET | `/api/v1/alerts/incidents/activity/export` | `X-API-Key` | Export incident activity as CSV. |
| POST | `/api/v1/alerts/incidents/{id}/state` | `X-API-Key` | Update incident status, owner, or note. |

### Reports and notifications

| Method | Endpoint | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/api/v1/alerts/reports` | `X-API-Key` | List and filter investigation reports. |
| GET | `/api/v1/alerts/reports/activity` | `X-API-Key` | List report lifecycle activity. |
| GET | `/api/v1/alerts/reports/activity/export` | `X-API-Key` | Export report activity as CSV. |
| GET | `/api/v1/alerts/reports/{id}/print` | `X-API-Key` | Return a printable report view. |
| GET | `/api/v1/alerts/reports/{id}/export` | `X-API-Key` | Export a report bundle. |
| POST | `/api/v1/alerts/{id}/report` | `X-API-Key` | Create a report from an alert. |
| POST | `/api/v1/alerts/reports/{id}/status` | `X-API-Key` | Finalize or reopen a report. |
| POST | `/api/v1/alerts/reports/{id}/details` | `X-API-Key` | Update report title or summary. |
| POST | `/api/v1/alerts/reports/{id}/archive` | `X-API-Key` | Archive a report without deleting it. |
| POST | `/api/v1/alerts/reports/{id}/restore` | `X-API-Key` | Restore an archived report. |
| GET | `/api/v1/alerts/notifications` | `X-API-Key` | List notification history and summary data. |
| POST | `/api/v1/alerts/notifications` | `X-API-Key` | Request alert notification delivery. |

### Devices and network operations

| Method | Endpoint | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/api/v1/devices` | `X-API-Key` | List and filter discovered devices. |
| GET | `/api/v1/devices/export` | `X-API-Key` | Export device inventory as CSV. |
| GET | `/api/v1/network/scan` | `X-API-Key` | Trigger local network discovery. |

## Security controls

Implemented controls include:

- no committed default API key and fail-closed startup when the key is missing;
- constant-time API-key comparison for protected routes;
- localhost-only binding by default;
- exact-origin CORS allowlisting;
- centralized JSON body validation and bounded `Content-Length` handling;
- rejection of unsupported transfer framing and media types;
- parameterized SQLite operations;
- error responses that avoid reflecting request bodies, secrets, stack traces, or decoder details.

These are application-level controls for a portfolio project, not a claim of complete security or production readiness. ZeroSOC has one shared API key, no user accounts or role-based access, no TLS termination, no rate limiter, and no production reverse proxy. See [SECURITY.md](SECURITY.md) for responsible reporting.

## Testing

Compile both retained entry-point files:

```powershell
python -m py_compile run.py app/main.py
```

Run the automated suite:

```powershell
python -m unittest tests.test_run
```

The suite exercises authentication, CORS, configuration, request framing and size limits, JSON validation, endpoint behavior, persistence, notifications, and other backend contracts without opening an external connection, binding a LAN interface, or scanning a network. See [Project status](#project-status) for the latest observed result.

## Portfolio highlights

- Versioned HTTP APIs with consistent JSON responses and request IDs
- SQLite-backed events, devices, alerts, incidents, reports, and notifications
- Rule-based event classification, tagging, alert creation, and correlation
- CSV exports and a browser-based operational dashboard
- Defensive input validation and authentication regression coverage
- Repository governance, security guidance, and technical documentation

## Screenshots

These retained images are historical portfolio evidence. They were not recaptured or freshly runtime-verified during ZS-5.

![Dashboard overview](screenshots/dashboard-overview.png)

*Dashboard overview showing service health, system context, and operational metrics.*

![Event summary and analytics](screenshots/event-summary-analytics.png)

*Event analytics showing how collected security activity is summarized for review.*

![Alerts, incidents, and notifications](screenshots/alerts-incidents-notifications.png)

*Modeled SOC workflow connecting alerts, grouped incidents, and notification history.*

![Investigation reports and resolved alerts](screenshots/reports-resolved-alerts.png)

*Investigation reporting and alert-resolution workflow retained as portfolio evidence.*

See [the complete screenshot inventory](docs/screenshots-inventory.md) for every retained dashboard and API image.

## Limitations and planned work

Current limitations include a single shared credential, plain HTTP, a single-process standard-library server, limited pagination, rule-based detection and correlation, and platform-dependent network discovery. Raspberry Pi deployment has been validated on a Raspberry Pi Zero 2 W: persistent `systemd` startup, localhost-only service binding, SSH-tunnel access, authenticated API access, and recovery after one clean reboot were verified. Repeated power-loss and long-duration soak testing remain unverified. Large datasets and accessibility need further dashboard testing. Webhook delivery depends on an operator-supplied external endpoint and is not exercised by routine setup or tests.

`app/main.py` remains in the repository as a retained historical entry-point file, but it is not the supported runtime entry point. Its disposition is deferred; use `run.py`.

Planned work includes stronger identity and authorization, deployment guidance and hardware validation, improved pagination and accessibility, richer correlation, and production-oriented transport and proxy guidance. See [Known Limitations and Next Upgrades](docs/known-limitations-and-next-upgrades.md).

## License

ZeroSOC is available under the [MIT License](LICENSE).
