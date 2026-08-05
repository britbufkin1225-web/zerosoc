# ZeroSOC

![Python](https://img.shields.io/badge/Python-3.x-blue)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)
![Status](https://img.shields.io/badge/Status-Active%20Development-yellow)
![Project](https://img.shields.io/badge/Type-Cybersecurity%20Portfolio-blueviolet)
![License](https://img.shields.io/badge/License-MIT-green)

ZeroSOC is a compact cybersecurity and backend-engineering portfolio project. It combines a standard-library Python HTTP API, SQLite persistence, a browser dashboard, security-event and alert workflows, host metrics, and local-network device visibility. It is intended for local development, home-lab learning, and technical demonstration—not as a production SOC, SIEM, EDR, or SOAR replacement.

The latest completed security-hardening checkpoint is **ZS-3.1**. At the locked ZS-4 baseline, the automated suite passes **141/141 tests**. `run.py` is the canonical and supported backend entry point.

## Architecture

ZeroSOC is deliberately small. The active backend implementation is consolidated in `run.py`; it uses `http.server`, `sqlite3`, and other Python standard-library modules. The dashboard in `dashboard/` is static HTML, CSS, and JavaScript and uses Chart.js in the browser.

| Component | Current implementation |
| --- | --- |
| Backend API | `run.py` using `BaseHTTPRequestHandler` and `HTTPServer` |
| Persistence | SQLite runtime database under `data/` |
| Dashboard | `dashboard/index.html`, `style.css`, and `app.js` |
| Authentication | Shared API key supplied in `X-API-Key` |
| Observability | Request IDs, structured request logs, metrics, events, and exports |
| Network visibility | Local ARP/ping-based discovery and device inventory |

![ZeroSOC architecture](screenshots/zerosoc-architecture-v2.png)

`app/main.py` remains in the repository but is not the supported entry point. Its disposition is deferred to ZS-4.1.

## Quick start

ZeroSOC has no third-party Python runtime packages. `requirements.txt` is intentionally limited to comments as a placeholder for future dependencies; there is currently nothing to install from it. Use Python 3 from the repository root.

Clone the repository:

```powershell
git clone https://github.com/britbufkin1225-web/zerosoc.git
Set-Location zerosoc
```

Set a long, random API key and start the backend on its localhost-only default:

```powershell
$env:ZEROSOC_API_KEY = "replace-with-a-long-random-secret"
python run.py
```

In another PowerShell terminal, serve the dashboard:

```powershell
Set-Location path\to\zerosoc
python -m http.server 5500
```

Open `http://localhost:5500/dashboard/`. Protected requests require the same key in the `X-API-Key` header:

```powershell
$headers = @{ "X-API-Key" = $env:ZEROSOC_API_KEY }
Invoke-RestMethod "http://localhost:8000/api/v1/system" -Headers $headers
```

Bash equivalents:

```bash
git clone https://github.com/britbufkin1225-web/zerosoc.git
cd zerosoc
export ZEROSOC_API_KEY="replace-with-a-long-random-secret"
python3 run.py
```

The server refuses to start when `ZEROSOC_API_KEY` is unset, blank, or whitespace-only. Never commit a real key.

## Configuration

The application reads configuration directly from the process environment. `.env.example` is reference material only: the standard-library application does **not** automatically load `.env` files.

| Variable | Required/default | Behavior |
| --- | --- | --- |
| `ZEROSOC_API_KEY` | Required | Shared secret for protected endpoints; compared in constant time and not logged. |
| `ZEROSOC_HOST` | `127.0.0.1` | Bind address. The default is localhost-only. |
| `ZEROSOC_ALLOWED_ORIGINS` | `http://localhost:5500,http://127.0.0.1:5500` | Comma-separated exact CORS origins; wildcard origins are not used. |
| `ZEROSOC_MAX_REQUEST_BYTES` | `65536` | Maximum request body in bytes; must be a positive integer no greater than 1 MiB. |
| `ZEROSOC_ALERT_WEBHOOK_URL` | Empty/disabled | Destination used only when webhook notification delivery is requested. |
| `ZEROSOC_ALERT_NOTIFICATION_COOLDOWN_SECONDS` | `900` | Cooldown between duplicate alert notifications. |

The safe default is `127.0.0.1`, which does not expose the API to other devices. LAN access is an explicit opt-in:

```powershell
$env:ZEROSOC_HOST = "0.0.0.0"
$env:ZEROSOC_ALLOWED_ORIGINS = "http://YOUR_TRUSTED_LAN_HOST:5500"
python run.py
```

Binding to `0.0.0.0` exposes the plain-HTTP service to devices that can reach the host. Use it only on a trusted network, choose an exact dashboard origin, and understand that the API key and response data are not protected by TLS. Raspberry Pi and cross-device LAN deployment remain planned and unverified on hardware.

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

These are application-level controls for a portfolio project. ZeroSOC has one shared API key, no user accounts or role-based access, no TLS termination, no rate limiter, no production reverse proxy, and no claim of penetration testing or complete security.

See [SECURITY.md](SECURITY.md) for responsible reporting.

## Testing

Compile both retained entry-point files:

```powershell
python -m py_compile run.py app/main.py
```

Run the automated suite:

```powershell
python -m unittest tests.test_run
```

Current verified baseline: **141 tests, all passing**. The suite covers authentication, CORS, configuration, request framing and size limits, JSON validation, endpoint behavior, persistence, notifications, and other backend contracts without requiring a live LAN scan.

## API endpoints

`/health`, `/status`, `/api/v1/health`, and `/api/v1/status` are public. Other data and mutation routes require `X-API-Key`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/v1/health` | Health response |
| GET | `/api/v1/status` | Service status |
| GET | `/api/v1/system` | Host system details |
| GET | `/api/v1/logs/recent` | Recent request logs |
| GET | `/api/v1/metrics` | Request, event, and device metrics |
| GET/POST | `/api/v1/events` | List or create events |
| GET | `/api/v1/events/{id}` | Retrieve one event |
| GET | `/api/v1/events/summary` | Event counts and summaries |
| GET | `/api/v1/events/export` | CSV event export |
| GET | `/api/v1/alerts` | List alerts |
| GET | `/api/v1/alerts/export` | CSV alert export |
| POST | `/api/v1/alerts/{id}/status` | Update alert status |
| GET | `/api/v1/alerts/incidents/export` | Incident export |
| GET | `/api/v1/alerts/incidents/activity` | Incident activity |
| GET | `/api/v1/alerts/incidents/activity/export` | Incident activity export |
| POST | `/api/v1/alerts/incidents/{id}/state` | Update incident state |
| GET | `/api/v1/alerts/reports` | List investigation reports |
| GET | `/api/v1/alerts/reports/activity` | Report activity |
| GET | `/api/v1/alerts/reports/activity/export` | Report activity export |
| GET | `/api/v1/alerts/reports/{id}/print` | Printable report |
| GET | `/api/v1/alerts/reports/{id}/export` | Report export |
| POST | `/api/v1/alerts/{id}/report` | Create an alert report |
| POST | `/api/v1/alerts/reports/{id}/status` | Update report status |
| POST | `/api/v1/alerts/reports/{id}/details` | Update report details |
| POST | `/api/v1/alerts/reports/{id}/archive` | Archive a report |
| POST | `/api/v1/alerts/reports/{id}/restore` | Restore a report |
| GET/POST | `/api/v1/alerts/notifications` | List or deliver notifications |
| GET | `/api/v1/devices` | Device inventory |
| GET | `/api/v1/devices/export` | CSV device export |
| GET | `/api/v1/network/scan` | Trigger a local network scan |

## Portfolio highlights

- Versioned HTTP APIs with consistent JSON responses and request IDs
- SQLite-backed events, devices, alerts, incidents, reports, and notifications
- Rule-based event classification, tagging, alert creation, and correlation
- CSV/JSON-style operational exports and a browser dashboard
- Security-hardening work through ZS-3.1 backed by automated tests
- Repository governance and documentation for responsible collaboration

## Screenshots

The retained images are historical portfolio evidence; ZS-4 did not recapture or live-verify them.

![Dashboard overview](screenshots/dashboard-overview.png)

![Event summary and analytics](screenshots/event-summary-analytics.png)

![Alerts, incidents, and notifications](screenshots/alerts-incidents-notifications.png)

![Investigation reports and resolved alerts](screenshots/reports-resolved-alerts.png)

![Security events](screenshots/dashboard-events.png)

![Network devices](screenshots/dashboard-devices.png)

![API health response](screenshots/api-health.png)

See [the screenshot inventory](docs/screenshots-inventory.md) for all retained assets.

## Limitations and planned work

Current limitations include a single shared credential, plain HTTP, a single-process standard-library server, limited pagination, rule-based detection/correlation, platform-dependent network discovery, and no validated Raspberry Pi deployment. Large datasets and accessibility need further dashboard testing. Webhook delivery depends on an operator-supplied external endpoint and is not exercised by routine setup or tests.

Planned work includes stronger identity and authorization, deployment guidance and hardware validation, improved pagination and accessibility, richer correlation, and production-oriented transport/proxy guidance. Implemented capabilities are not listed as future work.

See [Known Limitations and Next Upgrades](docs/known-limitations-and-next-upgrades.md).

## License

ZeroSOC is available under the [MIT License](LICENSE).
