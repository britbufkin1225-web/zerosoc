# ZeroSOC

ZeroSOC is a lightweight Raspberry Pi Zero 2 W-powered security operations dashboard for monitoring local system health, local network devices, API activity, and suspicious security events.

## Project Overview

ZeroSOC is being built as a cybersecurity/backend portfolio project. The goal is to create a small but practical security monitoring system that can run on lightweight hardware, expose clean backend API endpoints, track activity, and eventually display security data in a web dashboard.

## Project Goals

- Monitor Raspberry Pi system health
- Scan local network devices
- Collect and store security events
- Expose protected backend API endpoints
- Track API requests and authentication attempts
- Display status and event data in a web dashboard
- Use SQLite for lightweight persistence
- Deploy as a small home-lab SOC-style tool

## Current Status

ZeroSOC currently has a working Python backend with structured API routing, SQLite persistence, API key authentication, request logging, local system status endpoints, security event storage, network device scanning, and basic metrics.

The backend cleanup pass is complete. Core GET and POST routes are now wired consistently and tested.

## API Endpoints

| Method | Endpoint | Description | Auth Required | Status |
|---|---|---|---|---|
| GET | `/api/v1/health` | Basic backend health check | No | Working |
| GET | `/api/v1/status` | Service status and uptime | No | Working |
| GET | `/api/v1/system` | Host system information | Yes | Working |
| GET | `/api/v1/events` | List stored security events | Yes | Working |
| GET | `/api/v1/events/{id}` | Retrieve one security event by ID | Yes | Working |
| GET | `/api/v1/events/summary` | Security event summary counts | Yes | Working |
| POST | `/api/v1/events` | Create a new security event | Yes | Working |
| GET | `/api/v1/devices` | List recently seen network devices | Yes | Working |
| GET | `/api/v1/network/scan` | Scan local network devices | Yes | Working |
| GET | `/api/v1/logs/recent` | View recent request logs | Yes | Working |
| GET | `/api/v1/metrics` | View request, event, and device metrics | Yes | Working |

## API Authentication

Protected endpoints require an API key header:

```http
X-API-Key: dev-zero-soc-key
```

The default development key can be overridden with the `ZEROSOC_API_KEY` environment variable.

## Example API Tests

### Health check

```powershell
curl.exe http://localhost:8000/api/v1/health
```

### Service status

```powershell
curl.exe http://localhost:8000/api/v1/status
```

### System information

```powershell
curl.exe -H "X-API-Key: dev-zero-soc-key" http://localhost:8000/api/v1/system
```

### List security events

```powershell
curl.exe -H "X-API-Key: dev-zero-soc-key" http://localhost:8000/api/v1/events
```

### Create a security event

```powershell
$body = @{
  event_type = "manual-test"
  severity = "low"
  source = "curl"
  message = "Manual API test event"
} | ConvertTo-Json

curl.exe -X POST "http://localhost:8000/api/v1/events" `
  -H "X-API-Key: dev-zero-soc-key" `
  -H "Content-Type: application/json" `
  --data-binary $body
```

### View event summary

```powershell
curl.exe -H "X-API-Key: dev-zero-soc-key" http://localhost:8000/api/v1/events/summary
```

### View one event by ID

Replace `<event_id>` with a real event ID returned from `/api/v1/events`.

```powershell
curl.exe -H "X-API-Key: dev-zero-soc-key" http://localhost:8000/api/v1/events/<event_id>
```

### List network devices

```powershell
curl.exe -H "X-API-Key: dev-zero-soc-key" http://localhost:8000/api/v1/devices
```

### Run network scan

```powershell
curl.exe -H "X-API-Key: dev-zero-soc-key" http://localhost:8000/api/v1/network/scan
```

### View recent request logs

```powershell
curl.exe -H "X-API-Key: dev-zero-soc-key" http://localhost:8000/api/v1/logs/recent
```

### View metrics

```powershell
curl.exe -H "X-API-Key: dev-zero-soc-key" http://localhost:8000/api/v1/metrics
```

## Completed Milestone: Backend Cleanup Pass

- [x] Fixed `do_GET()` route flow
- [x] Added `GET /api/v1/events/{id}`
- [x] Added `GET /api/v1/devices`
- [x] Added `GET /api/v1/network/scan`
- [x] Added `GET /api/v1/metrics`
- [x] Added `do_POST()` for `POST /api/v1/events`
- [x] Connected POST event creation to SQLite
- [x] Fixed POST `request_id` response handling
- [x] Updated server runner to use `run_server()`
- [x] Verified core endpoints with PowerShell `curl.exe`

## Current Features

- Python HTTP backend
- Versioned API routes under `/api/v1`
- API key authentication for protected endpoints
- Consistent JSON API responses
- Request ID tracking
- Structured request logging
- SQLite database storage
- Security event creation and retrieval
- Security event auto-tagging
- Event summary metrics
- Local system health/status endpoints
- Local network scanning
- Network device storage
- Unknown device detection
- Basic operational metrics endpoint

## Tech Stack

- Python
- SQLite
- Raspberry Pi OS Lite
- HTML/CSS/JavaScript planned for dashboard
- GitHub for version control

## Planned Next Steps

- Add a basic web dashboard
- Display system status, event counts, and device data
- Add dashboard API fetch logic
- Improve frontend layout and styling
- Add screenshots to the README
- Add setup instructions for Raspberry Pi deployment
- Add future alerting support

## Project Timeline

### Phase 1: Project Foundation

- [x] Create GitHub repository
- [x] Add initial project structure
- [x] Add Python backend entry point
- [x] Add basic health/status endpoints
- [x] Add versioned API routes

### Phase 2: Backend Core

- [x] Add system information endpoint
- [x] Add API key authentication
- [x] Add structured request logging
- [x] Add SQLite database storage
- [x] Add security event storage
- [x] Add security event filtering
- [x] Add event summary endpoint
- [x] Add POST event creation
- [x] Add single-event lookup by ID
- [x] Add metrics endpoint

### Phase 3: Network Monitoring

- [x] Add local network scanner
- [x] Add MAC address lookup from ARP table
- [x] Store scanned devices in SQLite
- [x] Detect unknown devices
- [x] Create security events for unknown devices
- [x] Add devices endpoint
- [x] Add network scan endpoint

### Phase 4: Dashboard

- [x] Create basic HTML dashboard
- [x] Add dashboard CSS styling
- [x] Fetch backend API data from JavaScript
- [x] Display system health
- [x] Display recent security events
- [x] Display network devices
- [x] Add manual refresh button
- [ ] Display event summary

### Phase 5: Polish and Portfolio Readiness

- [ ] Add screenshots
- [ ] Add setup instructions
- [ ] Add Raspberry Pi deployment notes
- [ ] Add project architecture diagram
- [ ] Add future improvement section
- [ ] Final README polish

## Development Notes

## Development Notes

ZeroSOC is currently in active development. The backend foundation is functional and tested, with protected API endpoints, request logging, SQLite persistence, security event storage, network device tracking, and basic metrics.

Phase 4 dashboard work has started. A basic web dashboard now loads in the browser, connects to the backend API, and displays system health, metrics, recent security events, and network devices. The project now has a working visual layer, making it easier to demonstrate as a cybersecurity/backend portfolio project.

The next major focus is dashboard polish, including cleaner timestamp formatting, API status indicators, improved event summaries, screenshots, and final README presentation.