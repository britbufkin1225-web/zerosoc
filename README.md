# ZeroSOC

ZeroSOC is a lightweight Raspberry Pi Zero 2 W-powered security operations dashboard for monitoring local system health, local network devices, API activity, and suspicious security events.

## Project Goals

- Monitor Raspberry Pi system health
- Scan local network devices
- Collect and store security events
- Expose protected backend API endpoints
- Track API requests and authentication attempts
- Display status data in a web dashboard
- Use SQLite for lightweight persistence

## Planned Features

- Pi system health monitor
- Local network device scanner
- Security event log collector
- Web dashboard
- API key authentication
- Request logging
- SQLite database
- Suspicious event tagging
- Future alerting system

## Tech Stack

- Python
- FastAPI
- SQLite
- Raspberry Pi OS Lite
- HTML/CSS/JavaScript
- GitHub

## Status

Initial project setup in progress.

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
- [x] Add `/health` endpoint
- [x] Add `/status` endpoint
- [x] Add `/system` endpoint
- [x] Add basic 404 handling

### Phase 3: System Visibility
- [x] Add hostname reporting
- [x] Add OS/platform reporting
- [x] Add Python version reporting
- [x] Add uptime tracking
- [x] Add disk usage reporting
- [x] Add Raspberry Pi-compatible CPU temperature support
- [ ] Split `/status` and `/system` responsibilities

### Phase 4: API Structure
- [ ] Add `/api/v1/health`
- [ ] Add `/api/v1/status`
- [ ] Add `/api/v1/system`
- [ ] Add centralized route handling
- [ ] Add consistent response format

### Phase 5: Security Events
- [ ] Add request logging
- [ ] Add request IDs
- [ ] Add suspicious event tagging
- [ ] Add `/events` endpoint
- [ ] Add `/events/recent` endpoint

### Phase 6: Local Network Monitoring
- [ ] Add local network scanner
- [ ] Add device inventory
- [ ] Add `/devices` endpoint
- [ ] Add `/devices/scan` endpoint

### Phase 7: Database Storage
- [ ] Add SQLite database
- [ ] Store request logs
- [ ] Store security events
- [ ] Store discovered devices

### Phase 8: Dashboard UI
- [ ] Build dashboard frontend
- [ ] Add system health cards
- [ ] Add recent events table
- [ ] Add local devices table
- [ ] Add refresh controls

### Phase 9: Raspberry Pi Deployment
- [ ] Deploy backend to Raspberry Pi Zero 2 W
- [ ] Enable SSH access
- [ ] Add systemd service
- [ ] Start ZeroSOC automatically on boot

### Phase 10: Portfolio Polish
- [ ] Add screenshots
- [ ] Add architecture diagram
- [ ] Add setup guide
- [ ] Add API documentation
- [ ] Add final project demo