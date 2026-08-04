# ZeroSOC Known Limitations and Next Upgrades

This document tracks current limitations, expected development constraints, and planned future improvements for ZeroSOC.

---

## Known Limitations

### Backend

- [ ] The backend currently uses Python's built-in `http.server` instead of a production web framework.
- [ ] Most backend logic is currently contained in `run.py`.
- [ ] The backend should eventually be split into smaller modules.
- [ ] The development API key defaults to `replace-with-a-long-random-secret`.
- [ ] Environment-based production configuration is not fully implemented yet.
- [ ] Request logging exists, but long-term log rotation is not implemented.
- [ ] API pagination is limited.
- [ ] Error handling works, but could be made more detailed across all endpoints.
- [ ] The backend API runs separately on port `8000`.

### Dashboard

- [ ] The dashboard is functional, but not yet fully accessibility-tested.
- [ ] Dashboard error handling could be improved.
- [ ] Some dashboard actions still use browser prompts.
- [ ] Larger datasets may need pagination or virtual scrolling.
- [ ] Chart styling is functional, but could be refined further.
- [ ] The dashboard currently runs through a local static server on port `5500`.
- [ ] Protected routes require the `X-API-Key` header and cannot be tested directly from the browser address bar.

### Security Events and Alerts

- [ ] Event auto-tagging is rule-based and intentionally simple.
- [ ] Alert creation is derived from high-priority or review-worthy events.
- [ ] Alert correlation is basic and based mostly on source and event type.
- [ ] No advanced threat intelligence feed integration exists yet.
- [ ] No email notification provider is integrated yet.
- [ ] Webhook notification support requires `ZEROSOC_ALERT_WEBHOOK_URL`.

### Network Scanning

- [ ] Network scanning may be slow on larger subnets.
- [ ] Some devices may not respond to ping.
- [ ] MAC address detection depends on the local ARP table.
- [ ] Device detection behavior may differ between Windows and Raspberry Pi OS.
- [ ] Network scan timing and reliability need Raspberry Pi testing.

### Raspberry Pi Deployment

- [ ] Raspberry Pi hardware deployment has not been completed yet.
- [ ] systemd service setup has not been added.
- [ ] Boot-time auto-start has not been configured.
- [ ] Raspberry Pi CPU temperature support should be tested on real hardware.
- [ ] Dashboard access from another device on the network still needs final validation.

---

## Next Upgrades

### Short-Term Upgrades

- [x] Complete Phase 9 local deployment testing
- [x] Verify core public API endpoints
- [x] Verify core protected API endpoints
- [x] Test missing API key rejection
- [x] Test invalid API key rejection
- [x] Test dashboard refresh workflow
- [x] Capture Phase 9 API response screenshots
- [x] Capture Phase 9 dashboard refresh screenshot
- [ ] Verify all README screenshot links
- [ ] Update screenshot inventory documentation
- [ ] Add architecture diagram
- [ ] Add final demo walkthrough section
- [ ] Add Raspberry Pi deployment guide

### Backend Cleanup

- [ ] Split `run.py` into modules
- [ ] Move configuration into `app/config.py`
- [ ] Move database logic into `app/database.py`
- [ ] Move authentication helpers into `app/auth.py`
- [ ] Move request logging helpers into `app/logging_utils.py`
- [ ] Move system health helpers into `app/system.py`
- [ ] Move security event logic into `app/events.py`
- [ ] Move alert logic into `app/alerts.py`
- [ ] Move incident logic into `app/incidents.py`
- [ ] Move report logic into `app/reports.py`
- [ ] Move notification logic into `app/notifications.py`
- [ ] Move device and scanner logic into `app/devices.py` and `app/scanner.py`

### Dashboard Improvements

- [ ] Replace browser prompts with modal dialogs
- [ ] Add loading indicators to individual panels
- [ ] Add friendlier empty states
- [ ] Improve mobile dashboard layout
- [ ] Add pagination for large tables
- [ ] Add better error messages for failed API requests
- [ ] Add dashboard settings for API URL and API key

### Security Improvements

- [ ] Move the API key fully into environment configuration
- [ ] Add `.env` loading support
- [ ] Add API key setup instructions
- [ ] Add optional IP allowlist support
- [ ] Add stronger validation for POST bodies
- [ ] Add safer webhook configuration notes
- [ ] Avoid exposing development secrets in screenshots or documentation

### Raspberry Pi Deployment

- [ ] Test backend on Raspberry Pi Zero 2 W
- [ ] Test network scan behavior on Raspberry Pi OS
- [ ] Add Raspberry Pi setup guide
- [ ] Add systemd service file example
- [ ] Add boot-time startup instructions
- [ ] Add local network dashboard access instructions
- [ ] Add troubleshooting section for Pi deployment

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

docs/
  backend-api-test-checklist.md
  dashboard-smoke-test-checklist.md
  screenshots-inventory.md
  known-limitations-and-next-upgrades.md

screenshots/
  dashboard-overview.png
  event-summary-analytics.png
  alerts-incidents-notifications.png
  reports-resolved-alerts.png
  events-devices.png
  api-health.png
  phase-9-health-test.png
  phase-9-status-test.png
  phase-9-system-test.png
  phase-9-events-test.png
  phase-9-events-summary-test.png
  phase-9-devices-test.png
  phase-9-metrics-test.png
  phase-9-missing-api-key-test.png
  phase-9-bad-api-key-test.png
  phase-9-dashboard-refresh.png

data/
  zerosoc.db

logs/
  requests.log

run.py
README.md
requirements.txt
.env.example
.gitignore