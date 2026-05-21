# ZeroSOC Dashboard Smoke Test Checklist

Use this checklist after dashboard or backend changes to confirm the ZeroSOC dashboard still works correctly.

## Setup

Start the backend:

```powershell
python run.py
```

Backend URL:

```text
http://localhost:8000
```

Start the dashboard server from the project root:

```powershell
python -m http.server 5500
```

Dashboard URL:

```text
http://localhost:5500/dashboard/
```

---

## Page Load

- [ ] Dashboard page opens without a browser error
- [ ] API indicator changes from checking to online
- [ ] Header displays correctly
- [ ] Refresh button is visible
- [ ] Summary cards load
- [ ] Footer last-updated timestamp changes after refresh

---

## Summary Cards

- [ ] System summary card loads
- [ ] Security Events summary card loads
- [ ] Alerts summary card loads
- [ ] Notifications summary card loads
- [ ] Reports summary card loads
- [ ] Devices summary card loads
- [ ] API summary card loads
- [ ] Card status labels are readable

---

## System and Metrics

- [ ] System Status panel loads
- [ ] Hostname displays
- [ ] Platform displays
- [ ] Python version displays
- [ ] Uptime displays
- [ ] Disk usage displays
- [ ] Metrics panel loads
- [ ] Total requests displays
- [ ] Recent errors displays
- [ ] Average latency displays

---

## Event Summary and Charts

- [ ] Event Summary panel loads
- [ ] Total event count displays
- [ ] Severity counts display
- [ ] Event type counts display
- [ ] Tag counts display
- [ ] Events by Severity chart renders
- [ ] Events by Type chart renders
- [ ] Chart labels are readable on the light theme

---

## Security Events

- [ ] Security Events section loads
- [ ] Search events input works
- [ ] Severity dropdown works
- [ ] Time Range dropdown works
- [ ] Export Events button appears once
- [ ] Export Events downloads a CSV
- [ ] No duplicate event filter controls appear

---

## Active Alerts

- [ ] Active Alerts section loads
- [ ] Alert severity filters work
- [ ] Alert priority filters work
- [ ] Alert SLA filters work
- [ ] Alert search works
- [ ] Export Alerts downloads a CSV
- [ ] Export Incidents downloads a CSV
- [ ] Acknowledge button works when alerts exist
- [ ] Resolve button works when alerts exist

---

## Incident Groups

- [ ] Incident Groups section loads
- [ ] Incident owner filter works
- [ ] Incident status filter works
- [ ] Incident activity panel loads
- [ ] Export Incident Activity downloads a CSV
- [ ] Incident assignment prompt opens when incident exists
- [ ] Incident status dropdown works when incident exists

---

## Alert Notifications

- [ ] Alert Notifications section loads
- [ ] Log Active Alerts button works
- [ ] Send Webhook button does not crash the dashboard
- [ ] Notification history updates when local alert logging is used

---

## Investigation Reports

- [ ] Investigation Reports section loads
- [ ] Report status filters work
- [ ] Report search works
- [ ] Report Activity panel loads
- [ ] Export Report Activity downloads a CSV
- [ ] Save Report button works when alerts exist
- [ ] Edit report works when reports exist
- [ ] Print report opens a printable view when reports exist
- [ ] Export report downloads JSON when reports exist
- [ ] Archive and Restore work when reports exist

---

## Resolved Alerts

- [ ] Resolved Alerts section loads
- [ ] Resolved alert history displays when available
- [ ] Reopen button works when resolved alerts exist

---

## Network Devices

- [ ] Network Devices section loads
- [ ] Device summary loads
- [ ] Device table loads
- [ ] Device search works
- [ ] Device status filter works
- [ ] Export Devices downloads a CSV
- [ ] Run Scan starts without breaking the dashboard
- [ ] Run Scan either returns devices or a clean error message

---

## Browser Console

Open DevTools:

```text
F12
```

Check the Console tab:

- [ ] No red JavaScript errors
- [ ] No duplicate ID warnings
- [ ] No missing element errors
- [ ] No failed API calls except expected protected-route or network-scan edge cases

---

## Final Result

- [ ] Dashboard is usable
- [ ] Backend remains running
- [ ] No visible layout breakage
- [ ] No major console errors
- [ ] Export buttons work
- [ ] Filters work