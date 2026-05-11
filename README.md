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

ZeroSOC currently has a working lightweight Python backend with health, status, and system visibility endpoints. The backend supports both legacy routes and versioned API routes.

Current stage:

```text
Backend foundation complete; route refactor and request logging are next.