# ZeroSOC Known Limitations and Next Upgrades

This document separates current constraints from genuinely planned work. ZeroSOC is a portfolio and home-lab project, not production SOC software.

## Current limitations

### Backend and deployment

- The supported backend is a single-process standard-library `HTTPServer`, with most active logic consolidated in `run.py`.
- Authentication uses one shared API key; there are no user accounts, roles, sessions, or key-usage audit identities.
- Transport is plain HTTP. TLS termination and reverse-proxy deployment are not provided.
- Rate limiting, account lockout, and production denial-of-service controls are not implemented.
- API pagination is limited, and large datasets need further performance testing.
- Request logs and SQLite data are local runtime artifacts; automated retention, rotation, backup, and recovery are not provided.

### Detection and notifications

- Event tagging, alert creation, and correlation are intentionally rule-based and basic.
- No threat-intelligence feed or email provider is integrated.
- Webhook delivery requires an operator-supplied `ZEROSOC_ALERT_WEBHOOK_URL`; endpoint trust, TLS, availability, and downstream handling are operator responsibilities.

### Dashboard

- The static dashboard is not fully accessibility-tested.
- Some actions use browser prompts. The event table has bounded keyboard-accessible scrolling, but large datasets may still need API pagination or virtual scrolling.
- The dashboard is normally served separately on port 5500 and must be given the API key for protected requests.

### Network scanning and Raspberry Pi

- Ping and ARP behavior varies by operating system, permissions, firewall, and network topology; some devices do not answer probes.
- Network timing, CPU-temperature reporting, cross-device dashboard access, and overall behavior have not been validated on Raspberry Pi hardware.
- systemd service setup and boot-time startup are not implemented.
- The default backend bind remains `127.0.0.1`; LAN exposure requires an explicit, security-sensitive configuration choice.

## Completed security work

Through ZS-3.1, ZeroSOC requires an environment-supplied key, compares it in constant time, protects sensitive routes, defaults to localhost, restricts CORS to exact origins, validates JSON request bodies, enforces bounded request sizes before reading, and rejects ambiguous or unsupported request framing. Later portfolio phases retained those controls; current test results are recorded in the README rather than asserted here as a stale phase baseline.

These controls do not make the project production-ready or penetration-tested.

## Planned upgrades

- Evaluate per-user identity, roles, key rotation, and auditable authorization.
- Add production-oriented TLS/reverse-proxy and rate-limiting guidance.
- Improve API pagination, very-large-dataset behavior, broader dashboard accessibility coverage, and non-prompt interactions.
- Expand detection and correlation beyond basic local rules.
- Define log/data retention, backup, and recovery procedures.
- Validate the application and scanner on Raspberry Pi hardware before publishing deployment claims.
- Document systemd/boot-time operation only after hardware validation.
- Decide whether to remove or modernize the retained historical `app/main.py` entry point in a future scoped phase.
