# Security Policy

## Supported Versions

ZeroSOC is currently a portfolio and home-lab cybersecurity project in active development.

At this stage, only the latest version of the main branch is actively maintained.

| Version | Supported |
|---|---|
| Latest main branch | Yes |
| Older versions | No |

## Reporting a Vulnerability

If you discover a security issue, vulnerability, exposed secret, authentication weakness, or unsafe behavior in this project, please report it responsibly.

Please do **not** open a public GitHub issue for security vulnerabilities.

Instead, report the issue privately by contacting the repository maintainer through GitHub.

When reporting a vulnerability, please include:

- A clear description of the issue
- Steps to reproduce the behavior
- The affected file, endpoint, or feature
- Any relevant screenshots, logs, or request examples
- The potential impact of the issue

## Response Expectations

This is a student portfolio project, so response times may vary.

Expected response process:

1. The report will be reviewed.
2. The issue will be reproduced if possible.
3. A fix or mitigation will be planned.
4. The fix will be committed once verified.
5. Public disclosure will happen only after the issue is resolved.

## Scope

The following areas are in scope:

- API key authentication behavior
- Protected backend routes
- Request logging
- Security event storage
- SQLite database handling
- Network scanning behavior
- Dashboard data exposure
- Misconfigured environment variables
- Accidental secret exposure

The following areas are out of scope:

- Attacks against GitHub itself
- Social engineering
- Physical attacks
- Denial-of-service testing against deployed systems
- Testing against networks or devices without permission

## Responsible Disclosure

Please give the maintainer reasonable time to investigate and fix reported issues before publicly disclosing them.

Do not use discovered vulnerabilities to access, modify, delete, or exfiltrate data.

## Project Status

ZeroSOC is intended for educational, portfolio, and home-lab use. It is not production SOC software.
