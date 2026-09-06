# ZeroSOC Raspberry Pi Deployment

This document describes the persistent Raspberry Pi runtime: two `systemd` services that survive closed terminals, process crashes, and reboots, reached from Windows over an SSH tunnel. It records a deployment that was verified on hardware, including a real reboot.

Paths and the account name below are from the verified deployment. Adapt them if your Pi differs.

## Services

Two units run the deployment. Reproducible, secret-free copies of the deployed files are tracked in [`deploy/systemd/`](../deploy/systemd/).

| | Backend | Dashboard |
| --- | --- | --- |
| Unit | `zerosoc-backend.service` | `zerosoc-dashboard.service` |
| Installed at | `/etc/systemd/system/zerosoc-backend.service` | `/etc/systemd/system/zerosoc-dashboard.service` |
| Runs as | `devdevbuilds` | `devdevbuilds` |
| WorkingDirectory | `/home/devdevbuilds/zerosoc` | `/home/devdevbuilds/zerosoc/dashboard` |
| Binds | `127.0.0.1:8000` | `127.0.0.1:5500` |
| Restart | `on-failure`, 5s delay | `on-failure`, 5s delay |
| Starts at boot | yes (`multi-user.target`) | yes (`multi-user.target`) |

Both start after `network-online.target`, run unprivileged, and log to the journal under the identifiers `zerosoc-backend` and `zerosoc-dashboard`.

### Installing the units

From a clone of this repository on the Pi:

```bash
sudo install -m 644 -o root -g root deploy/systemd/zerosoc-backend.service /etc/systemd/system/
sudo install -m 644 -o root -g root deploy/systemd/zerosoc-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
systemd-analyze verify zerosoc-backend.service zerosoc-dashboard.service
sudo systemctl enable --now zerosoc-backend.service zerosoc-dashboard.service
```

`systemd-analyze verify` is a non-destructive check; run it before enabling anything. The tracked copies use absolute paths under `/home/devdevbuilds/zerosoc`; edit them to match your account and clone location before installing.

### Localhost-only binding

Both services bind `127.0.0.1` and are therefore unreachable from the LAN. Access is through the SSH tunnel only.

The backend needs care here. `run.py` reads `ZEROSOC_HOST` from the environment, and the private `.env` sets it to `0.0.0.0`. `systemd` applies `EnvironmentFile=` *after* `Environment=`, so an `Environment=ZEROSOC_HOST=...` line in the unit cannot override the file. The unit therefore enforces the bind at exec time, where it cannot be overridden:

```ini
ExecStart=/usr/bin/env ZEROSOC_HOST=127.0.0.1 /home/devdevbuilds/zerosoc/.venv/bin/python /home/devdevbuilds/zerosoc/run.py
```

`.env` is left unmodified, so a manual `python3 run.py` keeps its existing behavior.

The dashboard service serves the `dashboard/` directory as its document root rather than the repository root. Serving the repository root would publish `.env`, `.git/`, and `data/*.db` over HTTP.

### Environment and secrets

The backend loads configuration with:

```ini
EnvironmentFile=/home/devdevbuilds/zerosoc/.env
```

`.env` stays on the Pi at mode `0600`, owned by `devdevbuilds`. It is listed in `.gitignore` and is **not tracked in this repository** — only `.env.example` is. No API key or other secret appears in the unit files, in this documentation, or anywhere in version control. Rotating the key means editing `.env` on the Pi and running `sudo systemctl restart zerosoc-backend`.

## Windows SSH tunnel launcher

[`scripts/Start-ZeroSOCTunnel.ps1`](../scripts/Start-ZeroSOCTunnel.ps1) opens the tunnel and launches the dashboard:

```powershell
.\scripts\Start-ZeroSOCTunnel.ps1
```

It forwards `localhost:8000` and `localhost:5500` to the matching loopback ports on the Pi, waits for `/health` to return 200, then opens the dashboard in the default browser and stays in the foreground so failures remain visible. `Ctrl+C` closes the tunnel.

The backend must be forwarded to local port **8000** specifically, because `dashboard/app.js` hardcodes `API_BASE_URL = "http://localhost:8000"`.

The script contains no password and no API key. It authenticates with an SSH key (default `%USERPROFILE%\.ssh\zerosoc_claude`); if that key has a passphrase, SSH prompts for it in the window. The dashboard prompts for the ZeroSOC API key separately in the browser. If a local port is already in use, the script names the port, the owning process and PID, and exits without starting a tunnel.

Useful parameters: `-NoBrowser`, `-IdentityFile`, `-PiUser`, `-PiHostName`, `-BackendPort`, `-DashboardPort`.

## Dashboard URL

With the tunnel running, the dashboard is at:

```text
http://localhost:5500/
```

Because the dashboard service serves the `dashboard/` directory as its document root, the page is at the server root. The older `http://localhost:5500/dashboard/` path came from manually serving the repository root and returns 404 under this deployment.

## Operating the deployment

Status:

```bash
systemctl status zerosoc-backend zerosoc-dashboard
systemctl is-enabled zerosoc-backend zerosoc-dashboard
systemctl is-active zerosoc-backend zerosoc-dashboard
```

Restart and stop:

```bash
sudo systemctl restart zerosoc-backend
sudo systemctl restart zerosoc-dashboard
sudo systemctl stop zerosoc-backend zerosoc-dashboard
```

Logs:

```bash
journalctl -u zerosoc-backend -f
journalctl -u zerosoc-dashboard -n 50 --no-pager
journalctl -u zerosoc-backend -b          # current boot only
```

After editing a unit file:

```bash
sudo systemctl daemon-reload
sudo systemctl restart zerosoc-backend zerosoc-dashboard
```

### Reboot verification

Confirm the services return on their own, with no terminal session involved:

```bash
sudo systemctl reboot
# wait for SSH, reconnect, then:
uptime -p
systemctl is-active zerosoc-backend zerosoc-dashboard
ss -tlnp | grep -E ':8000|:5500'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/health
```

Expect `active` for both, listeners on `127.0.0.1:8000` and `127.0.0.1:5500`, and `200` from `/health`. Confirming the service processes report `PPID 1` proves `systemd` owns them rather than a login shell:

```bash
ps -eo pid,ppid,user,args | grep -E 'run\.py|http\.server' | grep -v grep
```

Authenticated access can be checked without printing the key:

```bash
cd /home/devdevbuilds/zerosoc
KEY=$(grep -m1 '^ZEROSOC_API_KEY=' .env | cut -d= -f2-)
curl -s -o /dev/null -w 'with key: %{http_code}\n' -H "X-API-Key: $KEY" http://127.0.0.1:8000/api/v1/system
curl -s -o /dev/null -w 'no key:   %{http_code}\n' http://127.0.0.1:8000/api/v1/system
unset KEY
```

Expect `200` and `401`.

## Deferred hardening

These are known and deliberately out of scope for the runtime-persistence work. They are recorded here rather than silently carried.

- **No host firewall on the Pi.** `ufw`, `nft`, and `iptables` are not installed. This is mitigated but not replaced by the loopback-only binding: at verification, the only LAN-exposed listener was SSH on port 22. There is no packet filter as defense in depth.
- **`ZEROSOC_HOST=0.0.0.0` remains in `.env`.** Only the service is pinned to loopback, at exec time. A manual `python3 run.py` still binds all interfaces.
- **Vestigial entries in `ZEROSOC_ALLOWED_ORIGINS`.** The list still contains LAN origins such as `http://10.2.1.220:5500` and `http://zerosoc.local:5500`. They cannot function while `dashboard/app.js` hardcodes `localhost:8000`, since a LAN browser would resolve `localhost` to itself. They are harmless and were left alone as configuration adjacent to the API contract.
- **Reboot persistence is proven by a single clean reboot**, not by a repeated power-loss soak test.
- **Transport inside the tunnel is plain HTTP.** Confidentiality depends on SSH, consistent with the constraints in [Known Limitations and Next Upgrades](known-limitations-and-next-upgrades.md).
