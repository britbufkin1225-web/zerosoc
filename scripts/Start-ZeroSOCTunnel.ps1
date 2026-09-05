#Requires -Version 5.1
<#
.SYNOPSIS
    Opens the SSH tunnel to the ZeroSOC Raspberry Pi and launches the dashboard.

.DESCRIPTION
    The ZeroSOC backend and dashboard run as persistent systemd services on the
    Pi (zerosoc-backend.service, zerosoc-dashboard.service). Both bind to
    127.0.0.1 on the Pi only, so they are not reachable over the LAN. This
    script forwards both ports over SSH and opens the dashboard locally.

    The backend is forwarded to the SAME local port (8000) because
    dashboard/app.js hardcodes API_BASE_URL = "http://localhost:8000".

    This script contains no password and no API key. Authentication uses your
    SSH key; if the key has a passphrase, SSH prompts for it in this window.
    The dashboard prompts for the ZeroSOC API key separately in the browser.

    The window stays open while the tunnel runs so that any failure remains
    visible. Press Ctrl+C to close the tunnel.

.EXAMPLE
    .\scripts\Start-ZeroSOCTunnel.ps1

.EXAMPLE
    .\scripts\Start-ZeroSOCTunnel.ps1 -NoBrowser
#>
[CmdletBinding()]
param(
    [string]$PiUser         = 'devdevbuilds',
    [string]$PiHostName     = 'zerosoc.local',
    [int]   $BackendPort    = 8000,
    [int]   $DashboardPort  = 5500,
    [string]$IdentityFile   = (Join-Path $env:USERPROFILE '.ssh\zerosoc_claude'),
    [int]   $ReadyTimeoutSec = 60,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "    $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "    $Message" -ForegroundColor Yellow }

function Test-LocalPortInUse {
    param([int]$Port)

    # Get-NetTCPConnection is present on Windows 8/2012 and later.
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
                Select-Object -First 1
    if ($null -eq $listener) { return $null }

    $owner = $null
    if ($listener.OwningProcess) {
        $owner = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{
        Port        = $Port
        ProcessId   = $listener.OwningProcess
        ProcessName = if ($owner) { $owner.ProcessName } else { '<unknown>' }
    }
}

# --- Preflight -------------------------------------------------------------

Write-Step "Checking prerequisites"

$ssh = Get-Command ssh -ErrorAction SilentlyContinue
if (-not $ssh) {
    Write-Host "ERROR: 'ssh' was not found on PATH." -ForegroundColor Red
    Write-Host "       Install the Windows OpenSSH client, or run this from Git Bash's PATH." -ForegroundColor Red
    exit 1
}
Write-Ok "ssh found at $($ssh.Source)"

if (-not (Test-Path -LiteralPath $IdentityFile)) {
    Write-Host "ERROR: SSH key not found at: $IdentityFile" -ForegroundColor Red
    Write-Host "       Pass a different key with -IdentityFile <path>." -ForegroundColor Red
    exit 1
}
Write-Ok "identity file present"

Write-Step "Checking local ports $BackendPort and $DashboardPort"

$conflicts = @()
foreach ($port in @($BackendPort, $DashboardPort)) {
    $inUse = Test-LocalPortInUse -Port $port
    if ($inUse) { $conflicts += $inUse }
}

if ($conflicts.Count -gt 0) {
    Write-Host ""
    Write-Host "ERROR: cannot open the tunnel - local port(s) already in use:" -ForegroundColor Red
    foreach ($c in $conflicts) {
        Write-Host ("       port {0} is held by {1} (PID {2})" -f $c.Port, $c.ProcessName, $c.ProcessId) -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "This usually means a ZeroSOC tunnel is already running." -ForegroundColor Yellow
    Write-Host "Either use the existing tunnel, or close the owning process, for example:" -ForegroundColor Yellow
    foreach ($c in $conflicts) {
        Write-Host ("       Stop-Process -Id {0}" -f $c.ProcessId) -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "You can also pick different local ports with -BackendPort / -DashboardPort," -ForegroundColor Yellow
    Write-Host "but the dashboard only works when the backend is on local port 8000." -ForegroundColor Yellow
    exit 1
}
Write-Ok "both local ports are free"

# --- Open the tunnel -------------------------------------------------------

$dashboardUrl = "http://localhost:$DashboardPort/"
$healthUrl    = "http://localhost:$BackendPort/health"
$target       = "$PiUser@$PiHostName"

$sshArgs = @(
    '-N'
    '-o'; 'ExitOnForwardFailure=yes'
    '-o'; 'ServerAliveInterval=30'
    '-o'; 'ServerAliveCountMax=3'
    '-i'; $IdentityFile
    '-L'; "${BackendPort}:127.0.0.1:${BackendPort}"
    '-L'; "${DashboardPort}:127.0.0.1:${DashboardPort}"
    $target
)

Write-Step "Opening SSH tunnel to $target"
Write-Host "    forwarding localhost:$BackendPort   -> Pi 127.0.0.1:$BackendPort   (backend API)"
Write-Host "    forwarding localhost:$DashboardPort -> Pi 127.0.0.1:$DashboardPort (dashboard)"
Write-Host "    (if your SSH key has a passphrase, enter it below)"
Write-Host ""

$tunnel = Start-Process -FilePath $ssh.Source -ArgumentList $sshArgs -PassThru -NoNewWindow

try {
    Write-Step "Waiting for the backend to answer through the tunnel"

    $deadline = (Get-Date).AddSeconds($ReadyTimeoutSec)
    $ready    = $false

    while ((Get-Date) -lt $deadline) {
        if ($tunnel.HasExited) { break }
        try {
            $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 3
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        }
        catch {
            Start-Sleep -Milliseconds 800
        }
    }

    if ($tunnel.HasExited) {
        Write-Host ""
        Write-Host "ERROR: the SSH tunnel exited before it became ready (exit code $($tunnel.ExitCode))." -ForegroundColor Red
        Write-Host "       Check the SSH output above - a wrong passphrase, an unreachable host," -ForegroundColor Red
        Write-Host "       or a rejected key are the usual causes." -ForegroundColor Red
        exit 1
    }

    if (-not $ready) {
        Write-Warn "backend did not return HTTP 200 within $ReadyTimeoutSec seconds."
        Write-Warn "The tunnel is open, so this usually means the Pi services are down."
        Write-Warn "Check on the Pi with:"
        Write-Warn "    systemctl status zerosoc-backend zerosoc-dashboard"
    }
    else {
        Write-Ok "backend healthy at $healthUrl"

        if (-not $NoBrowser) {
            Write-Step "Opening the dashboard"
            Write-Ok $dashboardUrl
            Start-Process $dashboardUrl | Out-Null
        }
        else {
            Write-Step "Dashboard available at $dashboardUrl (-NoBrowser was set)"
        }
    }

    Write-Host ""
    Write-Host "Tunnel is running. Keep this window open." -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to close the tunnel." -ForegroundColor Cyan
    Write-Host ""

    Wait-Process -Id $tunnel.Id
}
finally {
    if ($tunnel -and -not $tunnel.HasExited) {
        Write-Host ""
        Write-Step "Closing SSH tunnel"
        Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue
        Write-Ok "tunnel closed"
    }
}
