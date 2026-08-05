# ZeroSOC Backend API Test Checklist

Use this checklist after backend changes. It describes manual checks; the automated suite remains the authoritative regression check.

## Setup

The application does not automatically load `.env`. Set the required API key in the process environment before startup:

```powershell
$env:ZEROSOC_API_KEY = "replace-with-a-long-random-secret"
python run.py
```

The default API address is `http://127.0.0.1:8000`. In a second PowerShell terminal:

```powershell
$headers = @{ "X-API-Key" = $env:ZEROSOC_API_KEY }
```

## Public endpoints

- [ ] `Invoke-RestMethod "http://127.0.0.1:8000/api/v1/health"` succeeds.
- [ ] `Invoke-RestMethod "http://127.0.0.1:8000/api/v1/status"` succeeds.

## Authentication

- [ ] A protected request with `$headers` succeeds.
- [ ] A protected request without `X-API-Key` returns 401.
- [ ] A protected request with an incorrect key returns 401.
- [ ] Responses and logs do not disclose the configured key.

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/system" -Headers $headers
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/metrics" -Headers $headers
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/events/summary" -Headers $headers
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/devices" -Headers $headers
```

## Request validation

- [ ] JSON write requests include `Content-Type: application/json` and a valid `Content-Length`.
- [ ] Malformed JSON and invalid event fields return 400 without creating a record.
- [ ] Unsupported media types return 415.
- [ ] Bodies larger than `ZEROSOC_MAX_REQUEST_BYTES` return 413.
- [ ] Error responses do not echo bodies, secrets, stack traces, or decoder details.

## Automated regression

```powershell
python -m py_compile run.py app/main.py
python -m unittest tests.test_run
```

Expected ZS-4 baseline: **141/141 tests pass**.

Do not trigger `/api/v1/network/scan` unless you own or are authorized to test the network. Do not configure a real webhook merely to complete this checklist.
