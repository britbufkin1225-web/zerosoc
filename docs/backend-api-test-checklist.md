# ZeroSOC Backend API Test Checklist

Use this checklist after backend changes to confirm the API still works correctly.

## Setup

Start the backend:

```powershell
python run.py

http://localhost:8000

$headers = @{ "X-API-Key" = "replace-with-a-long-random-secret" }