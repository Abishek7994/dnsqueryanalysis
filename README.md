# DNS Sentinel

A local DNS-traffic analysis demo with a FastAPI API, SQLite event log, WebSocket event stream, deterministic hostname validation, and a React SOC dashboard. Traffic is simulated; the app does not send DNS requests to external resolvers.

## Requirements

- Python 3.10+
- Node.js 18+

## Start the backend (PowerShell)

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn main:app --reload
```

The API is available at `http://localhost:8000`; interactive API documentation is at `http://localhost:8000/docs`.

## Start the frontend (another PowerShell)

```powershell
cd frontend
npm run dev
```

Open `http://localhost:5173`. The dashboard automatically connects to the API's WebSocket and begins receiving simulated traffic.

## Initialize dependencies

From the workspace root:

```powershell
python -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
cd frontend
npm install
```

The SQLite database is created as `backend/dns_logs.db` on first backend startup.
