# ATHENA: Autonomous Cyber Threat Hunting and Evolving Neural AI (MVP)

A working SOC-style dashboard (plain HTML, CSS and JavaScript, no build step) backed by a modular Flask REST API.
**All detection is simulated.** ATHENA does not analyze real traffic and is not a production security engine.

## Features
Login with roles, Overview dashboard, Live Alerts (search, filter, sort, details, status updates), Detection Analysis (pipeline + Run Analysis),
Network Activity (charts + flow table), downloadable Reports, Admin controls (enable/disable engine, refresh models, generate/clear alerts).

## Architecture
User -> Login -> React dashboard -> Flask REST API -> validation/preprocessing (`services/detection.py`) -> detection engine
(`models/detectors.py`: Isolation Forest sim, STMP sim, Zero-Day Lab sim -> anomaly score -> threat score) -> data layer
(`services/store.py`, in-memory) -> alerts / reports / visualization -> dashboard.
To plug in real ML, replace the classes in `backend/models/detectors.py` (keep `score(event)`) and swap `store.py` for a database.
No architecture diagram file was attached to the request, so the structure follows the flow described in the brief.

## Tech stack
HTML5, CSS3, vanilla JavaScript (ES2020) with hand-written SVG charts; Python 3.12, Flask, flask-cors, gunicorn.

## Run locally
```bash
# backend (http://localhost:5000)
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && python app.py
# frontend (http://localhost:5173), any static server works
cd frontend && python -m http.server 5173
```
Or with Docker: `docker compose up --build` then open http://localhost:8080.

## Demo credentials
`admin` / `athena123` (Admin role, full access). SOC Analyst and Regular User roles are modeled in `USERS` in `backend/routes/api.py` but only admin is enabled.

## Environment variables
| Where | Name | Purpose |
|---|---|---|
| backend | `SECRET_KEY` | Signs login tokens. Set a long random value in production |
| backend | `ADMIN_PASSWORD` | Demo password (default `athena123`) |
| backend | `CORS_ORIGINS` | Comma-separated allowed frontend origins |
| frontend | `window.ATHENA_API_URL` in `frontend/js/config.js` | Backend base URL, no trailing slash |

## API endpoints
Public: `POST /api/login`, `GET /api/health`. Authenticated (Bearer token): `GET /api/dashboard`, `GET /api/alerts`, `PATCH /api/alerts/<id>`,
`DELETE /api/alerts` (admin), `GET /api/network-events`, `GET /api/reports`, `GET /api/reports/<id>/download`, `GET /api/model-status`,
`POST /api/analyze`, `POST /api/generate-alert`, `GET /api/admin/status`, `POST /api/admin/engine` (admin), `POST /api/admin/refresh-models` (admin).

`POST /api/analyze` body: `{"source_ip":"192.168.1.20","destination_ip":"10.0.0.5","protocol":"TCP","packet_count":450}`.
It returns `anomaly_score`, `threat_score`, `severity`, `prediction`, `confidence`, per-model `details`, and the alert it created (when score is 40 or higher).

## Deploy
**Backend on Render:** New > Web Service > connect repo, Root Directory `backend`, Build `pip install -r requirements.txt`,
Start `gunicorn app:app`. Set `SECRET_KEY` (random), `ADMIN_PASSWORD`, and `CORS_ORIGINS` (your Vercel URL). Check `/api/health`.
Railway works the same way: set the root to `backend`; the Dockerfile uses `$PORT`.
**Frontend on Vercel:** Import repo, Root Directory `frontend`, Framework Preset `Other`, no build command, output directory `.`.
Edit `frontend/js/config.js` to your Render URL, deploy, then add the Vercel URL to the backend's `CORS_ORIGINS` and redeploy the backend.

## Limitations
Simulated detection; in-memory data resets on restart and is not shared across multiple gunicorn workers (use one worker for the demo);
single demo user; token kept in localStorage; charts for traffic and trends are generated, not live.

## Future improvements
Real scikit-learn Isolation Forest and statistical baselines, PCAP/NetFlow ingestion, SQLite/Postgres, real user management with hashed passwords,
WebSocket live alerts, automated response actions, tests and CI.
