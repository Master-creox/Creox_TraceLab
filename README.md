# Creox TraceLab — Milestone 5: Command Dashboard

Milestone 5 adds a responsive dark-themed web dashboard to the existing local-first forensic API. It includes case overview, evidence inventory, case observations, investigation timeline, report generation, and report viewing.

## Requirements
- Python 3.11+
- Node.js 18+ (for Vite development frontend)
- Existing API dependencies from `requirements.txt`

## Run backend
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Run frontend
Open a second terminal:
```powershell
cd frontend
npm install
npm run dev
```
Open the Vite URL shown in the terminal (normally http://localhost:5173).

The Vite development server proxies `/api` and `/health` to `http://127.0.0.1:8000`.

## Production frontend build
```powershell
cd frontend
npm run build
```
The build output is `frontend/dist`. This milestone keeps frontend and API as separate processes; configure a trusted reverse proxy before production deployment.

## Dashboard capabilities
- Case list and case selection.
- Create case.
- Case status and priority display.
- Evidence upload to the selected case.
- Evidence SHA-256 and integrity status.
- Run offline log or PCAP analysis.
- Add analyst observations.
- Add timeline events and show UTC timeline.
- Generate and inspect HTML forensic reports.
- API health indicator.

## Security notes
This dashboard is a local development interface. It does not include user authentication or role-based access control. Keep the API bound to localhost and do not expose it to the internet or an untrusted network. Use only evidence you are authorized to examine. Before multi-user use, add authentication, authorization, CSRF protections as appropriate, strict CORS, secure session handling, encrypted storage, backups, retention controls, and deployment hardening.

The report generator creates HTML content for review/printing. Do not treat a report digest as a digital signature or legal certification.
