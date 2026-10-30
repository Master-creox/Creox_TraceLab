# Creox TraceLab v1.0 — Unified Release

**Creox TraceLab** is a local-first digital forensics investigation workbench by Creox Tech Labs. This unified release brings the functionality developed across Milestones 1–6 into one coherent application.

## Included capabilities
- Investigation case creation, status tracking, workspace view
- Evidence acquisition, SHA-256 hashing, integrity verification
- Evidence encryption at rest using Fernet; authenticated download decrypts and verifies plaintext
- Offline PCAP metadata analysis and log analysis
- Analyst observations and UTC-normalized event timeline
- Investigation report generation with canonical JSON digest and HTML report view
- JWT-style signed bearer sessions, PBKDF2 password hashing, Admin/Analyst roles
- Hash-chained security audit events with verification endpoint
- Backup-ready local `data/` storage, Docker and CI starter workflow

## Installation on Windows

1. Extract ZIP and open the folder in VS Code.

2. Install backend dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

3. Generate two security keys:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put them in `.env`:
- First key → `TRACE_LAB_JWT_SECRET`
- Second key → `TRACE_LAB_EVIDENCE_KEY`

Do not commit `.env`.

4. Create your administrator:

```powershell
python scripts_create_admin.py --username admin --password "Your-Strong-Password-123!"
```

5. Start backend:

```powershell
uvicorn app.main:app --reload
```

6. Start frontend in another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in your terminal (normally `http://localhost:5173`) and sign in with the admin credentials. Open `http://127.0.0.1:8000` for health and `http://127.0.0.1:8000/docs` for API documentation.

## Create analyst accounts
Sign in through Swagger or the dashboard, then use `POST /api/v1/admin/users` with an admin bearer token:

```json
{"username":"analyst1","password":"Use-Another-Long-Password!","role":"analyst"}
```

## Security endpoints
- `GET /api/v1/security/me` — current session
- `GET /api/v1/security/audit` — admin-only security audit
- `GET /api/v1/security/audit/verify` — verify hash chain
- `GET /api/v1/evidence/{id}/download` — authenticated decrypted download with plaintext SHA-256 check

## Backup and restore

```powershell
python -m scripts.backup --output backups
python -m scripts.restore --archive backups\tracelab-YYYYMMDD-HHMMSS.zip --destination restore_test
```

The archive contains the SQLite database and encrypted evidence files, but not `.env` secrets. Keep the Fernet key backed up separately in a secure password manager or secrets vault; without it, evidence cannot be decrypted.

## Important data migration note
This unified v1.0 uses the SQLite database and encrypted evidence storage under `data/`. **Do not copy an older milestone database/evidence folder directly into this release.** Older milestone evidence files were not encrypted. Export reports and preserve old project folders separately; if migrating existing cases, use a documented migration utility and verify every original SHA-256 before importing.

## Production readiness
This is a portfolio/development release, not a certified forensic platform. Before real legal or operational use, obtain an independent security review; use HTTPS, a managed secret store/KMS, MFA, rate limiting, immutable external audit checkpoints, access logging, backup/restore drills, retention policy, and documented chain-of-custody procedures. Hash chaining is tamper-evident but not immutable if an attacker can rewrite the database and recompute the chain. Fernet key loss means evidence cannot be decrypted. Keep encrypted backups and keys separately secured.

## License
Add a license before public distribution. Use only on systems and evidence you are authorized to investigate.
