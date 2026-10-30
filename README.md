# Creox TraceLab — Milestone 3: Case Investigation

A local-first digital-forensics workbench. This release combines the Evidence Vault, offline artifact analysis, and case investigation management.

## Milestone 3 features
- Create and list investigation cases.
- View case details and linked evidence.
- Add analyst observations linked to a case and optionally to evidence.
- Add timeline events with source timestamps and normalized UTC timestamps.
- Link evidence to timeline events.
- Filter timeline by case and sort chronologically.
- Audit case, observation, and timeline operations.
- Retains Milestone 1 evidence upload/hash/verification and Milestone 2 offline log/PCAP analysis.

## Install
Python 3.11+ recommended.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Linux/macOS: `source .venv/bin/activate`

Open http://127.0.0.1:8000/docs

## API workflow
1. Create a case: `POST /api/v1/cases`
2. Upload evidence using its `case_id`: `POST /api/v1/evidence`
3. Add an observation: `POST /api/v1/cases/{case_id}/observations`
4. Add a timeline event: `POST /api/v1/cases/{case_id}/timeline`
5. View the case workspace: `GET /api/v1/cases/{case_id}`
6. View chronological timeline: `GET /api/v1/cases/{case_id}/timeline`

### Create a case JSON
```json
{
  "case_id": "CASE-2026-001",
  "title": "Suspicious workstation activity",
  "description": "Authorized internal investigation",
  "priority": "medium"
}
```

### Add an observation JSON
```json
{
  "title": "Repeated authentication failures",
  "content": "The supplied log contains multiple failed sign-in events.",
  "classification": "observation",
  "evidence_id": 1
}
```

### Add a timeline event JSON
```json
{
  "title": "First recorded failed login",
  "details": "Timestamp extracted from the supplied authentication log.",
  "event_time": "2026-10-30T08:15:00+05:30",
  "event_type": "log_event",
  "evidence_id": 1
}
```

## API overview
- `POST /api/v1/cases` — create case
- `GET /api/v1/cases` — list cases
- `GET /api/v1/cases/{case_id}` — case workspace and linked records
- `POST /api/v1/cases/{case_id}/observations` — add analyst observation
- `GET /api/v1/cases/{case_id}/observations` — list observations
- `POST /api/v1/cases/{case_id}/timeline` — add timeline event
- `GET /api/v1/cases/{case_id}/timeline` — chronological timeline
- `POST /api/v1/evidence` — acquire evidence, calculate SHA-256
- `POST /api/v1/evidence/{id}/verify` — verify evidence integrity
- `POST /api/v1/evidence/{id}/analyze/logs` — offline log analysis
- `POST /api/v1/evidence/{id}/analyze/pcap` — offline PCAP analysis
- `GET /api/v1/evidence/{id}/analyses` — saved analysis results
- `GET /api/v1/audit` — audit events

## Important limitations
This is an investigative aid, not a validated forensic suite. It does not prove source authenticity or establish a legally sufficient chain of custody by itself. Store authorized evidence only, preserve originals, work from verified copies, document acquisition procedures, and independently validate findings. Keep the API bound to localhost; authentication, authorization, encryption at rest, backup/retention controls, and hardened deployment are still required before multi-user or network exposure.
