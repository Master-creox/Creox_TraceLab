# Creox TraceLab — Milestone 4: Forensic Report Generator

Milestone 4 adds reproducible case reports to TraceLab. It retains the evidence vault, offline PCAP/log analysis, case workspace, observations, and timeline from earlier milestones.

## Features
- Generate a point-in-time JSON report for a case.
- Generate a self-contained HTML report for review and printing to PDF from a browser.
- Include case metadata, evidence inventory, SHA-256 digests, latest integrity status, analysis summaries, analyst observations, and UTC timeline.
- Include a SHA-256 manifest for the canonical JSON report payload.
- Store report metadata and report payload snapshots in SQLite.
- Record report generation in the audit log.
- Retrieve previously generated report snapshots by report ID.

## Run
Python 3.11+:
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Linux/macOS activation: `source .venv/bin/activate`

Open http://127.0.0.1:8000/docs

## Generate a report
`POST /api/v1/cases/{case_id}/reports`

Example:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/cases/CASE-001/reports \
  -H "Content-Type: application/json" \
  -d '{"title":"CASE-001 Investigation Report","include_analysis":true}'
```

The response includes a report ID, JSON payload, SHA-256 digest, and HTML report. Save the HTML as a `.html` file and open it in a browser; use Print → Save as PDF to create a PDF copy.

Retrieve a stored snapshot:
`GET /api/v1/reports/{report_id}`

List case reports:
`GET /api/v1/cases/{case_id}/reports`

## Report integrity
The report digest is SHA-256 over canonical JSON (`sort_keys=True`, compact separators, UTF-8). The digest detects later changes to the payload when recomputed. It does not certify the truth of findings, prove source authenticity, or create a legally sufficient chain of custody by itself.

## Important limitations
This is an investigative aid, not a validated forensic suite. Reports are snapshots at generation time; generate a new report after adding or changing case material. This implementation stores report payloads in SQLite. Authentication, authorization, access controls, encrypted storage, backup/retention policy, signed reports, and hardened deployment remain necessary before multi-user or public-network use. Work only with evidence you are authorized to examine.
