# Creox TraceLab

A local-first digital forensics workbench for evidence acquisition, SHA-256 integrity verification, audit events, and repeatable investigations.

## Milestone 1: Evidence Vault API

### Features
- Register evidence by uploading a file.
- Stream file contents to disk while calculating SHA-256 and byte size.
- Store evidence metadata in SQLite.
- Append audit events for acquisition and verification.
- Verify an evidence file against its recorded digest.
- List evidence and retrieve its metadata.
- Local operation; no external AI or cloud service required.

> **Forensic note:** This prototype records acquisition metadata and hashes, but does not by itself establish legal chain of custody, prove the original source was authentic, or replace a validated forensic acquisition process. Use copies of evidence, document handling procedures, and restrict access to the evidence directory.

## Requirements
- Python 3.11+
- Windows, Linux, or macOS

## Run locally

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs for interactive API documentation.

## API quick start

Upload a file:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/evidence" \
  -F "file=@sample.log" \
  -F "case_id=CASE-001" \
  -F "description=Sample system log"
```

List evidence:
```bash
curl "http://127.0.0.1:8000/api/v1/evidence"
```

Verify integrity:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/evidence/1/verify"
```

Fetch audit events:
```bash
curl "http://127.0.0.1:8000/api/v1/audit"
```

## Configuration
Environment variables:
- `TRACE_LAB_DATA_DIR`: data directory (default `./data`)
- `TRACE_LAB_MAX_UPLOAD_MB`: maximum upload size in MiB (default `100`)

## Project structure

```text
creox-tracelab/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   └── services/
│       ├── __init__.py
│       └── evidence.py
├── tests/
│   └── test_api.py
├── .gitignore
├── requirements.txt
└── README.md
```

## Milestones
1. **Evidence Vault API** — upload, hash, metadata, verification, audit log. (Included)
2. **Artifact Analysis** — offline PCAP metadata and log parsers with fixture-based tests.
3. **Case Timeline** — case records, observations, timestamp normalization, evidence relationships.
4. **Reporting** — JSON and HTML reports, integrity manifest, clear fact/inference labels.
5. **Dashboard & hardening** — React dashboard, authentication, role permissions, retention controls, backups, packaging, CI.

## Safety and security
- Run on localhost until authentication and authorization are added.
- Do not expose the API to the public internet as-is.
- Evidence is potentially sensitive. Use authorized evidence only and protect backups.
- Uploaded files are stored under generated IDs, not user-supplied filenames.
- This first milestone accepts files as evidence but does not execute or open them.
