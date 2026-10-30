# Creox TraceLab — Milestone 2

Local-first digital forensics workbench. This release includes Milestone 1 (Evidence Vault) plus Milestone 2 (offline PCAP and log analysis).

## What's new in Milestone 2
- Analyze previously acquired PCAP/PCAPNG evidence offline using Scapy.
- Extract packet counts, protocol distribution, endpoint pairs, DNS queries, TCP conversations, and capture time range.
- Parse common syslog-style, ISO timestamped, and Apache/Nginx access logs.
- Normalize timestamps to UTC where timezone information is available; naive timestamps are explicitly treated as UTC for consistency and flagged in the output.
- Produce deterministic JSON analysis results linked to evidence IDs.
- Record analysis actions in the audit log.
- No live packet capture, scanning, or external network connections.

## Requirements
- Python 3.11+
- Windows, Linux, or macOS

## Install and run
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Linux/macOS activation: `source .venv/bin/activate`

Open `http://127.0.0.1:8000/docs`.

## Workflow
1. Upload a PCAP or log file to `POST /api/v1/evidence`.
2. Analyze PCAP evidence: `POST /api/v1/evidence/{id}/analyze/pcap`.
3. Analyze log evidence: `POST /api/v1/evidence/{id}/analyze/logs`.
4. Retrieve saved analysis: `GET /api/v1/evidence/{id}/analyses`.
5. Verify file integrity: `POST /api/v1/evidence/{id}/verify`.

The analysis endpoints read only from the evidence vault; they do not modify original evidence.

## Supported log formats
- ISO-8601 timestamps followed by optional level and message.
- Syslog: `Jan  2 15:04:05 hostname process[123]: message` (year is not present; current UTC year is used and noted).
- Apache/Nginx combined/common access log lines.
- Unrecognized lines are retained as unparsed records with line numbers, not silently discarded.

## PCAP details
PCAP parsing uses Scapy's offline reader. It does not transmit packets or perform live capture. Packet payloads are not exported. The report contains metadata and selected protocol fields only. Malformed or unsupported capture files return a clear client error.

## API quick start
Upload evidence:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/evidence -F "file=@sample.pcap" -F "case_id=CASE-001"
```
Analyze:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/evidence/1/analyze/pcap
curl -X POST http://127.0.0.1:8000/api/v1/evidence/2/analyze/logs
```
List analyses:
```bash
curl http://127.0.0.1:8000/api/v1/evidence/1/analyses
```

## Tests
```bash
pytest -q
```

## Important limitations
This is an investigative aid, not a validated forensic suite. It does not prove source authenticity, preserve a legally sufficient chain of custody by itself, decrypt TLS, reconstruct complete sessions, or identify an attacker. Validate findings against original evidence and document analyst actions. Keep the service bound to localhost until authentication, authorization, upload hardening, and deployment security are implemented.
