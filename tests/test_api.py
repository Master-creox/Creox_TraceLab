import hashlib
import os
from pathlib import Path
from fastapi.testclient import TestClient

def test_health_and_evidence_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_LAB_DATA_DIR", str(tmp_path))
    # Reload modules so their path constants use the temporary test directory.
    import app.config as config
    import app.database as database
    import app.services.evidence as evidence_service
    config.DATA_DIR = tmp_path
    config.EVIDENCE_DIR = tmp_path / "evidence"
    config.DB_PATH = tmp_path / "tracelab.sqlite3"
    database.DATA_DIR = config.DATA_DIR
    database.DB_PATH = config.DB_PATH
    evidence_service.EVIDENCE_DIR = config.EVIDENCE_DIR

    from app.main import app
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "ok"
        payload = b"Example forensic log line\n"
        response = client.post(
            "/api/v1/evidence",
            files={"file": ("sample.log", payload, "text/plain")},
            data={"case_id": "CASE-TEST", "description": "test artifact"},
        )
        assert response.status_code == 201, response.text
        record = response.json()
        assert record["sha256"] == hashlib.sha256(payload).hexdigest()
        assert record["size_bytes"] == len(payload)

        listed = client.get("/api/v1/evidence", params={"case_id": "CASE-TEST"})
        assert listed.status_code == 200
        assert len(listed.json()) == 1

        verified = client.post(f"/api/v1/evidence/{record['id']}/verify")
        assert verified.status_code == 200
        assert verified.json()["match"] is True
        assert verified.json()["status"] == "intact"

        audit = client.get("/api/v1/audit")
        assert audit.status_code == 200
        assert [x["event_type"] for x in audit.json()] == ["integrity_check", "evidence_acquired"]

def test_integrity_mismatch_is_detected(tmp_path, monkeypatch):
    import app.config as config
    import app.database as database
    import app.services.evidence as evidence_service
    config.DATA_DIR = tmp_path
    config.EVIDENCE_DIR = tmp_path / "evidence"
    config.DB_PATH = tmp_path / "tracelab.sqlite3"
    database.DATA_DIR = config.DATA_DIR
    database.DB_PATH = config.DB_PATH
    evidence_service.EVIDENCE_DIR = config.EVIDENCE_DIR

    from app.main import app
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/evidence",
            files={"file": ("sample.bin", b"original", "application/octet-stream")},
            data={"case_id": "CASE-2"},
        )
        record = response.json()
        stored = config.EVIDENCE_DIR / f"{record['evidence_uuid']}.bin"
        stored.write_bytes(b"modified")
        checked = client.post(f"/api/v1/evidence/{record['id']}/verify")
        assert checked.status_code == 200
        assert checked.json()["match"] is False
        assert checked.json()["status"] == "mismatch"
