import hashlib
import json
import uuid
from pathlib import Path
from fastapi import UploadFile, HTTPException
from app.config import EVIDENCE_DIR, MAX_UPLOAD_MB, CHUNK_SIZE
from app.database import get_db, utc_now

def append_audit(conn, event_type: str, evidence_id: int | None, details: dict) -> None:
    conn.execute(
        "INSERT INTO audit_events(event_type, evidence_id, timestamp, details_json) VALUES (?, ?, ?, ?)",
        (event_type, evidence_id, utc_now(), json.dumps(details, sort_keys=True))
    )

async def acquire_evidence(file: UploadFile, case_id: str, description: str) -> dict:
    if not case_id.strip():
        raise HTTPException(status_code=422, detail="case_id must not be empty")
    if not file.filename or Path(file.filename).name in ("", ".", ".."):
        raise HTTPException(status_code=400, detail="A valid filename is required")
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    evidence_uuid = str(uuid.uuid4())
    stored_filename = f"{evidence_uuid}.bin"
    target = EVIDENCE_DIR / stored_filename
    digest = hashlib.sha256()
    total = 0
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    try:
        with target.open("xb") as output:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(status_code=413, detail=f"Upload exceeds {MAX_UPLOAD_MB} MiB limit")
                digest.update(chunk)
                output.write(chunk)
        acquired_at = utc_now()
        sha256 = digest.hexdigest()
        with get_db() as conn:
            cursor = conn.execute(
                """INSERT INTO evidence
                (evidence_uuid, case_id, original_filename, stored_filename, media_type,
                 size_bytes, sha256, description, acquired_at, integrity_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified_at_acquisition')""",
                (evidence_uuid, case_id.strip(), Path(file.filename).name, stored_filename,
                 file.content_type, total, sha256, description.strip(), acquired_at)
            )
            evidence_id = cursor.lastrowid
            append_audit(conn, "evidence_acquired", evidence_id, {
                "case_id": case_id.strip(), "sha256": sha256, "size_bytes": total,
                "filename": Path(file.filename).name
            })
            row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
            return dict(row)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

def list_evidence(case_id: str | None = None) -> list[dict]:
    with get_db() as conn:
        if case_id:
            rows = conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]

def get_evidence(evidence_id: int) -> dict:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Evidence not found")
        return dict(row)

def evidence_path(record: dict) -> Path:
    return EVIDENCE_DIR / record["stored_filename"]

def verify_evidence(evidence_id: int) -> dict:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Evidence not found")
        target = EVIDENCE_DIR / row["stored_filename"]
        checked_at = utc_now()
        if not target.is_file():
            actual, match = "MISSING", False
        else:
            digest = hashlib.sha256()
            with target.open("rb") as source:
                for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
                    digest.update(chunk)
            actual = digest.hexdigest()
            match = actual == row["sha256"]
        status = "intact" if match else ("missing" if actual == "MISSING" else "mismatch")
        conn.execute("UPDATE evidence SET integrity_status=? WHERE id=?", (status, evidence_id))
        append_audit(conn, "integrity_check", evidence_id, {
            "expected_sha256": row["sha256"], "actual_sha256": actual,
            "match": match, "status": status
        })
        return {"evidence_id": evidence_id, "expected_sha256": row["sha256"],
                "actual_sha256": actual, "match": match, "checked_at": checked_at, "status": status}

def list_audit(limit: int = 100) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",
                            (min(max(limit, 1), 500),)).fetchall()
        return [dict(row) for row in rows]
