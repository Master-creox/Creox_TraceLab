import json
from fastapi import HTTPException
from app.database import get_db, utc_now
from app.services.evidence import get_evidence, evidence_path, append_audit
from app.services.log_analyzer import analyze_log_bytes
from app.services.pcap_analyzer import analyze_pcap

def save_analysis(evidence_id: int, analysis_type: str, result: dict) -> dict:
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO analysis_results(evidence_id, analysis_type, created_at, result_json) VALUES (?, ?, ?, ?)",
            (evidence_id, analysis_type, utc_now(), json.dumps(result, sort_keys=True))
        )
        append_audit(conn, f"{analysis_type}_analysis_completed", evidence_id,
                     {"analysis_id": cursor.lastrowid, "parser": result.get("parser")})
        row = conn.execute("SELECT * FROM analysis_results WHERE id=?", (cursor.lastrowid,)).fetchone()
        return {"id": row["id"], "evidence_id": row["evidence_id"],
                "analysis_type": row["analysis_type"], "created_at": row["created_at"],
                "result": json.loads(row["result_json"])}

def analyze_evidence(evidence_id: int, kind: str) -> dict:
    record = get_evidence(evidence_id)
    path = evidence_path(record)
    if not path.is_file():
        raise HTTPException(status_code=409, detail="Evidence file is missing from storage")
    if kind == "pcap":
        try:
            result = analyze_pcap(path)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif kind == "logs":
        result = analyze_log_bytes(path.read_bytes())
    else:
        raise HTTPException(status_code=400, detail="Unsupported analysis type")
    return save_analysis(evidence_id, kind, result)

def get_analyses(evidence_id: int) -> list[dict]:
    get_evidence(evidence_id)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM analysis_results WHERE evidence_id=? ORDER BY id DESC",
                            (evidence_id,)).fetchall()
        return [{"id": r["id"], "evidence_id": r["evidence_id"],
                 "analysis_type": r["analysis_type"], "created_at": r["created_at"],
                 "result": json.loads(r["result_json"])} for r in rows]
