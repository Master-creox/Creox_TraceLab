import hashlib,json,uuid
from pathlib import Path
from fastapi import UploadFile,HTTPException
from app.config import EVIDENCE_DIR,MAX_UPLOAD_MB,CHUNK_SIZE
from app.database import get_db,utc_now
def append_audit(conn,event_type,evidence_id,details):
    conn.execute("INSERT INTO audit_events(event_type,evidence_id,timestamp,details_json) VALUES(?,?,?,?)",
                 (event_type,evidence_id,utc_now(),json.dumps(details,sort_keys=True)))
async def acquire_evidence(file:UploadFile,case_id:str,description:str):
    if not case_id.strip(): raise HTTPException(422,"case_id must not be empty")
    if not file.filename or Path(file.filename).name in ("",".",".."): raise HTTPException(400,"Valid filename required")
    EVIDENCE_DIR.mkdir(parents=True,exist_ok=True); uid=str(uuid.uuid4()); stored=f"{uid}.bin"; target=EVIDENCE_DIR/stored
    digest=hashlib.sha256(); total=0
    try:
        with target.open("xb") as out:
            while chunk:=await file.read(CHUNK_SIZE):
                total+=len(chunk)
                if total>MAX_UPLOAD_MB*1024*1024: raise HTTPException(413,f"Upload exceeds {MAX_UPLOAD_MB} MiB")
                digest.update(chunk); out.write(chunk)
        now=utc_now(); sha=digest.hexdigest()
        with get_db() as conn:
            if not conn.execute("SELECT 1 FROM cases WHERE case_id=?",(case_id.strip(),)).fetchone():
                raise HTTPException(422,"Create the case before uploading evidence")
            cur=conn.execute("""INSERT INTO evidence(evidence_uuid,case_id,original_filename,stored_filename,media_type,size_bytes,sha256,description,acquired_at,integrity_status)
                                VALUES(?,?,?,?,?,?,?,?,?,'verified_at_acquisition')""",
                             (uid,case_id.strip(),Path(file.filename).name,stored,file.content_type,total,sha,description.strip(),now))
            eid=cur.lastrowid; append_audit(conn,"evidence_acquired",eid,{"case_id":case_id.strip(),"sha256":sha,"size_bytes":total})
            return dict(conn.execute("SELECT * FROM evidence WHERE id=?",(eid,)).fetchone())
    except Exception:
        target.unlink(missing_ok=True); raise
    finally: await file.close()
def get_evidence(eid):
    with get_db() as conn:
        row=conn.execute("SELECT * FROM evidence WHERE id=?",(eid,)).fetchone()
        if row is None: raise HTTPException(404,"Evidence not found")
        return dict(row)
def evidence_path(record): return EVIDENCE_DIR/record["stored_filename"]
def list_evidence(case_id=None):
    with get_db() as conn:
        if case_id: rows=conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC",(case_id,))
        else: rows=conn.execute("SELECT * FROM evidence ORDER BY id DESC")
        return [dict(r) for r in rows]
def verify_evidence(eid):
    record=get_evidence(eid); path=evidence_path(record); checked=utc_now()
    if not path.is_file(): actual,match="MISSING",False
    else:
        h=hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda:f.read(CHUNK_SIZE),b""): h.update(chunk)
        actual=h.hexdigest(); match=actual==record["sha256"]
    status="intact" if match else ("missing" if actual=="MISSING" else "mismatch")
    with get_db() as conn:
        conn.execute("UPDATE evidence SET integrity_status=? WHERE id=?",(status,eid))
        append_audit(conn,"integrity_check",eid,{"expected_sha256":record["sha256"],"actual_sha256":actual,"match":match,"status":status})
    return {"evidence_id":eid,"expected_sha256":record["sha256"],"actual_sha256":actual,"match":match,"checked_at":checked,"status":status}
def list_audit(limit=100):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",(min(max(limit,1),500),))]
