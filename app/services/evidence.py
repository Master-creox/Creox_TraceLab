import hashlib,json,uuid,os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from fastapi import UploadFile,HTTPException
from app.config import EVIDENCE_DIR,MAX_UPLOAD_MB,CHUNK_SIZE
from app.database import get_db,utc_now

def _fernet():
    key=os.getenv("TRACE_LAB_EVIDENCE_KEY", "")
    if not key: raise HTTPException(500,"TRACE_LAB_EVIDENCE_KEY is not configured")
    try: return Fernet(key.encode())
    except Exception: raise HTTPException(500,"TRACE_LAB_EVIDENCE_KEY is invalid")

def decrypt_evidence(rec):
    path=EVIDENCE_DIR/rec["stored_filename"]
    if not path.is_file(): raise HTTPException(409,"Evidence file missing")
    try: data=_fernet().decrypt(path.read_bytes())
    except InvalidToken: raise HTTPException(409,"Evidence decryption failed; check key or file integrity")
    if hashlib.sha256(data).hexdigest()!=rec["sha256"]: raise HTTPException(409,"Evidence integrity verification failed")
    return data

def append_audit(c,kind,eid,details):
    c.execute("INSERT INTO audit_events(event_type,evidence_id,timestamp,details_json) VALUES(?,?,?,?)",(kind,eid,utc_now(),json.dumps(details,sort_keys=True)))

async def acquire_evidence(file:UploadFile,case_id:str,description:str):
    if not file.filename or Path(file.filename).name in ("",".",".."): raise HTTPException(400,"Valid filename required")
    data=bytearray(); h=hashlib.sha256()
    try:
        while chunk:=await file.read(CHUNK_SIZE):
            data.extend(chunk)
            if len(data)>MAX_UPLOAD_MB*1024*1024: raise HTTPException(413,"Upload size limit exceeded")
            h.update(chunk)
        EVIDENCE_DIR.mkdir(parents=True,exist_ok=True); uid=str(uuid.uuid4()); stored=uid+".fernet"; path=EVIDENCE_DIR/stored
        path.write_bytes(_fernet().encrypt(bytes(data)))
        try:
            with get_db() as c:
                if not c.execute("SELECT 1 FROM cases WHERE case_id=?",(case_id,)).fetchone(): raise HTTPException(422,"Create case before uploading evidence")
                cur=c.execute("INSERT INTO evidence(evidence_uuid,case_id,original_filename,stored_filename,media_type,size_bytes,sha256,description,acquired_at,integrity_status) VALUES(?,?,?,?,?,?,?,?,?,'verified_at_acquisition')",(uid,case_id,Path(file.filename).name,stored,file.content_type,len(data),h.hexdigest(),description,utc_now()))
                eid=cur.lastrowid; append_audit(c,"evidence_acquired",eid,{"case_id":case_id,"sha256":h.hexdigest(),"size_bytes":len(data),"encrypted_at_rest":True})
                return dict(c.execute("SELECT * FROM evidence WHERE id=?",(eid,)).fetchone())
        except Exception:
            path.unlink(missing_ok=True); raise
    finally:
        data.clear(); await file.close()

def get_evidence(eid):
    with get_db() as c:
        r=c.execute("SELECT * FROM evidence WHERE id=?",(eid,)).fetchone()
        if r is None: raise HTTPException(404,"Evidence not found")
        return dict(r)
def evidence_path(rec): return EVIDENCE_DIR/rec["stored_filename"]
def list_evidence(cid=None):
    with get_db() as c:
        q=c.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC",(cid,)) if cid else c.execute("SELECT * FROM evidence ORDER BY id DESC")
        return [dict(r) for r in q]
def verify_evidence(eid):
    r=get_evidence(eid); checked=utc_now()
    try: decrypt_evidence(r); actual=r["sha256"]; match=True
    except HTTPException as e:
        actual="MISSING_OR_INVALID"; match=False
    status="intact" if match else "mismatch"
    with get_db() as c:
        c.execute("UPDATE evidence SET integrity_status=? WHERE id=?",(status,eid))
        append_audit(c,"integrity_check",eid,{"expected_sha256":r["sha256"],"actual_sha256":actual,"match":match,"status":status})
    return {"evidence_id":eid,"expected_sha256":r["sha256"],"actual_sha256":actual,"match":match,"checked_at":checked,"status":status}
def list_audit(limit=100):
    with get_db() as c: return [dict(r) for r in c.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",(min(max(limit,1),500),))]
