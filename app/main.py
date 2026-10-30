from contextlib import asynccontextmanager
from fastapi import FastAPI,File,Form,UploadFile,Query,Depends,HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from app.database import init_db, get_db, utc_now
from app.services.auth import (create_access_token, get_current_user, hash_password,
                               require_admin, record_chain_event, verify_chain, verify_password)
from app.schemas import *
from app.services.evidence import acquire_evidence,list_evidence,get_evidence,verify_evidence,list_audit
from app.services.analysis import analyze_evidence,get_analyses
from app.services.cases import create_case,list_cases,update_case_status,add_observation,list_observations,add_timeline_event,list_timeline,get_case_workspace
from app.services.reports import build_report,list_reports,get_report
@asynccontextmanager
async def lifespan(app:FastAPI):
    init_db()
    yield
app=FastAPI(title="Creox TraceLab API",version="0.6.0-integrated",description="Local-first digital forensics investigation workbench. M1-M5 endpoints unchanged; M6 auth + hash-chained audit added on top.",lifespan=lifespan)
# --- M6 integration: auth + hash-chained audit (existing endpoints untouched) ---
@app.post("/api/v1/auth/login")
def auth_login(form: OAuth2PasswordRequestForm = Depends()):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=? AND is_active=1", (form.username,)).fetchone()
        if row is None or not verify_password(form.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        record_chain_event(form.username, "auth.login", "Successful login", conn=conn)
        return {"access_token": create_access_token(row["username"], row["role"]), "token_type": "bearer", "role": row["role"]}
@app.get("/api/v1/security/me")
def security_me(user: dict = Depends(get_current_user)):
    return {"username": user["username"], "role": user["role"], "active": bool(user["is_active"])}
@app.post("/api/v1/admin/users", status_code=201)
def admin_create_user(payload: dict, admin: dict = Depends(require_admin)):
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    role = str(payload.get("role", "analyst"))
    if not username or len(username) > 80 or role not in {"admin", "analyst"}:
        raise HTTPException(status_code=400, detail="Provide a username and role 'admin' or 'analyst'")
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    with get_db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        cursor = conn.execute("INSERT INTO users(username, password_hash, role, is_active, created_at) VALUES (?, ?, ?, 1, ?)",
                              (username, hash_password(password), role, utc_now()))
        record_chain_event(admin["username"], "user.created", f"username={username};role={role}", conn=conn)
        row = conn.execute("SELECT * FROM users WHERE id=?", (cursor.lastrowid,)).fetchone()
        return {"id": row["id"], "username": row["username"], "role": row["role"]}
@app.get("/api/v1/audit/chain")
def audit_chain(admin: dict = Depends(require_admin)):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_chain ORDER BY id DESC LIMIT 500").fetchall()]
@app.get("/api/v1/audit/chain/verify")
def audit_chain_verify(admin: dict = Depends(require_admin)):
    valid, failed_id = verify_chain()
    return {"valid": valid, "first_invalid_event_id": failed_id}
@app.get("/health")
def health(): return {"status":"ok","service":"Creox TraceLab","version":app.version}
@app.post("/api/v1/cases",response_model=CaseOut,status_code=201)
def case_create(p:CaseCreate): return create_case(p)
@app.get("/api/v1/cases",response_model=list[CaseOut])
def case_list(): return list_cases()
@app.patch("/api/v1/cases/{case_id}",response_model=CaseOut)
def case_update(case_id:str,p:CaseStatusUpdate): return update_case_status(case_id,p.status)
@app.get("/api/v1/cases/{case_id}")
def case_get(case_id:str): return get_case_workspace(case_id)
@app.post("/api/v1/cases/{case_id}/observations",status_code=201)
def observation_add(case_id:str,p:ObservationCreate): return add_observation(case_id,p)
@app.get("/api/v1/cases/{case_id}/observations")
def observation_get(case_id:str): return list_observations(case_id)
@app.post("/api/v1/cases/{case_id}/timeline",status_code=201)
def timeline_add(case_id:str,p:TimelineCreate): return add_timeline_event(case_id,p)
@app.get("/api/v1/cases/{case_id}/timeline")
def timeline_get(case_id:str): return list_timeline(case_id)
@app.post("/api/v1/cases/{case_id}/reports")
def report_add(case_id:str,p:ReportCreate): return build_report(case_id,p.title,p.include_analysis)
@app.get("/api/v1/cases/{case_id}/reports")
def report_list(case_id:str): return list_reports(case_id)
@app.get("/api/v1/reports/{report_id}")
def report_get(report_id:int): return get_report(report_id)
@app.get("/api/v1/reports/{report_id}/html",response_class=HTMLResponse)
def report_html(report_id:int): return HTMLResponse(get_report(report_id)["html"])
@app.post("/api/v1/evidence",response_model=EvidenceOut,status_code=201)
async def evidence_add(file:UploadFile=File(...),case_id:str=Form(...,min_length=1,max_length=80),description:str=Form(default="",max_length=2000)):
    return await acquire_evidence(file,case_id,description)
@app.get("/api/v1/evidence",response_model=list[EvidenceOut])
def evidence_list(case_id:str|None=Query(default=None,max_length=80)): return list_evidence(case_id)
@app.get("/api/v1/evidence/{evidence_id}",response_model=EvidenceOut)
def evidence_get(evidence_id:int): return get_evidence(evidence_id)
@app.post("/api/v1/evidence/{evidence_id}/verify",response_model=VerifyOut)
def evidence_verify(evidence_id:int): return verify_evidence(evidence_id)
@app.post("/api/v1/evidence/{evidence_id}/analyze/pcap",response_model=AnalysisOut)
def pcap_analyze(evidence_id:int): return analyze_evidence(evidence_id,"pcap")
@app.post("/api/v1/evidence/{evidence_id}/analyze/logs",response_model=AnalysisOut)
def logs_analyze(evidence_id:int): return analyze_evidence(evidence_id,"logs")
@app.get("/api/v1/evidence/{evidence_id}/analyses",response_model=list[AnalysisOut])
def analysis_list(evidence_id:int): return get_analyses(evidence_id)
@app.get("/api/v1/audit",response_model=list[AuditEventOut])
def audit_get(limit:int=Query(default=100,ge=1,le=500)): return list_audit(limit)
