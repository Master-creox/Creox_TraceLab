from contextlib import asynccontextmanager
import hashlib, io
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from app.database import init_db, get_db
from app.schemas import *
from app.services.evidence import acquire_evidence,list_evidence,get_evidence,verify_evidence,list_audit,decrypt_evidence
from app.services.analysis import analyze_evidence,get_analyses
from app.services.cases import create_case,list_cases,update_case_status,add_observation,list_observations,add_timeline_event,list_timeline,get_case_workspace
from app.services.reports import build_report,list_reports,get_report
from app.security import current_user,admin_user,verify_password,create_token,hash_password,record_security_event

@asynccontextmanager
async def lifespan(app:FastAPI):
    init_db()
    yield

app=FastAPI(title="Creox TraceLab API",version="1.0.0",description="Unified local-first digital forensics investigation workbench with authenticated access and encrypted evidence storage.",lifespan=lifespan)

@app.get("/health")
def health(): return {"status":"ok","service":"Creox TraceLab","version":app.version}

@app.post("/api/v1/auth/login")
def login(form:OAuth2PasswordRequestForm=Depends()):
    with get_db() as c: user=c.execute("SELECT * FROM auth_users WHERE username=? AND is_active=1",(form.username,)).fetchone()
    if not user or not verify_password(form.password,user["password_hash"]): raise HTTPException(401,"Incorrect username or password")
    token=create_token(user["username"],user["role"]); record_security_event(user["username"],"auth.login","successful login")
    return {"access_token":token,"token_type":"bearer","role":user["role"],"username":user["username"]}

@app.get("/api/v1/security/me")
def security_me(user=Depends(current_user)): return {"username":user["username"],"role":user["role"],"active":bool(user["is_active"])}

@app.post("/api/v1/admin/users",status_code=201)
def admin_create_user(payload:dict,admin=Depends(admin_user)):
    username=str(payload.get("username","")).strip(); password=str(payload.get("password","")); role=str(payload.get("role","analyst"))
    if not username or len(username)>80 or role not in {"admin","analyst"}: raise HTTPException(400,"Provide a username and role admin or analyst")
    try: password_hash=hash_password(password)
    except ValueError as e: raise HTTPException(400,str(e))
    with get_db() as c:
        if c.execute("SELECT 1 FROM auth_users WHERE username=?",(username,)).fetchone(): raise HTTPException(409,"Username already exists")
        cur=c.execute("INSERT INTO auth_users(username,password_hash,role,created_at) VALUES(?,?,?,datetime('now'))",(username,password_hash,role))
        user_id=cur.lastrowid
    record_security_event(admin["username"],"user.created",f"username={username};role={role}")
    return {"id":user_id,"username":username,"role":role}

@app.post("/api/v1/cases",response_model=CaseOut,status_code=201)
def case_create(p:CaseCreate,user=Depends(current_user)):
    result=create_case(p); record_security_event(user["username"],"case.created",result["case_id"]); return result
@app.get("/api/v1/cases",response_model=list[CaseOut])
def case_list(user=Depends(current_user)): return list_cases()
@app.patch("/api/v1/cases/{case_id}",response_model=CaseOut)
def case_update(case_id:str,p:CaseStatusUpdate,user=Depends(current_user)):
    result=update_case_status(case_id,p.status); record_security_event(user["username"],"case.status_changed",f"{case_id}:{p.status}"); return result
@app.get("/api/v1/cases/{case_id}")
def case_get(case_id:str,user=Depends(current_user)): return get_case_workspace(case_id)
@app.post("/api/v1/cases/{case_id}/observations",status_code=201)
def observation_add(case_id:str,p:ObservationCreate,user=Depends(current_user)):
    result=add_observation(case_id,p); record_security_event(user["username"],"observation.created",case_id); return result
@app.get("/api/v1/cases/{case_id}/observations")
def observation_get(case_id:str,user=Depends(current_user)): return list_observations(case_id)
@app.post("/api/v1/cases/{case_id}/timeline",status_code=201)
def timeline_add(case_id:str,p:TimelineCreate,user=Depends(current_user)):
    result=add_timeline_event(case_id,p); record_security_event(user["username"],"timeline.created",case_id); return result
@app.get("/api/v1/cases/{case_id}/timeline")
def timeline_get(case_id:str,user=Depends(current_user)): return list_timeline(case_id)
@app.post("/api/v1/cases/{case_id}/reports")
def report_add(case_id:str,p:ReportCreate,user=Depends(current_user)):
    result=build_report(case_id,p.title,p.include_analysis); record_security_event(user["username"],"report.generated",case_id); return result
@app.get("/api/v1/cases/{case_id}/reports")
def report_list(case_id:str,user=Depends(current_user)): return list_reports(case_id)
@app.get("/api/v1/reports/{report_id}")
def report_get(report_id:int,user=Depends(current_user)): return get_report(report_id)
@app.get("/api/v1/reports/{report_id}/html",response_class=HTMLResponse)
def report_html(report_id:int,user=Depends(current_user)): return HTMLResponse(get_report(report_id)["html"])
@app.post("/api/v1/evidence",response_model=EvidenceOut,status_code=201)
async def evidence_add(file:UploadFile=File(...),case_id:str=Form(...,min_length=1,max_length=80),description:str=Form(default="",max_length=2000),user=Depends(current_user)):
    result=await acquire_evidence(file,case_id,description); record_security_event(user["username"],"evidence.acquired",f"id={result['id']};case={case_id};sha256={result['sha256']}"); return result
@app.get("/api/v1/evidence",response_model=list[EvidenceOut])
def evidence_list(case_id:str|None=Query(default=None,max_length=80),user=Depends(current_user)): return list_evidence(case_id)
@app.get("/api/v1/evidence/{evidence_id}",response_model=EvidenceOut)
def evidence_get(evidence_id:int,user=Depends(current_user)): return get_evidence(evidence_id)
@app.get("/api/v1/evidence/{evidence_id}/download")
def evidence_download(evidence_id:int,user=Depends(current_user)):
    rec=get_evidence(evidence_id); data=decrypt_evidence(rec)
    record_security_event(user["username"],"evidence.downloaded",f"id={evidence_id};sha256={rec['sha256']}")
    return StreamingResponse(io.BytesIO(data),media_type="application/octet-stream",headers={"Content-Disposition":f'attachment; filename="{rec["original_filename"]}"',"X-Evidence-SHA256":rec["sha256"]})
@app.post("/api/v1/evidence/{evidence_id}/verify",response_model=VerifyOut)
def evidence_verify(evidence_id:int,user=Depends(current_user)): return verify_evidence(evidence_id)
@app.post("/api/v1/evidence/{evidence_id}/analyze/pcap",response_model=AnalysisOut)
def pcap_analyze(evidence_id:int,user=Depends(current_user)): return analyze_evidence(evidence_id,"pcap")
@app.post("/api/v1/evidence/{evidence_id}/analyze/logs",response_model=AnalysisOut)
def logs_analyze(evidence_id:int,user=Depends(current_user)): return analyze_evidence(evidence_id,"logs")
@app.get("/api/v1/evidence/{evidence_id}/analyses",response_model=list[AnalysisOut])
def analysis_list(evidence_id:int,user=Depends(current_user)): return get_analyses(evidence_id)
@app.get("/api/v1/audit",response_model=list[AuditEventOut])
def audit_get(limit:int=Query(default=100,ge=1,le=500),admin=Depends(admin_user)): return list_audit(limit)
@app.get("/api/v1/security/audit")
def security_audit(admin=Depends(admin_user)):
    with get_db() as c: rows=[dict(r) for r in c.execute("SELECT * FROM security_audit ORDER BY id DESC LIMIT 500")]
    return rows
@app.get("/api/v1/security/audit/verify")
def security_audit_verify(admin=Depends(admin_user)):
    import hashlib
    with get_db() as c: rows=c.execute("SELECT * FROM security_audit ORDER BY id ASC").fetchall()
    previous="0"*64
    for row in rows:
        payload="|".join([row["actor"],row["action"],row["detail"],row["created_at"],previous])
        digest=hashlib.sha256(payload.encode()).hexdigest()
        if row["previous_hash"]!=previous or row["event_hash"]!=digest: return {"valid":False,"first_invalid_event_id":row["id"]}
        previous=digest
    return {"valid":True,"events_checked":len(rows),"first_invalid_event_id":None}
