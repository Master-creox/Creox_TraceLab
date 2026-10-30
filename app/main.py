from contextlib import asynccontextmanager
from fastapi import FastAPI, File, Form, UploadFile, Query
from app.database import init_db
from app.schemas import *
from app.services.evidence import acquire_evidence,list_evidence,get_evidence,verify_evidence,list_audit
from app.services.analysis import analyze_evidence,get_analyses
from app.services.cases import (create_case,list_cases,update_case_status,add_observation,
    list_observations,add_timeline_event,list_timeline,get_case_workspace)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app=FastAPI(title="Creox TraceLab API",version="0.3.0",
            description="Local-first digital forensics evidence, offline analysis and case investigation.",lifespan=lifespan)

@app.get("/health")
def health(): return {"status":"ok","service":"Creox TraceLab","version":app.version}

@app.post("/api/v1/cases",response_model=CaseOut,status_code=201)
def case_create(payload:CaseCreate): return create_case(payload)

@app.get("/api/v1/cases",response_model=list[CaseOut])
def case_list(): return list_cases()

@app.patch("/api/v1/cases/{case_id}",response_model=CaseOut)
def case_status(case_id:str,payload:CaseStatusUpdate): return update_case_status(case_id,payload.status)

@app.get("/api/v1/cases/{case_id}")
def case_workspace(case_id:str): return get_case_workspace(case_id)

@app.post("/api/v1/cases/{case_id}/observations",status_code=201)
def observation_create(case_id:str,payload:ObservationCreate): return add_observation(case_id,payload)

@app.get("/api/v1/cases/{case_id}/observations")
def observation_list(case_id:str): return list_observations(case_id)

@app.post("/api/v1/cases/{case_id}/timeline",status_code=201)
def timeline_create(case_id:str,payload:TimelineCreate): return add_timeline_event(case_id,payload)

@app.get("/api/v1/cases/{case_id}/timeline")
def timeline_list(case_id:str): return list_timeline(case_id)

@app.post("/api/v1/evidence",response_model=EvidenceOut,status_code=201)
async def upload_evidence(file:UploadFile=File(...),case_id:str=Form(...,min_length=1,max_length=80),
                          description:str=Form(default="",max_length=2000)):
    return await acquire_evidence(file,case_id,description)

@app.get("/api/v1/evidence",response_model=list[EvidenceOut])
def evidence_list(case_id:str|None=Query(default=None,max_length=80)): return list_evidence(case_id)

@app.get("/api/v1/evidence/{evidence_id}",response_model=EvidenceOut)
def evidence_detail(evidence_id:int): return get_evidence(evidence_id)

@app.post("/api/v1/evidence/{evidence_id}/verify",response_model=VerifyOut)
def evidence_verify(evidence_id:int): return verify_evidence(evidence_id)

@app.post("/api/v1/evidence/{evidence_id}/analyze/pcap",response_model=AnalysisOut)
def pcap_analyze(evidence_id:int): return analyze_evidence(evidence_id,"pcap")

@app.post("/api/v1/evidence/{evidence_id}/analyze/logs",response_model=AnalysisOut)
def logs_analyze(evidence_id:int): return analyze_evidence(evidence_id,"logs")

@app.get("/api/v1/evidence/{evidence_id}/analyses",response_model=list[AnalysisOut])
def evidence_analyses(evidence_id:int): return get_analyses(evidence_id)

@app.get("/api/v1/audit",response_model=list[AuditEventOut])
def audit_events(limit:int=Query(default=100,ge=1,le=500)): return list_audit(limit)
