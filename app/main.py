from contextlib import asynccontextmanager
from fastapi import FastAPI, File, Form, UploadFile, Query, HTTPException
from app.database import init_db
from app.schemas import EvidenceOut, VerifyOut, AuditEventOut, AnalysisOut
from app.services.evidence import acquire_evidence, list_evidence, get_evidence, verify_evidence, list_audit
from app.services.analysis import analyze_evidence, get_analyses

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Creox TraceLab API", version="0.2.0",
              description="Local-first evidence acquisition, integrity verification and offline artifact analysis.",
              lifespan=lifespan)

@app.get("/health")
def health():
    return {"status": "ok", "service": "Creox TraceLab", "version": app.version}

@app.post("/api/v1/evidence", response_model=EvidenceOut, status_code=201)
async def upload_evidence(file: UploadFile = File(...),
                          case_id: str = Form(..., min_length=1, max_length=100),
                          description: str = Form(default="", max_length=2000)):
    return await acquire_evidence(file, case_id, description)

@app.get("/api/v1/evidence", response_model=list[EvidenceOut])
def get_evidence_list(case_id: str | None = Query(default=None, max_length=100)):
    return list_evidence(case_id)

@app.get("/api/v1/evidence/{evidence_id}", response_model=EvidenceOut)
def evidence_detail(evidence_id: int):
    return get_evidence(evidence_id)

@app.post("/api/v1/evidence/{evidence_id}/verify", response_model=VerifyOut)
def evidence_verify(evidence_id: int):
    return verify_evidence(evidence_id)

@app.post("/api/v1/evidence/{evidence_id}/analyze/pcap", response_model=AnalysisOut)
def analyze_pcap_evidence(evidence_id: int):
    return analyze_evidence(evidence_id, "pcap")

@app.post("/api/v1/evidence/{evidence_id}/analyze/logs", response_model=AnalysisOut)
def analyze_log_evidence(evidence_id: int):
    return analyze_evidence(evidence_id, "logs")

@app.get("/api/v1/evidence/{evidence_id}/analyses", response_model=list[AnalysisOut])
def evidence_analyses(evidence_id: int):
    return get_analyses(evidence_id)

@app.get("/api/v1/audit", response_model=list[AuditEventOut])
def audit_events(limit: int = Query(default=100, ge=1, le=500)):
    return list_audit(limit)
