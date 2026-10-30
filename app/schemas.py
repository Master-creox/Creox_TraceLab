from pydantic import BaseModel, Field, ConfigDict
from typing import Literal

class CaseCreate(BaseModel):
    case_id: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=4000)
    priority: Literal["low","medium","high","critical"] = "medium"
class CaseStatusUpdate(BaseModel):
    status: Literal["open","in_progress","closed"]
class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    case_id: str; title: str; description: str; priority: str; status: str; created_at: str; updated_at: str
class ObservationCreate(BaseModel):
    title: str = Field(min_length=3,max_length=200)
    content: str = Field(min_length=1,max_length=10000)
    classification: Literal["observation","hypothesis","conclusion"] = "observation"
    evidence_id: int | None = None
class TimelineCreate(BaseModel):
    title: str = Field(min_length=3,max_length=200)
    details: str = Field(default="",max_length=5000)
    event_time: str = Field(min_length=10,max_length=80)
    event_type: str = Field(default="analyst_event",max_length=80)
    evidence_id: int | None = None
class ReportCreate(BaseModel):
    title: str = Field(min_length=3,max_length=200)
    include_analysis: bool = True
class EvidenceOut(BaseModel):
    id: int; evidence_uuid: str; case_id: str; original_filename: str; media_type: str | None
    size_bytes: int; sha256: str; description: str; acquired_at: str; integrity_status: str
class VerifyOut(BaseModel):
    evidence_id: int; expected_sha256: str; actual_sha256: str; match: bool; checked_at: str; status: str
class AuditEventOut(BaseModel):
    id: int; event_type: str; evidence_id: int | None; timestamp: str; details_json: str
class AnalysisOut(BaseModel):
    id: int; evidence_id: int; analysis_type: str; created_at: str; result: dict
