from pydantic import BaseModel, Field, ConfigDict

class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    evidence_uuid: str
    case_id: str
    original_filename: str
    media_type: str | None
    size_bytes: int
    sha256: str
    description: str
    acquired_at: str
    integrity_status: str

class VerifyOut(BaseModel):
    evidence_id: int
    expected_sha256: str
    actual_sha256: str
    match: bool
    checked_at: str
    status: str

class AuditEventOut(BaseModel):
    id: int
    event_type: str
    evidence_id: int | None
    timestamp: str
    details_json: str
