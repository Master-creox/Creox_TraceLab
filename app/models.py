from dataclasses import dataclass

@dataclass(frozen=True)
class EvidenceRecord:
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
