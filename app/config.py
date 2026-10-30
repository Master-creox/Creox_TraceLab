import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("TRACE_LAB_DATA_DIR", str(BASE_DIR / "data"))).resolve()
EVIDENCE_DIR = DATA_DIR / "evidence"
DB_PATH = DATA_DIR / "tracelab.sqlite3"
MAX_UPLOAD_MB = max(1, int(os.getenv("TRACE_LAB_MAX_UPLOAD_MB", "100")))
CHUNK_SIZE = 1024 * 1024
