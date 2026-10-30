import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from app.config import DATA_DIR, DB_PATH

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        conn.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_uuid TEXT NOT NULL UNIQUE,
            case_id TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL UNIQUE,
            media_type TEXT,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            acquired_at TEXT NOT NULL,
            integrity_status TEXT NOT NULL DEFAULT 'not_checked'
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            evidence_id INTEGER,
            timestamp TEXT NOT NULL,
            details_json TEXT NOT NULL,
            FOREIGN KEY(evidence_id) REFERENCES evidence(id)
        );
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            analysis_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            result_json TEXT NOT NULL,
            FOREIGN KEY(evidence_id) REFERENCES evidence(id)
        );
        """)
        conn.commit()

@contextmanager
def get_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
