import sqlite3
from contextlib import contextmanager
from app.config import DATA_DIR,DB_PATH

def utc_now():
    from datetime import datetime,timezone
    return datetime.now(timezone.utc).isoformat()

def init_db():
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases(case_id TEXT PRIMARY KEY,title TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',priority TEXT NOT NULL DEFAULT 'medium',status TEXT NOT NULL DEFAULT 'open',created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY AUTOINCREMENT,evidence_uuid TEXT NOT NULL UNIQUE,case_id TEXT NOT NULL,original_filename TEXT NOT NULL,stored_filename TEXT NOT NULL UNIQUE,media_type TEXT,size_bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',acquired_at TEXT NOT NULL,integrity_status TEXT NOT NULL DEFAULT 'not_checked',FOREIGN KEY(case_id) REFERENCES cases(case_id));
        CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,event_type TEXT NOT NULL,evidence_id INTEGER,timestamp TEXT NOT NULL,details_json TEXT NOT NULL,FOREIGN KEY(evidence_id) REFERENCES evidence(id));
        CREATE TABLE IF NOT EXISTS analysis_results(id INTEGER PRIMARY KEY AUTOINCREMENT,evidence_id INTEGER NOT NULL,analysis_type TEXT NOT NULL,created_at TEXT NOT NULL,result_json TEXT NOT NULL,FOREIGN KEY(evidence_id) REFERENCES evidence(id));
        CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL,evidence_id INTEGER,title TEXT NOT NULL,content TEXT NOT NULL,classification TEXT NOT NULL DEFAULT 'observation',created_at TEXT NOT NULL,FOREIGN KEY(case_id) REFERENCES cases(case_id),FOREIGN KEY(evidence_id) REFERENCES evidence(id));
        CREATE TABLE IF NOT EXISTS timeline_events(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL,evidence_id INTEGER,title TEXT NOT NULL,details TEXT NOT NULL DEFAULT '',event_type TEXT NOT NULL DEFAULT 'analyst_event',source_time TEXT NOT NULL,event_time_utc TEXT NOT NULL,timezone_assumed_utc INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,FOREIGN KEY(case_id) REFERENCES cases(case_id),FOREIGN KEY(evidence_id) REFERENCES evidence(id));
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,report_uuid TEXT NOT NULL UNIQUE,case_id TEXT NOT NULL,title TEXT NOT NULL,created_at TEXT NOT NULL,payload_json TEXT NOT NULL,payload_sha256 TEXT NOT NULL,FOREIGN KEY(case_id) REFERENCES cases(case_id));
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst', is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_chain(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL);
        """)
        conn.commit()

@contextmanager
def get_db():
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    conn=sqlite3.connect(DB_PATH); conn.row_factory=sqlite3.Row; conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn; conn.commit()
    finally: conn.close()
