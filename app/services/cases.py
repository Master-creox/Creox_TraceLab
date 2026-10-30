import json
from datetime import datetime, timezone
from fastapi import HTTPException
from app.database import get_db, utc_now

def _case_or_404(conn, case_id):
    row=conn.execute("SELECT * FROM cases WHERE case_id=?",(case_id,)).fetchone()
    if row is None: raise HTTPException(404,"Case not found")
    return dict(row)
def create_case(payload):
    now=utc_now()
    with get_db() as conn:
        try:
            conn.execute("INSERT INTO cases VALUES(?,?,?,?,?,?,?)",
                         (payload.case_id,payload.title,payload.description,payload.priority,"open",now,now))
        except Exception as exc:
            if "UNIQUE" in str(exc): raise HTTPException(409,"A case with this case_id already exists")
            raise
        conn.execute("INSERT INTO audit_events(event_type,timestamp,details_json) VALUES(?,?,?)",
                     ("case_created",now,json.dumps({"case_id":payload.case_id,"title":payload.title})))
        return _case_or_404(conn,payload.case_id)
def list_cases():
    with get_db() as conn: return [dict(r) for r in conn.execute("SELECT * FROM cases ORDER BY created_at DESC")]
def update_case_status(case_id,status):
    with get_db() as conn:
        _case_or_404(conn,case_id); now=utc_now()
        conn.execute("UPDATE cases SET status=?,updated_at=? WHERE case_id=?",(status,now,case_id))
        conn.execute("INSERT INTO audit_events(event_type,timestamp,details_json) VALUES(?,?,?)",
                     ("case_status_changed",now,json.dumps({"case_id":case_id,"status":status})))
        return _case_or_404(conn,case_id)
def _validate_evidence_case(conn,case_id,eid):
    if eid is not None:
        row=conn.execute("SELECT case_id FROM evidence WHERE id=?",(eid,)).fetchone()
        if row is None or row["case_id"]!=case_id: raise HTTPException(422,"Evidence must exist and belong to this case")
def add_observation(case_id,payload):
    with get_db() as conn:
        _case_or_404(conn,case_id); _validate_evidence_case(conn,case_id,payload.evidence_id); now=utc_now()
        cur=conn.execute("INSERT INTO observations(case_id,evidence_id,title,content,classification,created_at) VALUES(?,?,?,?,?,?)",
                         (case_id,payload.evidence_id,payload.title,payload.content,payload.classification,now))
        conn.execute("INSERT INTO audit_events(event_type,timestamp,details_json) VALUES(?,?,?)",
                     ("observation_added",now,json.dumps({"case_id":case_id,"observation_id":cur.lastrowid})))
        return dict(conn.execute("SELECT * FROM observations WHERE id=?",(cur.lastrowid,)).fetchone())
def list_observations(case_id):
    with get_db() as conn:
        _case_or_404(conn,case_id)
        return [dict(r) for r in conn.execute("SELECT * FROM observations WHERE case_id=? ORDER BY created_at DESC",(case_id,))]
def _normalize_time(value):
    try: dt=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc: raise HTTPException(422,"event_time must be valid ISO-8601") from exc
    assumed=dt.tzinfo is None
    if assumed: dt=dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(),assumed
def add_timeline_event(case_id,payload):
    normalized,assumed=_normalize_time(payload.event_time)
    with get_db() as conn:
        _case_or_404(conn,case_id); _validate_evidence_case(conn,case_id,payload.evidence_id); now=utc_now()
        cur=conn.execute("""INSERT INTO timeline_events(case_id,evidence_id,title,details,event_type,source_time,event_time_utc,timezone_assumed_utc,created_at)
                            VALUES(?,?,?,?,?,?,?,?,?)""",
                         (case_id,payload.evidence_id,payload.title,payload.details,payload.event_type,payload.event_time,normalized,int(assumed),now))
        conn.execute("INSERT INTO audit_events(event_type,timestamp,details_json) VALUES(?,?,?)",
                     ("timeline_event_added",now,json.dumps({"case_id":case_id,"event_id":cur.lastrowid})))
        return dict(conn.execute("SELECT * FROM timeline_events WHERE id=?",(cur.lastrowid,)).fetchone())
def list_timeline(case_id):
    with get_db() as conn:
        _case_or_404(conn,case_id)
        return [dict(r) for r in conn.execute("SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_time_utc,id",(case_id,))]
def get_case_workspace(case_id):
    with get_db() as conn:
        case=_case_or_404(conn,case_id)
        def rows(sql): return [dict(r) for r in conn.execute(sql,(case_id,))]
        return {"case":case,
                "evidence":rows("SELECT * FROM evidence WHERE case_id=? ORDER BY acquired_at DESC"),
                "observations":rows("SELECT * FROM observations WHERE case_id=? ORDER BY created_at DESC"),
                "timeline":rows("SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_time_utc,id")}
