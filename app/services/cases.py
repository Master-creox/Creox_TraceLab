import json
from datetime import datetime,timezone
from fastapi import HTTPException
from app.database import get_db,utc_now
def _case_or_404(conn,cid):
    row=conn.execute("SELECT * FROM cases WHERE case_id=?",(cid,)).fetchone()
    if row is None: raise HTTPException(404,"Case not found")
    return dict(row)
def create_case(p):
    now=utc_now()
    with get_db() as c:
        try: c.execute("INSERT INTO cases VALUES(?,?,?,?,?,?,?)",(p.case_id,p.title,p.description,p.priority,"open",now,now))
        except Exception as e:
            if "UNIQUE" in str(e): raise HTTPException(409,"Case ID already exists")
            raise
        c.execute("INSERT INTO audit_events(event_type,timestamp,details_json) VALUES(?,?,?)",("case_created",now,json.dumps({"case_id":p.case_id})))
        return _case_or_404(c,p.case_id)
def list_cases():
    with get_db() as c: return [dict(r) for r in c.execute("SELECT * FROM cases ORDER BY created_at DESC")]
def update_case_status(cid,status):
    with get_db() as c:
        _case_or_404(c,cid); now=utc_now()
        c.execute("UPDATE cases SET status=?,updated_at=? WHERE case_id=?",(status,now,cid))
        c.execute("INSERT INTO audit_events(event_type,timestamp,details_json) VALUES(?,?,?)",("case_status_changed",now,json.dumps({"case_id":cid,"status":status})))
        return _case_or_404(c,cid)
def _validate_evidence(c,cid,eid):
    if eid is not None:
        r=c.execute("SELECT case_id FROM evidence WHERE id=?",(eid,)).fetchone()
        if r is None or r["case_id"]!=cid: raise HTTPException(422,"Evidence must belong to this case")
def add_observation(cid,p):
    with get_db() as c:
        _case_or_404(c,cid); _validate_evidence(c,cid,p.evidence_id); now=utc_now()
        cur=c.execute("INSERT INTO observations(case_id,evidence_id,title,content,classification,created_at) VALUES(?,?,?,?,?,?)",(cid,p.evidence_id,p.title,p.content,p.classification,now))
        c.execute("INSERT INTO audit_events(event_type,timestamp,details_json) VALUES(?,?,?)",("observation_added",now,json.dumps({"case_id":cid,"observation_id":cur.lastrowid})))
        return dict(c.execute("SELECT * FROM observations WHERE id=?",(cur.lastrowid,)).fetchone())
def list_observations(cid):
    with get_db() as c:
        _case_or_404(c,cid); return [dict(r) for r in c.execute("SELECT * FROM observations WHERE case_id=? ORDER BY created_at DESC",(cid,))]
def _normalize(v):
    try: dt=datetime.fromisoformat(v.replace("Z","+00:00"))
    except ValueError as e: raise HTTPException(422,"event_time must be ISO-8601") from e
    assumed=dt.tzinfo is None
    if assumed: dt=dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(),assumed
def add_timeline_event(cid,p):
    normalized,assumed=_normalize(p.event_time)
    with get_db() as c:
        _case_or_404(c,cid); _validate_evidence(c,cid,p.evidence_id); now=utc_now()
        cur=c.execute("INSERT INTO timeline_events(case_id,evidence_id,title,details,event_type,source_time,event_time_utc,timezone_assumed_utc,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(cid,p.evidence_id,p.title,p.details,p.event_type,p.event_time,normalized,int(assumed),now))
        c.execute("INSERT INTO audit_events(event_type,timestamp,details_json) VALUES(?,?,?)",("timeline_event_added",now,json.dumps({"case_id":cid,"event_id":cur.lastrowid})))
        return dict(c.execute("SELECT * FROM timeline_events WHERE id=?",(cur.lastrowid,)).fetchone())
def list_timeline(cid):
    with get_db() as c:
        _case_or_404(c,cid); return [dict(r) for r in c.execute("SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_time_utc,id",(cid,))]
def get_case_workspace(cid):
    with get_db() as c:
        case=_case_or_404(c,cid)
        def rows(sql): return [dict(r) for r in c.execute(sql,(cid,))]
        return {"case":case,"evidence":rows("SELECT * FROM evidence WHERE case_id=? ORDER BY acquired_at DESC"),
                "observations":rows("SELECT * FROM observations WHERE case_id=? ORDER BY created_at DESC"),
                "timeline":rows("SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_time_utc,id")}
