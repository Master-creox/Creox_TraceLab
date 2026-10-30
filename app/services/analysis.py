import json,tempfile
from pathlib import Path
from fastapi import HTTPException
from app.database import get_db,utc_now
from app.services.evidence import get_evidence,decrypt_evidence,append_audit
from app.services.log_analyzer import analyze_log_bytes
from app.services.pcap_analyzer import analyze_pcap

def save_analysis(eid,kind,result):
    with get_db() as c:
        cur=c.execute("INSERT INTO analysis_results(evidence_id,analysis_type,created_at,result_json) VALUES(?,?,?,?)",(eid,kind,utc_now(),json.dumps(result,sort_keys=True)))
        append_audit(c,f"{kind}_analysis_completed",eid,{"analysis_id":cur.lastrowid,"parser":result.get("parser")})
        r=c.execute("SELECT * FROM analysis_results WHERE id=?",(cur.lastrowid,)).fetchone()
        return {"id":r["id"],"evidence_id":r["evidence_id"],"analysis_type":r["analysis_type"],"created_at":r["created_at"],"result":json.loads(r["result_json"])}
def analyze_evidence(eid,kind):
    r=get_evidence(eid); data=decrypt_evidence(r)
    if kind=="pcap":
        suffix=".pcapng" if r["original_filename"].lower().endswith("pcapng") else ".pcap"
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
                tmp.write(data); tmp.flush(); result=analyze_pcap(Path(tmp.name))
        except ValueError as e: raise HTTPException(422,str(e)) from e
    else: result=analyze_log_bytes(data)
    return save_analysis(eid,kind,result)
def get_analyses(eid):
    get_evidence(eid)
    with get_db() as c:
        rows=c.execute("SELECT * FROM analysis_results WHERE evidence_id=? ORDER BY id DESC",(eid,)).fetchall()
        return [{"id":r["id"],"evidence_id":r["evidence_id"],"analysis_type":r["analysis_type"],"created_at":r["created_at"],"result":json.loads(r["result_json"])} for r in rows]
