import hashlib,json,uuid,html
from fastapi import HTTPException
from app.database import get_db,utc_now
from app.services.cases import get_case_workspace
from app.services.evidence import append_audit
def canonical(p): return json.dumps(p,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def _summary(r):
    if r.get("parser","").startswith("tracelab-pcap"): return {"packets":r.get("packets"),"protocols":r.get("protocols"),"top_endpoints":r.get("top_endpoints",[])[:10],"dns_queries":r.get("dns_queries",[])[:20]}
    return {"total_lines":r.get("total_lines"),"parsed_records":r.get("parsed_records"),"unparsed_lines":r.get("unparsed_lines"),"levels":r.get("levels"),"time_range_utc":r.get("time_range_utc")}
def build_report(cid,title,include_analysis=True):
    w=get_case_workspace(cid); evidence=[]
    with get_db() as c:
        for e in w["evidence"]:
            analyses=[]
            if include_analysis:
                for a in c.execute("SELECT analysis_type,created_at,result_json FROM analysis_results WHERE evidence_id=? ORDER BY id DESC",(e["id"],)):
                    analyses.append({"analysis_type":a["analysis_type"],"created_at":a["created_at"],"summary":_summary(json.loads(a["result_json"]))})
            evidence.append({k:e[k] for k in ("id","evidence_uuid","original_filename","media_type","size_bytes","sha256","description","acquired_at","integrity_status")} | {"analyses":analyses})
    payload={"schema":"creox-tracelab-report-v1","report_title":title,"generated_at_utc":utc_now(),"case":w["case"],"evidence":evidence,"observations":w["observations"],"timeline":w["timeline"],"disclaimer":"Investigative aid only; does not independently prove source authenticity, factual conclusions, or legal chain of custody."}
    digest=hashlib.sha256(canonical(payload)).hexdigest(); uid=str(uuid.uuid4())
    with get_db() as c:
        cur=c.execute("INSERT INTO reports(report_uuid,case_id,title,created_at,payload_json,payload_sha256) VALUES(?,?,?,?,?,?)",(uid,cid,title,payload["generated_at_utc"],canonical(payload).decode(),digest))
        append_audit(c,"report_generated",None,{"report_id":cur.lastrowid,"case_id":cid,"sha256":digest})
    return {"id":cur.lastrowid,"report_uuid":uid,"case_id":cid,"title":title,"created_at":payload["generated_at_utc"],"payload_sha256":digest,"payload":payload,"html":render_html(payload,digest)}
def render_html(p,digest):
    e=lambda x:html.escape(str(x if x is not None else ""))
    c=p["case"]
    er="".join(f"<tr><td>{e(x['id'])}</td><td>{e(x['original_filename'])}</td><td>{e(x['size_bytes'])}</td><td><code>{e(x['sha256'])}</code></td><td>{e(x['integrity_status'])}</td></tr>" for x in p["evidence"])
    obs="".join(f"<li><b>{e(x['classification'])}: {e(x['title'])}</b><p>{e(x['content'])}</p></li>" for x in p["observations"])
    tl="".join(f"<tr><td>{e(x['event_time_utc'])}</td><td>{e(x['event_type'])}</td><td>{e(x['title'])}</td><td>{e(x['details'])}</td></tr>" for x in p["timeline"])
    analyses=[]
    for x in p["evidence"]:
        for a in x["analyses"]: analyses.append(f"<li>Evidence #{e(x['id'])} — {e(a['analysis_type'])}<pre>{e(json.dumps(a['summary'],indent=2))}</pre></li>")
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{e(p['report_title'])}</title><style>
body{{background:#0b1220;color:#e8eef8;font:15px/1.55 system-ui;margin:0}}main{{max-width:1080px;margin:30px auto;padding:0 20px}}header,section{{background:#121d30;border:1px solid #2a3a52;border-radius:14px;padding:22px;margin-bottom:16px}}h2{{color:#61b7ff}}table{{width:100%;border-collapse:collapse;overflow-wrap:anywhere}}td,th{{text-align:left;padding:9px;border-bottom:1px solid #2a3a52;vertical-align:top}}code,pre{{overflow-wrap:anywhere;white-space:pre-wrap}}button{{padding:10px 15px;border:0;border-radius:8px}}@media print{{body{{background:white;color:black}}main{{margin:0}}header,section{{background:white;color:black;border-color:#aaa;break-inside:avoid}}button{{display:none}}h2{{color:#174b78}}}}</style></head><body><main><header><p>CREOX TRACELAB · DIGITAL FORENSICS</p><h1>{e(p['report_title'])}</h1><p>{e(c['case_id'])} · {e(c['status'])} · {e(c['priority'])}</p><p>Generated {e(p['generated_at_utc'])}</p><button onclick="window.print()">Print / Save as PDF</button></header>
<section><h2>Case overview</h2><b>{e(c['title'])}</b><p>{e(c['description'])}</p></section>
<section><h2>Evidence inventory</h2><table><tr><th>ID</th><th>Filename</th><th>Bytes</th><th>SHA-256</th><th>Status</th></tr>{er or '<tr><td colspan="5">No evidence</td></tr>'}</table></section>
<section><h2>Analysis summaries</h2><ul>{''.join(analyses) or '<li>No analysis included</li>'}</ul></section>
<section><h2>Observations</h2><ul>{obs or '<li>None</li>'}</ul></section>
<section><h2>Timeline (UTC)</h2><table><tr><th>Time</th><th>Type</th><th>Event</th><th>Details</th></tr>{tl or '<tr><td colspan="4">No events</td></tr>'}</table></section>
<section><h2>Report SHA-256 manifest</h2><code>{digest}</code><p>Digest of canonical JSON report payload; this is an integrity checksum, not a digital signature.</p><p>{e(p['disclaimer'])}</p></section></main></body></html>"""
def list_reports(cid):
    with get_db() as c:
        if not c.execute("SELECT 1 FROM cases WHERE case_id=?",(cid,)).fetchone(): raise HTTPException(404,"Case not found")
        return [dict(r) for r in c.execute("SELECT id,report_uuid,case_id,title,created_at,payload_sha256 FROM reports WHERE case_id=? ORDER BY id DESC",(cid,))]
def get_report(rid):
    with get_db() as c:
        r=c.execute("SELECT * FROM reports WHERE id=?",(rid,)).fetchone()
        if r is None: raise HTTPException(404,"Report not found")
        p=json.loads(r["payload_json"]); match=hashlib.sha256(canonical(p)).hexdigest()==r["payload_sha256"]
        return {"id":r["id"],"report_uuid":r["report_uuid"],"case_id":r["case_id"],"title":r["title"],"created_at":r["created_at"],"payload_sha256":r["payload_sha256"],"integrity_match":match,"payload":p,"html":render_html(p,r["payload_sha256"])}
