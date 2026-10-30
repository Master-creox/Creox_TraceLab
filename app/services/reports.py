import hashlib,json,uuid,html
from fastapi import HTTPException
from app.database import get_db,utc_now
from app.services.cases import get_case_workspace
from app.services.evidence import append_audit

def _canonical(payload):
    return json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")

def _analysis_summary(result):
    if result.get("parser","").startswith("tracelab-pcap"):
        return {"packets":result.get("packets"),"protocols":result.get("protocols"),
                "top_endpoints":result.get("top_endpoints",[])[:10],"dns_queries":result.get("dns_queries",[])[:20]}
    return {"total_lines":result.get("total_lines"),"parsed_records":result.get("parsed_records"),
            "unparsed_lines":result.get("unparsed_lines"),"levels":result.get("levels"),
            "time_range_utc":result.get("time_range_utc")}

def build_report(case_id,title,include_analysis=True):
    workspace=get_case_workspace(case_id)
    evidence=[]
    with get_db() as conn:
        for item in workspace["evidence"]:
            analyses=[]
            if include_analysis:
                rows=conn.execute("SELECT analysis_type,created_at,result_json FROM analysis_results WHERE evidence_id=? ORDER BY id DESC",(item["id"],)).fetchall()
                analyses=[{"analysis_type":r["analysis_type"],"created_at":r["created_at"],
                           "summary":_analysis_summary(json.loads(r["result_json"]))} for r in rows]
            evidence.append({k:item[k] for k in ("id","evidence_uuid","original_filename","media_type","size_bytes","sha256","description","acquired_at","integrity_status")} | {"analyses":analyses})
    payload={
        "schema":"creox-tracelab-report-v1",
        "report_title":title,
        "generated_at_utc":utc_now(),
        "case":workspace["case"],
        "evidence":evidence,
        "observations":workspace["observations"],
        "timeline":workspace["timeline"],
        "disclaimer":"This report is an investigative aid. It does not independently prove source authenticity, factual conclusions, or legal chain of custody."
    }
    digest=hashlib.sha256(_canonical(payload)).hexdigest()
    report_uuid=str(uuid.uuid4())
    with get_db() as conn:
        cur=conn.execute("INSERT INTO reports(report_uuid,case_id,title,created_at,payload_json,payload_sha256) VALUES(?,?,?,?,?,?)",
                         (report_uuid,case_id,title,payload["generated_at_utc"],_canonical(payload).decode("utf-8"),digest))
        rid=cur.lastrowid
        append_audit(conn,"report_generated",None,{"report_id":rid,"report_uuid":report_uuid,"case_id":case_id,"sha256":digest})
    return {"id":rid,"report_uuid":report_uuid,"case_id":case_id,"title":title,
            "created_at":payload["generated_at_utc"],"payload_sha256":digest,"payload":payload,
            "html":render_html(payload,digest)}

def render_html(payload,digest):
    esc=lambda x: html.escape(str(x if x is not None else ""))
    c=payload["case"]
    evidence_rows="".join(f"<tr><td>{esc(e['id'])}</td><td>{esc(e['original_filename'])}</td><td>{esc(e['size_bytes'])}</td><td><code>{esc(e['sha256'])}</code></td><td>{esc(e['integrity_status'])}</td></tr>" for e in payload["evidence"])
    obs_rows="".join(f"<li><b>{esc(o['classification'])}: {esc(o['title'])}</b><p>{esc(o['content'])}</p></li>" for o in payload["observations"])
    timeline_rows="".join(f"<tr><td>{esc(t['event_time_utc'])}</td><td>{esc(t['event_type'])}</td><td>{esc(t['title'])}</td><td>{esc(t['details'])}</td></tr>" for t in payload["timeline"])
    analysis_blocks=[]
    for e in payload["evidence"]:
        for a in e["analyses"]:
            analysis_blocks.append(f"<li>Evidence #{esc(e['id'])} — {esc(a['analysis_type'])}: <pre>{esc(json.dumps(a['summary'],indent=2,ensure_ascii=False))}</pre></li>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(payload['report_title'])}</title>
<style>
:root{{--bg:#0b1220;--panel:#121d30;--text:#e8eef8;--muted:#9eacc2;--line:#2a3a52;--accent:#61b7ff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:36px auto;padding:0 22px}}header,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:18px}}
h1,h2{{margin-top:0}}h1{{font-size:28px}}h2{{font-size:19px;color:var(--accent)}}.muted{{color:var(--muted)}}table{{width:100%;border-collapse:collapse;display:block;overflow-x:auto}}td,th{{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}code,pre{{overflow-wrap:anywhere;white-space:pre-wrap}}.hash{{font-size:12px}}button{{background:var(--accent);border:0;border-radius:8px;padding:10px 16px;font-weight:700;cursor:pointer}}
@media print{{:root{{--bg:#fff;--panel:#fff;--text:#111;--muted:#444;--line:#bbb;--accent:#174b78}}body{{background:#fff;color:#111}}main{{margin:0;max-width:none;padding:0}}header,.panel{{break-inside:avoid}}button{{display:none}}}}
</style></head><body><main><header><p class="muted">CREOX TRACELAB · DIGITAL FORENSICS</p><h1>{esc(payload['report_title'])}</h1><p>{esc(c['case_id'])} · {esc(c['status']).upper()} · Priority {esc(c['priority'])}</p><p class="muted">Generated {esc(payload['generated_at_utc'])}</p><button onclick="window.print()">Print / Save as PDF</button></header>
<section class="panel"><h2>Case overview</h2><p><b>{esc(c['title'])}</b></p><p>{esc(c['description'])}</p><p>Status: {esc(c['status'])} | Created: {esc(c['created_at'])}</p></section>
<section class="panel"><h2>Evidence inventory</h2><table><thead><tr><th>ID</th><th>Filename</th><th>Bytes</th><th>SHA-256</th><th>Integrity status</th></tr></thead><tbody>{evidence_rows or '<tr><td colspan="5">No evidence linked.</td></tr>'}</tbody></table></section>
<section class="panel"><h2>Analysis summaries</h2><ul>{''.join(analysis_blocks) or '<li>No analysis results included.</li>'}</ul></section>
<section class="panel"><h2>Analyst observations</h2><ul>{obs_rows or '<li>No observations recorded.</li>'}</ul></section>
<section class="panel"><h2>Investigation timeline (UTC)</h2><table><thead><tr><th>Time</th><th>Type</th><th>Event</th><th>Details</th></tr></thead><tbody>{timeline_rows or '<tr><td colspan="4">No timeline events.</td></tr>'}</tbody></table></section>
<section class="panel"><h2>Report integrity manifest</h2><p class="muted">SHA-256 of canonical UTF-8 JSON report payload:</p><code class="hash">{digest}</code><p class="muted">Recompute the digest over the stored payload to check whether the report payload has changed.</p></section>
<section class="panel"><h2>Limitations</h2><p>{esc(payload['disclaimer'])}</p></section></main></body></html>"""

def list_reports(case_id):
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM cases WHERE case_id=?",(case_id,)).fetchone():
            raise HTTPException(404,"Case not found")
        rows=conn.execute("SELECT id,report_uuid,case_id,title,created_at,payload_sha256 FROM reports WHERE case_id=? ORDER BY id DESC",(case_id,)).fetchall()
        return [dict(r) for r in rows]
def get_report(report_id):
    with get_db() as conn:
        row=conn.execute("SELECT * FROM reports WHERE id=?",(report_id,)).fetchone()
        if row is None: raise HTTPException(404,"Report not found")
        payload=json.loads(row["payload_json"])
        actual=hashlib.sha256(_canonical(payload)).hexdigest()
        return {"id":row["id"],"report_uuid":row["report_uuid"],"case_id":row["case_id"],
                "title":row["title"],"created_at":row["created_at"],"payload_sha256":row["payload_sha256"],
                "integrity_match":actual==row["payload_sha256"],"payload":payload,"html":render_html(payload,row["payload_sha256"])}
