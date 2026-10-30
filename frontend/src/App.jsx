import React, { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, BadgeCheck, BookOpen, BriefcaseBusiness,
  CalendarClock, CheckCircle2, ChevronRight, CircleDot, Clock3, FileArchive,
  FileCheck2, FileText, Fingerprint, FolderOpen, LayoutDashboard, Loader2,
  Plus, RefreshCw, Search, Shield, ShieldCheck, Upload, Wifi, X
} from "lucide-react";

const api = async (url, options={}) => {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
};
const fmtDate = value => value ? new Date(value).toLocaleString() : "—";
const bytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KB` : `${(n/1048576).toFixed(2)} MB`;

function App() {
  const [cases,setCases]=useState([]), [selected,setSelected]=useState("");
  const [workspace,setWorkspace]=useState(null), [health,setHealth]=useState("checking");
  const [loading,setLoading]=useState(false), [busy,setBusy]=useState(""), [error,setError]=useState("");
  const [query,setQuery]=useState(""), [modal,setModal]=useState("");
  const [caseForm,setCaseForm]=useState({case_id:"",title:"",description:"",priority:"medium"});
  const [obsForm,setObsForm]=useState({title:"",content:"",classification:"observation",evidence_id:""});
  const [eventForm,setEventForm]=useState({title:"",details:"",event_time:new Date().toISOString().slice(0,16),event_type:"analyst_event",evidence_id:""});
  const [file,setFile]=useState(null), [fileDescription,setFileDescription]=useState("");
  const [report,setReport]=useState(null), [toast,setToast]=useState("");

  const loadCases=async()=>{
    try { const [data,h]=await Promise.all([api("/api/v1/cases"),api("/health")]); setCases(data);setHealth(h.status); if(!selected && data.length)setSelected(data[0].case_id); }
    catch(e){setHealth("offline");setError(e.message);}
  };
  const loadWorkspace=async(id=selected)=>{
    if(!id)return; setLoading(true);
    try{setWorkspace(await api(`/api/v1/cases/${encodeURIComponent(id)}`));setError("");}
    catch(e){setError(e.message);setWorkspace(null);}
    finally{setLoading(false);}
  };
  useEffect(()=>{loadCases();},[]);
  useEffect(()=>{if(selected)loadWorkspace(selected);},[selected]);
  const notify=msg=>{setToast(msg);window.setTimeout(()=>setToast(""),3200);};
  const run=async(label,fn)=>{
    setBusy(label);setError("");
    try{await fn();}catch(e){setError(e.message);}finally{setBusy("");}
  };
  const filteredCases=useMemo(()=>cases.filter(c=>`${c.case_id} ${c.title}`.toLowerCase().includes(query.toLowerCase())),[cases,query]);
  const evidence=workspace?.evidence||[];
  const stats=[
    {label:"Evidence items",value:evidence.length,icon:FileArchive},
    {label:"Observations",value:workspace?.observations?.length||0,icon:BookOpen},
    {label:"Timeline events",value:workspace?.timeline?.length||0,icon:CalendarClock},
    {label:"Case priority",value:workspace?.case?.priority||"—",icon:Shield}
  ];

  const createCase=async e=>{
    e.preventDefault();
    await run("create",async()=>{const c=await api("/api/v1/cases",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(caseForm)});await loadCases();setSelected(c.case_id);setModal("");setCaseForm({case_id:"",title:"",description:"",priority:"medium"});notify("Case created");});
  };
  const uploadEvidence=async e=>{
    e.preventDefault();if(!file)return;
    await run("upload",async()=>{const fd=new FormData();fd.append("file",file);fd.append("case_id",selected);fd.append("description",fileDescription);await api("/api/v1/evidence",{method:"POST",body:fd});setFile(null);setFileDescription("");e.target.reset();await loadWorkspace();notify("Evidence acquired and hashed");});
  };
  const addObservation=async e=>{
    e.preventDefault();
    await run("observation",async()=>{await api(`/api/v1/cases/${selected}/observations`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...obsForm,evidence_id:obsForm.evidence_id?Number(obsForm.evidence_id):null})});setObsForm({title:"",content:"",classification:"observation",evidence_id:""});setModal("");await loadWorkspace();notify("Observation saved");});
  };
  const addEvent=async e=>{
    e.preventDefault();
    await run("timeline",async()=>{await api(`/api/v1/cases/${selected}/timeline`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...eventForm,event_time:new Date(eventForm.event_time).toISOString(),evidence_id:eventForm.evidence_id?Number(eventForm.evidence_id):null})});setModal("");await loadWorkspace();notify("Timeline event added");});
  };
  const analyze=async(item,kind)=>run(`analysis-${item.id}`,async()=>{await api(`/api/v1/evidence/${item.id}/analyze/${kind}`,{method:"POST"});await loadWorkspace();notify(`${kind.toUpperCase()} analysis completed`);});
  const verify=async item=>run(`verify-${item.id}`,async()=>{const r=await api(`/api/v1/evidence/${item.id}/verify`,{method:"POST"});await loadWorkspace();notify(r.match?"Integrity verified":"Integrity check reported a mismatch");});
  const generateReport=async()=>run("report",async()=>{const r=await api(`/api/v1/cases/${selected}/reports`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title:`${selected} Investigation Report`,include_analysis:true})});setReport(r);notify("Report generated");});
  const openReport=()=>{if(!report)return;const w=window.open("","_blank");if(!w){setError("Popup blocked. Allow popups to view the report.");return;}w.document.open();w.document.write(report.html);w.document.close();};
  const statusClass=s=>s==="intact"||s==="verified_at_acquisition"?"good":s==="mismatch"||s==="missing"?"bad":"neutral";

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Fingerprint size={23}/></div><div><b>CREOX</b><span>TRACELAB <i>v0.5</i></span></div></div>
      <div className="side-label">WORKSPACE</div>
      <button className="nav active"><LayoutDashboard size={17}/> Command dashboard</button>
      <button className="nav" onClick={()=>setModal("case")}><BriefcaseBusiness size={17}/> New investigation <Plus size={15} className="nav-end"/></button>
      <div className="side-label cases-label">INVESTIGATIONS <span>{cases.length}</span></div>
      <div className="case-search"><Search size={14}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Find a case..."/></div>
      <div className="case-list">{filteredCases.map(c=><button key={c.case_id} className={`case-link ${selected===c.case_id?"selected":""}`} onClick={()=>setSelected(c.case_id)}><span className="case-dot"/><span className="case-link-text"><b>{c.case_id}</b><small>{c.title}</small></span><ChevronRight size={14}/></button>)}
      {!filteredCases.length&&<p className="muted small pad">No matching cases</p>}</div>
      <div className="sidebar-bottom"><div className="local-card"><ShieldCheck size={18}/><div><b>Local evidence vault</b><small>Evidence stays on this machine</small></div><span className="pulse"/></div><div className="owner"><div className="avatar">MC</div><div><b>Master Creox</b><small>Investigation workspace</small></div></div></div>
    </aside>

    <main className="main">
      <header className="topbar"><div><div className="eyebrow">DIGITAL FORENSICS / WORKSPACE</div><h1>Command dashboard</h1></div><div className="top-actions"><div className={`api-status ${health}`}><span/>API {health}</div><button className="icon-btn" title="Refresh" onClick={()=>run("refresh",async()=>{await loadCases();await loadWorkspace();})}><RefreshCw size={17}/></button><button className="primary" onClick={()=>setModal("case")}><Plus size={16}/> New case</button></div></header>
      {error&&<div className="alert"><AlertTriangle size={17}/><span>{error}</span><button onClick={()=>setError("")}><X size={15}/></button></div>}
      {!selected?<section className="empty-state"><div className="empty-icon"><FolderOpen size={34}/></div><h2>Your investigation workspace is ready</h2><p>Create your first case to start acquiring and analyzing evidence.</p><button className="primary" onClick={()=>setModal("case")}><Plus size={16}/> Create first case</button></section>:
      <>
        <section className="case-heading"><div><div className="eyebrow">ACTIVE INVESTIGATION <span className="case-id">{workspace?.case?.case_id||selected}</span></div><h2>{workspace?.case?.title||"Loading case..."}</h2><p>{workspace?.case?.description||"No case description provided."}</p></div><div className="case-meta"><span className={`priority ${workspace?.case?.priority}`}>{workspace?.case?.priority||"—"} priority</span><select value={workspace?.case?.status||"open"} onChange={e=>run("status",async()=>{await api(`/api/v1/cases/${selected}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({status:e.target.value})});await loadWorkspace();notify("Case status updated");})}><option value="open">Open</option><option value="in_progress">In progress</option><option value="closed">Closed</option></select></div></section>
        <section className="stats">{stats.map(s=><div className="stat" key={s.label}><div className="stat-icon"><s.icon size={18}/></div><div><small>{s.label}</small><strong>{s.value}</strong></div></div>)}</section>
        <div className="content-grid">
          <section className="panel evidence-panel"><div className="panel-head"><div><h3><FileArchive size={17}/> Evidence vault</h3><p>Acquired artifacts and integrity controls</p></div><span className="count">{evidence.length} ITEMS</span></div>
            <form className="upload-row" onSubmit={uploadEvidence}><label className="file-pick"><Upload size={17}/><span>{file?file.name:"Choose evidence file"}</span><input type="file" onChange={e=>setFile(e.target.files?.[0]||null)} required/></label><input className="desc-input" value={fileDescription} onChange={e=>setFileDescription(e.target.value)} placeholder="Evidence description (optional)"/><button className="primary" disabled={!file||!!busy}>{busy==="upload"?<Loader2 className="spin" size={15}/>:<Upload size={15}/>} Acquire</button></form>
            {loading?<div className="loading"><Loader2 className="spin"/> Loading evidence...</div>:evidence.length===0?<div className="empty-inline"><FileText size={23}/><span>No evidence acquired for this case yet.</span></div>:
            <div className="table-wrap"><table><thead><tr><th>ARTIFACT</th><th>SIZE</th><th>SHA-256</th><th>INTEGRITY</th><th>ACTIONS</th></tr></thead><tbody>{evidence.map(item=><tr key={item.id}><td><div className="artifact"><FileText size={17}/><div><b>{item.original_filename}</b><small>#{item.id} · {fmtDate(item.acquired_at)}</small></div></div></td><td>{bytes(item.size_bytes)}</td><td><code title={item.sha256}>{item.sha256.slice(0,14)}…</code></td><td><span className={`tag ${statusClass(item.integrity_status)}`}>{item.integrity_status}</span></td><td><div className="action-row"><button className="tiny" title="Verify SHA-256" onClick={()=>verify(item)} disabled={!!busy}><ShieldCheck size={14}/></button><button className="tiny" title="Analyze logs" onClick={()=>analyze(item,"logs")} disabled={!!busy}><FileText size={14}/></button><button className="tiny" title="Analyze PCAP" onClick={()=>analyze(item,"pcap")} disabled={!!busy}><Wifi size={14}/></button></div></td></tr>)}</tbody></table></div>}
          </section>
          <section className="panel timeline-panel"><div className="panel-head"><div><h3><CalendarClock size={17}/> Investigation timeline</h3><p>Chronological events · UTC</p></div><button className="outline small-btn" onClick={()=>setModal("event")}><Plus size={14}/> Add event</button></div>
            <div className="timeline">{(workspace?.timeline||[]).map(ev=><div className="timeline-item" key={ev.id}><span className="timeline-point"/><div><small>{fmtDate(ev.event_time_utc)}</small><b>{ev.title}</b><p>{ev.details||ev.event_type}</p></div></div>)}
            {!workspace?.timeline?.length&&<div className="empty-inline"><Clock3 size={22}/>No timeline events yet.</div>}</div>
          </section>
          <section className="panel observations-panel"><div className="panel-head"><div><h3><BookOpen size={17}/> Analyst observations</h3><p>Document facts, hypotheses and conclusions</p></div><button className="outline small-btn" onClick={()=>setModal("observation")}><Plus size={14}/> Add note</button></div>
            <div className="notes">{(workspace?.observations||[]).map(o=><article className="note" key={o.id}><div><span className="tag neutral">{o.classification}</span><small>{fmtDate(o.created_at)}</small></div><b>{o.title}</b><p>{o.content}</p></article>)}
            {!workspace?.observations?.length&&<div className="empty-inline"><BookOpen size={22}/>No analyst observations yet.</div>}</div>
          </section>
          <section className="panel reports-panel"><div className="panel-head"><div><h3><FileCheck2 size={17}/> Forensic reports</h3><p>Generate a case snapshot and integrity manifest</p></div><button className="primary small-btn" onClick={generateReport} disabled={!!busy}>{busy==="report"?<Loader2 className="spin" size={14}/>:<FileText size={14}/>} Generate</button></div>
            {report?<div className="report-preview"><div className="report-success"><CheckCircle2 size={18}/> Report generated</div><b>{report.title}</b><small>SHA-256: {report.payload_sha256.slice(0,24)}…</small><button className="outline" onClick={openReport}>Open HTML report <ArrowUpRight size={14}/></button></div>:<div className="empty-inline"><FileCheck2 size={22}/>Generate a report to see its preview here.</div>}
          </section>
        </div>
      </>}
      <footer><span>CREOX TRACELAB <b>v0.5.0</b></span><span><Shield size={13}/> Local-first · Authorized investigations only</span></footer>
    </main>

    {modal&&<div className="modal-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget)setModal("");}}><div className="modal"><div className="modal-head"><div><div className="eyebrow">CREOX TRACELAB</div><h2>{modal==="case"?"Create investigation":modal==="observation"?"Add analyst observation":"Add timeline event"}</h2></div><button className="icon-btn" onClick={()=>setModal("")}><X size={18}/></button></div>
      {modal==="case"&&<form onSubmit={createCase} className="modal-form"><label>Case ID<input required pattern="[A-Za-z0-9_-]+" value={caseForm.case_id} onChange={e=>setCaseForm({...caseForm,case_id:e.target.value})} placeholder="CASE-2026-001"/></label><label>Case title<input required minLength="3" value={caseForm.title} onChange={e=>setCaseForm({...caseForm,title:e.target.value})} placeholder="Suspicious workstation activity"/></label><label>Description<textarea value={caseForm.description} onChange={e=>setCaseForm({...caseForm,description:e.target.value})} placeholder="Investigation scope and context"/></label><label>Priority<select value={caseForm.priority} onChange={e=>setCaseForm({...caseForm,priority:e.target.value})}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label><button className="primary" disabled={!!busy}>{busy==="create"?"Creating…":"Create case"}</button></form>}
      {modal==="observation"&&<form onSubmit={addObservation} className="modal-form"><label>Title<input required minLength="3" value={obsForm.title} onChange={e=>setObsForm({...obsForm,title:e.target.value})}/></label><label>Details<textarea required value={obsForm.content} onChange={e=>setObsForm({...obsForm,content:e.target.value})}/></label><label>Classification<select value={obsForm.classification} onChange={e=>setObsForm({...obsForm,classification:e.target.value})}><option value="observation">Observation</option><option value="hypothesis">Hypothesis</option><option value="conclusion">Conclusion</option></select></label><label>Linked evidence<select value={obsForm.evidence_id} onChange={e=>setObsForm({...obsForm,evidence_id:e.target.value})}><option value="">None</option>{evidence.map(x=><option key={x.id} value={x.id}>#{x.id} {x.original_filename}</option>)}</select></label><button className="primary" disabled={!!busy}>Save observation</button></form>}
      {modal==="event"&&<form onSubmit={addEvent} className="modal-form"><label>Event title<input required minLength="3" value={eventForm.title} onChange={e=>setEventForm({...eventForm,title:e.target.value})}/></label><label>Details<textarea value={eventForm.details} onChange={e=>setEventForm({...eventForm,details:e.target.value})}/></label><label>Event date/time (local)<input type="datetime-local" required value={eventForm.event_time} onChange={e=>setEventForm({...eventForm,event_time:e.target.value})}/></label><label>Event type<input value={eventForm.event_type} onChange={e=>setEventForm({...eventForm,event_type:e.target.value})}/></label><label>Linked evidence<select value={eventForm.evidence_id} onChange={e=>setEventForm({...eventForm,evidence_id:e.target.value})}><option value="">None</option>{evidence.map(x=><option key={x.id} value={x.id}>#{x.id} {x.original_filename}</option>)}</select></label><button className="primary" disabled={!!busy}>Add timeline event</button></form>}
    </div></div>}
    {toast&&<div className="toast"><CheckCircle2 size={17}/>{toast}</div>}
    {busy&&<div className="busy-indicator"><Loader2 className="spin" size={15}/>{busy==="report"?"Generating report…":"Working…"}</div>}
  </div>;
}
export default App;
