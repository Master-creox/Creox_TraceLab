import re
from datetime import datetime,timezone
from collections import Counter
from app.config import MAX_ANALYSIS_RECORDS
ISO=re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(?:(?P<level>TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL)\s+)?(?P<message>.*)$",re.I)
SYS=re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$")
APACHE=re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)')
def norm(raw,year):
    if re.match(r"^[A-Z][a-z]{2}\s",raw): dt=datetime.strptime(f"{year} {raw}","%Y %b %d %H:%M:%S"); assumed=True
    else:
        v=raw.replace("Z","+00:00")
        if re.search(r"[+-]\d{4}$",v): v=v[:-5]+v[-5:-2]+":"+v[-2:]
        dt=datetime.fromisoformat(v); assumed=dt.tzinfo is None
        if assumed: dt=dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(),assumed
def analyze_log_bytes(data):
    lines=data.decode("utf-8",errors="replace").splitlines(); records=[]; bad=[]; levels=Counter(); year=datetime.now(timezone.utc).year
    for n,line in enumerate(lines[:MAX_ANALYSIS_RECORDS],1):
        if not line.strip(): continue
        m=ISO.match(line); fmt="iso"
        if not m: m=SYS.match(line); fmt="syslog"
        if m:
            try: ts,assumed=norm(m.group("ts"),year)
            except ValueError: bad.append({"line":n,"reason":"timestamp_parse_error","text":line[:500]}); continue
            level=(m.groupdict().get("level") or "UNKNOWN").upper(); levels[level]+=1
            records.append({"line":n,"format":fmt,"timestamp_utc":ts,"timezone_assumed_utc":assumed,"level":level,"message":(m.groupdict().get("message") or "")[:1000]}); continue
        m=APACHE.match(line)
        if m:
            try: ts,assumed=norm(m.group("ts"),year)
            except ValueError: bad.append({"line":n,"reason":"timestamp_parse_error","text":line[:500]}); continue
            levels["HTTP"]+=1; records.append({"line":n,"format":"apache","timestamp_utc":ts,"timezone_assumed_utc":assumed,"level":"HTTP","client_ip":m.group("ip"),"request":m.group("request")[:500],"status_code":int(m.group("status")),"response_bytes":m.group("size")}); continue
        bad.append({"line":n,"reason":"unrecognized_format","text":line[:500]})
    times=[r["timestamp_utc"] for r in records]
    return {"parser":"tracelab-log-parser-v1","total_lines":len(lines),"parsed_records":len(records),"unparsed_lines":len(bad),"truncated":len(lines)>MAX_ANALYSIS_RECORDS,"levels":dict(sorted(levels.items())),"time_range_utc":{"first":min(times) if times else None,"last":max(times) if times else None},"records":records,"unparsed":bad}
