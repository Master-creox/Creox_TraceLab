import re
from datetime import datetime, timezone
from collections import Counter
from app.config import MAX_ANALYSIS_RECORDS

ISO_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?:(?P<level>TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL)\s+)?(?P<message>.*)$", re.I)
SYSLOG_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$")
APACHE_RE = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)')

def normalize_timestamp(raw: str, current_year: int) -> tuple[str, bool]:
    raw = raw.strip()
    naive = False
    if re.match(r"^[A-Z][a-z]{2}\s", raw):
        dt = datetime.strptime(f"{current_year} {raw}", "%Y %b %d %H:%M:%S")
        naive = True
    else:
        value = raw.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", value):
            value = value[:-5] + value[-5:-2] + ":" + value[-2:]
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
            naive = True
    return dt.astimezone(timezone.utc).isoformat(), naive

def analyze_log_bytes(data: bytes) -> dict:
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    year = datetime.now(timezone.utc).year
    records, levels, unparsed = [], Counter(), []
    for number, line in enumerate(lines[:MAX_ANALYSIS_RECORDS], start=1):
        if not line.strip():
            continue
        match = ISO_RE.match(line)
        kind = "iso"
        if not match:
            match = SYSLOG_RE.match(line)
            kind = "syslog"
        if match:
            raw_ts = match.group("ts")
            try:
                timestamp, assumed_utc = normalize_timestamp(raw_ts, year)
            except ValueError:
                unparsed.append({"line": number, "reason": "timestamp_parse_error", "text": line[:500]})
                continue
            level = (match.groupdict().get("level") or "UNKNOWN").upper()
            levels[level] += 1
            records.append({"line": number, "format": kind, "timestamp_utc": timestamp,
                            "timezone_assumed_utc": assumed_utc, "level": level,
                            "message": (match.groupdict().get("message") or "")[:1000]})
            continue
        match = APACHE_RE.match(line)
        if match:
            try:
                timestamp, assumed_utc = normalize_timestamp(match.group("ts"), year)
            except ValueError:
                unparsed.append({"line": number, "reason": "timestamp_parse_error", "text": line[:500]})
                continue
            status = int(match.group("status"))
            records.append({"line": number, "format": "apache", "timestamp_utc": timestamp,
                            "timezone_assumed_utc": assumed_utc, "level": "HTTP",
                            "client_ip": match.group("ip"), "request": match.group("request")[:500],
                            "status_code": status, "response_bytes": match.group("size")})
            levels["HTTP"] += 1
            continue
        unparsed.append({"line": number, "reason": "unrecognized_format", "text": line[:500]})
    timestamps = [r["timestamp_utc"] for r in records]
    return {
        "parser": "tracelab-log-parser-v1",
        "total_lines": len(lines),
        "parsed_records": len(records),
        "unparsed_lines": len(unparsed),
        "truncated": len(lines) > MAX_ANALYSIS_RECORDS,
        "levels": dict(sorted(levels.items())),
        "time_range_utc": {"first": min(timestamps) if timestamps else None,
                           "last": max(timestamps) if timestamps else None},
        "records": records,
        "unparsed": unparsed
    }
