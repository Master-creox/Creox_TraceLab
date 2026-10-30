from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from app.config import MAX_ANALYSIS_RECORDS
def analyze_pcap(path:Path):
    try:
        from scapy.utils import PcapReader
        from scapy.layers.inet import IP,TCP,UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.dns import DNS,DNSQR
        from scapy.layers.l2 import Ether
    except ImportError as e:
        raise ValueError("PCAP analysis requires Scapy. Install dependencies with: pip install -r requirements.txt") from e
    protocols=Counter(); endpoints=Counter(); conversations=Counter(); dns=Counter(); first=last=None; count=0; truncated=False
    try:
        with PcapReader(str(path)) as reader:
            for p in reader:
                if count>=MAX_ANALYSIS_RECORDS: truncated=True; break
                count+=1; ts=datetime.fromtimestamp(float(p.time),tz=timezone.utc).isoformat()
                first=ts if first is None or ts<first else first; last=ts if last is None or ts>last else last
                src=dst=None; sp=dp=None; proto="OTHER"
                if IP in p: src,dst=p[IP].src,p[IP].dst; proto="IPv4"
                elif IPv6 in p: src,dst=p[IPv6].src,p[IPv6].dst; proto="IPv6"
                elif Ether in p: src,dst=p[Ether].src,p[Ether].dst; proto="Ethernet"
                if TCP in p: proto="TCP"; sp,dp=int(p[TCP].sport),int(p[TCP].dport)
                elif UDP in p: proto="UDP"; sp,dp=int(p[UDP].sport),int(p[UDP].dport)
                elif DNS in p: proto="DNS"
                protocols[proto]+=1
                if src: endpoints[src]+=1
                if dst: endpoints[dst]+=1
                if src and dst:
                    a,b=sorted([f"{src}:{sp or 0}",f"{dst}:{dp or 0}"]); conversations[f"{a} <-> {b} ({proto})"]+=1
                _qd = p[DNS].qd if DNS in p else None
                if isinstance(_qd, (list, tuple)):
                    _qd = _qd[0] if _qd else None
                if _qd and isinstance(_qd, DNSQR):
                    q=_qd.qname
                    if isinstance(q,bytes): q=q.decode("utf-8",errors="replace")
                    dns[str(q).rstrip(".")]+=1
    except Exception as e: raise ValueError(f"Unable to parse capture: {type(e).__name__}: {e}") from e
    return {"parser":"tracelab-pcap-parser-v1","packets":count,"truncated":truncated,"protocols":dict(protocols.most_common()),"top_endpoints":[{"address":k,"packet_references":v} for k,v in endpoints.most_common(20)],"top_conversations":[{"conversation":k,"packets":v} for k,v in conversations.most_common(20)],"dns_queries":[{"query":k,"count":v} for k,v in dns.most_common(100)],"time_range_utc":{"first":first,"last":last},"notes":["Offline metadata analysis only; packet payloads are not exported.","Endpoint counts include source and destination appearances."]}
