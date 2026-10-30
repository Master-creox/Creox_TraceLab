from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from app.config import MAX_ANALYSIS_RECORDS
def analyze_pcap(path: Path):
    protocols=Counter(); endpoints=Counter(); conversations=Counter(); dns=Counter()
    first=last=None; count=0; truncated=False
    try:
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                if count>=MAX_ANALYSIS_RECORDS: truncated=True; break
                count+=1; ts=datetime.fromtimestamp(float(pkt.time),tz=timezone.utc).isoformat()
                first=ts if first is None or ts<first else first; last=ts if last is None or ts>last else last
                src=dst=None; sport=dport=None; proto="OTHER"
                if IP in pkt: src,dst=pkt[IP].src,pkt[IP].dst; proto="IPv4"
                elif IPv6 in pkt: src,dst=pkt[IPv6].src,pkt[IPv6].dst; proto="IPv6"
                elif Ether in pkt: src,dst=pkt[Ether].src,pkt[Ether].dst; proto="Ethernet"
                if TCP in pkt: proto="TCP"; sport,dport=int(pkt[TCP].sport),int(pkt[TCP].dport)
                elif UDP in pkt: proto="UDP"; sport,dport=int(pkt[UDP].sport),int(pkt[UDP].dport)
                elif DNS in pkt: proto="DNS"
                protocols[proto]+=1
                if src: endpoints[src]+=1
                if dst: endpoints[dst]+=1
                if src and dst:
                    a,b=sorted([f"{src}:{sport or 0}",f"{dst}:{dport or 0}"])
                    conversations[f"{a} <-> {b} ({proto})"]+=1
                _qd = pkt[DNS].qd if DNS in pkt else None
                if isinstance(_qd, (list, tuple)):
                    _qd = _qd[0] if _qd else None
                if _qd and isinstance(_qd, DNSQR):
                    q=_qd.qname
                    if isinstance(q,bytes): q=q.decode("utf-8",errors="replace")
                    dns[str(q).rstrip(".")]+=1
    except Exception as exc: raise ValueError(f"Unable to parse capture: {type(exc).__name__}: {exc}") from exc
    return {"parser":"tracelab-pcap-parser-v1","packets":count,"truncated":truncated,
            "protocols":dict(protocols.most_common()),
            "top_endpoints":[{"address":k,"packet_references":v} for k,v in endpoints.most_common(20)],
            "top_conversations":[{"conversation":k,"packets":v} for k,v in conversations.most_common(20)],
            "dns_queries":[{"query":k,"count":v} for k,v in dns.most_common(100)],
            "time_range_utc":{"first":first,"last":last},
            "notes":["Offline metadata analysis only; packet payloads are not exported.",
                     "Endpoint counts count source and destination appearances."]}
