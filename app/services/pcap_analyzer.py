from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from app.config import MAX_ANALYSIS_RECORDS

def analyze_pcap(path: Path) -> dict:
    protocols = Counter()
    endpoints = Counter()
    conversations = Counter()
    dns_queries = Counter()
    first_ts = last_ts = None
    packet_count = 0
    truncated = False
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if packet_count >= MAX_ANALYSIS_RECORDS:
                    truncated = True
                    break
                packet_count += 1
                ts = float(packet.time)
                iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                first_ts = iso if first_ts is None or iso < first_ts else first_ts
                last_ts = iso if last_ts is None or iso > last_ts else last_ts

                proto = "OTHER"
                src = dst = None
                sport = dport = None
                if IP in packet:
                    layer = packet[IP]; src, dst = layer.src, layer.dst
                    proto = "IPv4"
                elif IPv6 in packet:
                    layer = packet[IPv6]; src, dst = layer.src, layer.dst
                    proto = "IPv6"
                elif Ether in packet:
                    src, dst = packet[Ether].src, packet[Ether].dst
                    proto = "Ethernet"

                if TCP in packet:
                    proto = "TCP"; sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
                elif UDP in packet:
                    proto = "UDP"; sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
                elif DNS in packet:
                    proto = "DNS"
                protocols[proto] += 1

                if src:
                    endpoints[src] += 1
                if dst:
                    endpoints[dst] += 1
                if src and dst:
                    left, right = sorted([f"{src}:{sport or 0}", f"{dst}:{dport or 0}"])
                    conversations[f"{left} <-> {right} ({proto})"] += 1
                # Scapy returns DNS.qd as a LIST when read back from a PCAP,
                # not a single DNSQR — take the first entry (fix 2026-10-30).
                _qd = packet[DNS].qd if DNS in packet else None
                if isinstance(_qd, (list, tuple)):
                    _qd = _qd[0] if _qd else None
                if _qd and isinstance(_qd, DNSQR):
                    qname = _qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="replace")
                    dns_queries[str(qname).rstrip(".")] += 1
    except Exception as exc:
        raise ValueError(f"Unable to parse capture: {type(exc).__name__}: {exc}") from exc

    return {
        "parser": "tracelab-pcap-parser-v1",
        "packets": packet_count,
        "truncated": truncated,
        "protocols": dict(protocols.most_common()),
        "top_endpoints": [{"address": k, "packet_references": v} for k, v in endpoints.most_common(20)],
        "top_conversations": [{"conversation": k, "packets": v} for k, v in conversations.most_common(20)],
        "dns_queries": [{"query": k, "count": v} for k, v in dns_queries.most_common(100)],
        "time_range_utc": {"first": first_ts, "last": last_ts},
        "notes": ["Offline metadata analysis only; packet payloads are not exported.",
                  "Endpoint counts count source and destination appearances."]
    }
