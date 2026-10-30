from fastapi.testclient import TestClient
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.utils import wrpcap

def configure_test_paths(tmp_path):
    import app.config as config
    import app.database as database
    import app.services.evidence as evidence_service
    import app.services.analysis as analysis_service
    config.DATA_DIR = tmp_path
    config.EVIDENCE_DIR = tmp_path / "evidence"
    config.DB_PATH = tmp_path / "tracelab.sqlite3"
    database.DATA_DIR = config.DATA_DIR
    database.DB_PATH = config.DB_PATH
    evidence_service.EVIDENCE_DIR = config.EVIDENCE_DIR
    return config

def test_log_analysis_and_persistence(tmp_path):
    configure_test_paths(tmp_path)
    from app.main import app
    with TestClient(app) as client:
        body = (b"2026-10-30T10:00:00Z INFO service started\n"
                b"2026-10-30T10:01:00+05:30 ERROR connection failed\n"
                b"this line is not recognized\n")
        uploaded = client.post("/api/v1/evidence",
            files={"file": ("app.log", body, "text/plain")},
            data={"case_id": "CASE-LOG"})
        assert uploaded.status_code == 201
        eid = uploaded.json()["id"]
        analyzed = client.post(f"/api/v1/evidence/{eid}/analyze/logs")
        assert analyzed.status_code == 200, analyzed.text
        result = analyzed.json()["result"]
        assert result["parsed_records"] == 2
        assert result["unparsed_lines"] == 1
        assert result["levels"]["ERROR"] == 1
        saved = client.get(f"/api/v1/evidence/{eid}/analyses")
        assert len(saved.json()) == 1

def test_pcap_analysis_offline(tmp_path):
    configure_test_paths(tmp_path)
    pcap_path = tmp_path / "tiny.pcap"
    packets = [
        IP(src="192.0.2.10", dst="198.51.100.53") /
        UDP(sport=53000, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="example.org")),
        IP(src="192.0.2.10", dst="198.51.100.20") / UDP(sport=40000, dport=443)
    ]
    wrpcap(str(pcap_path), packets)
    from app.main import app
    with TestClient(app) as client:
        uploaded = client.post("/api/v1/evidence",
            files={"file": ("tiny.pcap", pcap_path.read_bytes(), "application/vnd.tcpdump.pcap")},
            data={"case_id": "CASE-PCAP"})
        assert uploaded.status_code == 201
        eid = uploaded.json()["id"]
        analyzed = client.post(f"/api/v1/evidence/{eid}/analyze/pcap")
        assert analyzed.status_code == 200, analyzed.text
        result = analyzed.json()["result"]
        assert result["packets"] == 2
        assert result["protocols"]["UDP"] == 2
        assert result["dns_queries"][0]["query"] == "example.org"
