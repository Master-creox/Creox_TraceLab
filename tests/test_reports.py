import hashlib,json
from fastapi.testclient import TestClient

def setup_paths(tmp_path):
    import app.config as c, app.database as d, app.services.evidence as e
    c.DATA_DIR=tmp_path; c.EVIDENCE_DIR=tmp_path/"evidence"; c.DB_PATH=tmp_path/"db.sqlite3"
    d.DATA_DIR=c.DATA_DIR; d.DB_PATH=c.DB_PATH; e.EVIDENCE_DIR=c.EVIDENCE_DIR

def test_report_snapshot_hash_and_html(tmp_path):
    setup_paths(tmp_path)
    from app.main import app
    with TestClient(app) as client:
        case=client.post("/api/v1/cases",json={"case_id":"CASE-REP","title":"Report test case"})
        assert case.status_code==201,case.text
        upload=client.post("/api/v1/evidence",files={"file":("sample.txt",b"forensic fixture","text/plain")},data={"case_id":"CASE-REP"})
        assert upload.status_code==201,upload.text
        eid=upload.json()["id"]
        note=client.post("/api/v1/cases/CASE-REP/observations",json={"title":"Initial observation","content":"Fixture file acquired and hashed.","evidence_id":eid})
        assert note.status_code==201,note.text
        generated=client.post("/api/v1/cases/CASE-REP/reports",json={"title":"Case report","include_analysis":True})
        assert generated.status_code==200,generated.text
        body=generated.json()
        canonical=json.dumps(body["payload"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        assert hashlib.sha256(canonical).hexdigest()==body["payload_sha256"]
        assert "SHA-256" in body["html"]
        report_id=body["id"]
        fetched=client.get(f"/api/v1/reports/{report_id}")
        assert fetched.status_code==200
        assert fetched.json()["integrity_match"] is True
        assert len(client.get("/api/v1/cases/CASE-REP/reports").json())==1
