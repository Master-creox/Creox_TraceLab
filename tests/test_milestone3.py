from fastapi.testclient import TestClient

def configure(tmp_path):
    import app.config as c, app.database as d, app.services.evidence as e
    c.DATA_DIR=tmp_path; c.EVIDENCE_DIR=tmp_path/"evidence"; c.DB_PATH=tmp_path/"db.sqlite3"
    d.DATA_DIR=c.DATA_DIR; d.DB_PATH=c.DB_PATH; e.EVIDENCE_DIR=c.EVIDENCE_DIR

def test_case_observation_timeline_and_evidence(tmp_path):
    configure(tmp_path)
    from app.main import app
    with TestClient(app) as client:
        created=client.post("/api/v1/cases",json={"case_id":"CASE-001","title":"Test investigation","description":"Fixture case","priority":"high"})
        assert created.status_code==201,created.text
        upload=client.post("/api/v1/evidence",files={"file":("test.log",b"test evidence","text/plain")},
                           data={"case_id":"CASE-001","description":"fixture"})
        assert upload.status_code==201,upload.text
        eid=upload.json()["id"]
        obs=client.post("/api/v1/cases/CASE-001/observations",
                        json={"title":"Observed log artifact","content":"The test fixture was acquired.","classification":"observation","evidence_id":eid})
        assert obs.status_code==201,obs.text
        event=client.post("/api/v1/cases/CASE-001/timeline",
                          json={"title":"Evidence acquired","details":"Uploaded to vault","event_time":"2026-10-30T10:00:00+05:30","event_type":"acquisition","evidence_id":eid})
        assert event.status_code==201,event.text
        workspace=client.get("/api/v1/cases/CASE-001")
        assert workspace.status_code==200
        assert len(workspace.json()["evidence"])==1
        assert len(workspace.json()["observations"])==1
        assert len(workspace.json()["timeline"])==1
        assert workspace.json()["timeline"][0]["event_time_utc"].endswith("+00:00")

def test_reject_evidence_linked_from_other_case(tmp_path):
    configure(tmp_path)
    from app.main import app
    with TestClient(app) as client:
        for cid in ("CASE-A","CASE-B"):
            assert client.post("/api/v1/cases",json={"case_id":cid,"title":"Investigation "+cid}).status_code==201
        upload=client.post("/api/v1/evidence",files={"file":("x.txt",b"x","text/plain")},data={"case_id":"CASE-A"})
        eid=upload.json()["id"]
        bad=client.post("/api/v1/cases/CASE-B/observations",
                         json={"title":"Cross case link","content":"Should be rejected","evidence_id":eid})
        assert bad.status_code==422
