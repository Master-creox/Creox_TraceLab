"""M6 integration tests: auth + roles + hash-chained audit, on top of M5.

These run against the integrated app (sqlite3, M1-M5 tables intact).
The JWT secret is set via env before any auth call; auth reads it at
call time, so monkeypatch.setenv works here.
"""
import os

import pytest
from fastapi.testclient import TestClient


def setup_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_LAB_JWT_SECRET", "test-secret-that-is-long-enough-123456")
    import app.config as config
    import app.database as database
    import app.services.evidence as evidence_service

    config.DATA_DIR = tmp_path
    config.EVIDENCE_DIR = tmp_path / "evidence"
    config.DB_PATH = tmp_path / "tracelab.sqlite3"
    database.DATA_DIR = config.DATA_DIR
    database.DB_PATH = config.DB_PATH
    evidence_service.EVIDENCE_DIR = config.EVIDENCE_DIR


def _seed_admin(client):
    # First user is created directly in the DB for the test (bootstrap
    # script does the same on a real install); the API route for user
    # creation itself requires an admin, so it cannot bootstrap itself.
    import app.database as database
    from app.services.auth import hash_password

    with database.get_db() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, role, is_active, created_at)"
            " VALUES (?, ?, 'admin', 1, '2026-10-30T00:00:00+00:00')",
            ("admin", hash_password("Admin-Long-Password!")),
        )


def test_login_me_roles_and_chain(tmp_path, monkeypatch):
    setup_paths(tmp_path, monkeypatch)
    from app.main import app

    with TestClient(app) as client:
        _seed_admin(client)
        bad = client.post("/api/v1/auth/login", data={"username": "admin", "password": "wrong"})
        assert bad.status_code == 401
        ok = client.post("/api/v1/auth/login", data={"username": "admin", "password": "Admin-Long-Password!"})
        assert ok.status_code == 200, ok.text
        token = ok.json()["access_token"]
        assert ok.json()["role"] == "admin"
        me = client.get("/api/v1/security/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200 and me.json()["username"] == "admin"
        anon = client.get("/api/v1/security/me")
        assert anon.status_code == 401
        # Admin creates an analyst; analyst cannot create users.
        created = client.post("/api/v1/admin/users",
                              json={"username": "analyst1", "password": "Analyst-Long-Password!", "role": "analyst"},
                              headers={"Authorization": f"Bearer {token}"})
        assert created.status_code == 201, created.text
        analyst_login = client.post("/api/v1/auth/login", data={"username": "analyst1", "password": "Analyst-Long-Password!"})
        analyst_token = analyst_login.json()["access_token"]
        forbidden = client.post("/api/v1/admin/users",
                                json={"username": "x", "password": "X-Long-Password-123", "role": "analyst"},
                                headers={"Authorization": f"Bearer {analyst_token}"})
        assert forbidden.status_code == 403
        weak = client.post("/api/v1/admin/users",
                           json={"username": "weak", "password": "short", "role": "analyst"},
                           headers={"Authorization": f"Bearer {token}"})
        assert weak.status_code == 400
        chain = client.get("/api/v1/audit/chain", headers={"Authorization": f"Bearer {token}"})
        assert chain.status_code == 200 and len(chain.json()) >= 2
        verify = client.get("/api/v1/audit/chain/verify", headers={"Authorization": f"Bearer {token}"})
        assert verify.json() == {"valid": True, "first_invalid_event_id": None}
        # Existing M5 endpoints still work alongside auth.
        health = client.get("/health")
        assert health.json()["status"] == "ok"
