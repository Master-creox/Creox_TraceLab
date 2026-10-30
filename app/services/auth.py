"""M6 security layer, integrated into the M5 app WITHOUT replacing it.

This keeps every M1-M5 endpoint and table untouched and adds, on top:
- users table (admin / analyst roles, Argon2 password hashes)
- JWT login (30 min, HS256) — secret read from TRACE_LAB_JWT_SECRET
  at call time, so tests can set it; a short/placeholder secret is
  refused at login time, never silently accepted.
- hash-chained audit_chain table (separate from the existing
  audit_events table, which is left alone) for auth/admin events.

Deliberately NOT in this integration step: forcing auth on every
existing endpoint (that would break the M5 dashboard, which has no
login UI yet), and Fernet encrypted evidence (M6's version reads a
whole file into memory; the M1 streaming vault stays as-is).
Those are the next two steps, not silent changes here.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from app.database import get_db, utc_now

GENESIS = "0" * 64
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def _jwt_secret() -> str:
    secret = os.getenv("TRACE_LAB_JWT_SECRET", "CHANGE_ME")
    if secret == "CHANGE_ME" or len(secret) < 32:
        raise HTTPException(
            status_code=500,
            detail="Set a strong TRACE_LAB_JWT_SECRET (32+ chars) before using auth",
        )
    return secret


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    from passlib.context import CryptContext

    return CryptContext(schemes=["argon2"], deprecated="auto").hash(password)


def verify_password(password: str, hashed: str) -> bool:
    from passlib.context import CryptContext

    return CryptContext(schemes=["argon2"], deprecated="auto").verify(password, hashed)


def create_access_token(username: str, role: str) -> str:
    from jose import jwt

    expires = datetime.now(timezone.utc) + timedelta(minutes=30)
    return jwt.encode(
        {"sub": username, "role": role, "exp": expires},
        _jwt_secret(),
        algorithm="HS256",
    )


def _chain_digest(actor: str, action: str, detail: str, created_at: str, previous: str) -> str:
    payload = "|".join([actor, action, detail, created_at, previous])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_chain_event(actor: str, action: str, detail: str = "", conn=None) -> dict:
    """Append one hash-chained audit event; returns the stored row.

    Pass the caller's connection when already inside a write
    transaction — opening a second writer against the same SQLite
    database deadlocks with "database is locked". With no connection
    given, it opens (and commits) its own.
    """
    if conn is not None:
        previous = conn.execute(
            "SELECT event_hash FROM audit_chain ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else GENESIS
        created_at = utc_now()
        event_hash = _chain_digest(actor, action, detail, created_at, previous_hash)
        cursor = conn.execute(
            "INSERT INTO audit_chain(actor, action, detail, created_at, previous_hash, event_hash)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (actor, action, detail, created_at, previous_hash, event_hash),
        )
        row = conn.execute(
            "SELECT * FROM audit_chain WHERE id=?", (cursor.lastrowid,)
        ).fetchone()
        return dict(row)
    with get_db() as own_conn:
        return record_chain_event(actor, action, detail, conn=own_conn)


def verify_chain() -> tuple[bool, int | None]:
    with get_db() as conn:
        previous_hash = GENESIS
        for row in conn.execute(
            "SELECT * FROM audit_chain ORDER BY id ASC"
        ).fetchall():
            expected = _chain_digest(
                row["actor"], row["action"], row["detail"],
                row["created_at"], previous_hash,
            )
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return False, row["id"]
            previous_hash = row["event_hash"]
    return True, None


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    from jose import JWTError, jwt

    error = HTTPException(
        status_code=401,
        detail="Invalid or expired credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            raise error
    except JWTError:
        raise error
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
        ).fetchone()
        if row is None:
            raise error
        return dict(row)


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user
