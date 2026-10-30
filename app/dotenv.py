"""Minimal .env loader (no new dependency).

The v1 instructions tell users to copy .env.example to .env and put
their secrets there, but the original code only read os.environ — so
a user following the instructions exactly got a 500 on login, because
TRACE_LAB_JWT_SECRET was never loaded. This loader reads KEY=VALUE
lines from <project root>/.env (and ./data's parent is not used) and
fills os.environ only for keys not already set in the real environment.
Real environment variables always win over .env values.
"""
import os
from pathlib import Path

_LOADED = False


def load_dotenv() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)
