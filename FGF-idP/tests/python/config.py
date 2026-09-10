"""Test configuration loader for FGF-idP HTTP tests."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def _load_env_file() -> dict[str, str]:
    """Load a simple .env file (KEY=VALUE) into a dict if present."""
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return {}

    env_map: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, raw = line.split("=", 1)
        key = key.strip()
        value = raw.strip().strip('"').strip("'")
        env_map[key] = value
    return env_map


_ENV_FILE_CACHE = _load_env_file()


def _get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    if name in os.environ:
        return os.environ.get(name, default)
    return _ENV_FILE_CACHE.get(name, default)


@dataclass
class TestConfig:
    base_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    frontend_base_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    prebuilt_auth_code: Optional[str] = None
    prebuilt_access_token: Optional[str] = None
    prebuilt_verify_token: Optional[str] = None

    @classmethod
    def load(cls) -> "TestConfig":
        base_url = _get_env("BACKEND_BASE_URL", "http://localhost:3000").rstrip("/")
        client_id = _get_env("TEST_CLIENT_ID", "fgf-mc-panel")
        client_secret = _get_env("TEST_CLIENT_SECRET", "")
        redirect_uri = _get_env("TEST_REDIRECT_URI", "http://localhost:3000/callback")
        frontend_base_url = (_get_env("FRONTEND_BASE_URL", "http://localhost:3000") or "http://localhost:3000").rstrip("/")
        return cls(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            frontend_base_url=frontend_base_url,
            username=_get_env("TEST_USERNAME"),
            password=_get_env("TEST_PASSWORD"),
            prebuilt_auth_code=_get_env("TEST_AUTH_CODE"),
            prebuilt_access_token=_get_env("TEST_ACCESS_TOKEN"),
            prebuilt_verify_token=_get_env("TEST_VERIFY_TOKEN"),
        )
