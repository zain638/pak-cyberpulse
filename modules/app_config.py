"""
Pak-CyberPulse centralized configuration & secrets.

Single home for every secret, key, and tunable path:

  - OTX API key:      env OTX_API_KEY wins, else DB setting "otx_api_key"
  - REST API token:   env PAKCYBER_API_TOKEN wins, else DB setting "api_token",
                      else the hard-coded DEMO token (flagged "change me")
  - Feature toggles:  DB settings (abusech_auto_refresh, require_login, ...)

Secrets are NEVER logged, NEVER rendered back into the UI, and NEVER
hardcoded outside the clearly-labeled demo fallbacks. Values supplied via
the Settings page are stored in the local SQLite DB (user's own machine).
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DESKTOP_LOG = Path.home() / ".pak-cyberpulse" / "desktop.log"

_DEMO_API_TOKEN = "DEMO-TOKEN-CHANGE-ME"

# All known setting keys with their defaults. Anything not listed here can
# still be stored via set_setting(), but the Settings page only manages
# these.
KNOWN_SETTINGS: dict[str, str] = {
    "otx_api_key": "",            # AlienVault OTX key (env OTX_API_KEY wins)
    "api_token": "",              # REST API token (env PAKCYBER_API_TOKEN wins)
    "abusech_auto_refresh": "1",  # 1 = refresh Abuse.ch feeds every 6h
    "require_login": "0",         # 1 = gate every panel behind RBAC login
}

_log_lock = threading.Lock()


def log_to_desktop(msg: str) -> None:
    """Append one timestamped line to ~/.pak-cyberpulse/desktop.log.

    Never raises. Secrets must never be passed in here — callers are
    responsible for redacting.
    """
    try:
        DESKTOP_LOG.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with _log_lock:
            with open(DESKTOP_LOG, "a", encoding="utf-8") as fh:
                fh.write(f"{ts} {msg}\n")
    except Exception:
        pass


def get_setting(key: str, default: str = "") -> str:
    try:
        from database.db_manager import get_db

        val = get_db().get_setting(key)
        return default if val is None else val
    except Exception:
        return default


def set_setting(key: str, value: str) -> None:
    from database.db_manager import get_db

    get_db().set_setting(key, value)


def get_otx_api_key() -> str:
    """Env OTX_API_KEY wins; falls back to the DB setting; else empty."""
    env = (os.environ.get("OTX_API_KEY") or "").strip()
    if env:
        return env
    return get_setting("otx_api_key", "")


def otx_key_source() -> str:
    if (os.environ.get("OTX_API_KEY") or "").strip():
        return "environment"
    if get_setting("otx_api_key", ""):
        return "settings"
    return "none"


def get_api_token() -> str:
    """Env PAKCYBER_API_TOKEN wins; else DB setting; else DEMO fallback."""
    env = (os.environ.get("PAKCYBER_API_TOKEN") or "").strip()
    if env:
        return env
    dbv = get_setting("api_token", "").strip()
    if dbv:
        return dbv
    return _DEMO_API_TOKEN


def api_token_status() -> dict[str, str]:
    """Honest status for the Settings page / startup log."""
    if (os.environ.get("PAKCYBER_API_TOKEN") or "").strip():
        return {"mode": "custom", "source": "environment",
                "note": "Custom API token active (from environment)."}
    if get_setting("api_token", "").strip():
        return {"mode": "custom", "source": "settings",
                "note": "Custom API token active (from Settings page)."}
    return {"mode": "demo", "source": "built-in",
            "note": "⚠ DEMO API token active (DEMO-TOKEN-CHANGE-ME) — "
                    "change me: set PAKCYBER_API_TOKEN or configure one in Settings."}


def warn_if_demo_credentials() -> list[str]:
    """Startup warnings for anything still on demo credentials. Never raises."""
    warnings: list[str] = []
    try:
        if api_token_status()["mode"] == "demo":
            warnings.append(
                "REST API is using the DEMO token — set PAKCYBER_API_TOKEN "
                "or configure api_token in Settings before any pilot."
            )
        if otx_key_source() == "none":
            warnings.append(
                "No OTX API key configured — threat intel falls back to "
                "SIMULATED feeds (honestly labeled in the UI)."
            )
        if get_setting("require_login", "0") != "1":
            warnings.append(
                "Login is not required (require_login=0) — any local user can "
                "open every panel. Enable require_login in Settings for production."
            )
    except Exception:
        pass
    return warnings
