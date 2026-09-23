"""
Pak-CyberPulse REST API — machine interface to incidents, cases, and threat intel.

Run from the project directory (01_Software_Project/pak-cyberpulse):

    uvicorn modules.rest_api:app --host 0.0.0.0 --port 8000

Auth: HTTP Bearer token. Valid tokens are, in priority order:
  1. the PAKCYBER_API_TOKEN environment variable (when set and non-empty),
  2. the api_token configured in Settings (stored in the local SQLite DB),
  3. the built-in DEMO token (DEMO-TOKEN-CHANGE-ME) — flagged "change me"
     in the Settings page and in /health. /health is public.

This module must import cleanly with NO streamlit side effects — streamlit is
not imported here at all.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field


app = FastAPI(title="Pak-CyberPulse API")

_bearer = HTTPBearer(auto_error=False)

_DEMO_TOKEN = "DEMO-TOKEN-CHANGE-ME"


def _valid_tokens() -> set:
    tokens = set()
    env = os.environ.get("PAKCYBER_API_TOKEN", "").strip()
    if env:
        tokens.add(env)
    try:
        from modules.app_config import get_setting

        dbv = (get_setting("api_token", "") or "").strip()
        if dbv:
            tokens.add(dbv)
    except Exception:
        pass
    tokens.add(_DEMO_TOKEN)
    return tokens


def _auth_mode() -> str:
    """Honest label for /health: where the effective token comes from."""
    if os.environ.get("PAKCYBER_API_TOKEN", "").strip():
        return "custom-env"
    try:
        from modules.app_config import get_setting

        if (get_setting("api_token", "") or "").strip():
            return "custom-settings"
    except Exception:
        pass
    return "demo-token-change-me"


def require_token(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> str:
    if creds is None or not creds.credentials or creds.credentials not in _valid_tokens():
        raise HTTPException(status_code=401, detail="Invalid or missing API token")
    return creds.credentials


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class WebsiteIngestBody(BaseModel):
    """v7: ship access-log lines for a registered site over HTTP.

    site: registered website name or numeric id.
    lines: raw access-log lines (Combined Log Format), max 5000 per call.
    """

    site: str
    lines: List[str]


@app.get("/health")
def health() -> Dict[str, str]:
    """Public liveness probe — no auth required."""
    return {"status": "ok", "service": "pak-cyberpulse-api", "time": _utc_iso(),
            "auth_mode": _auth_mode()}


@app.get("/alerts")
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    token: str = Depends(require_token),
) -> List[Dict[str, Any]]:
    """Recent incidents from the detection ledger (auth required)."""
    from database.db_manager import get_db

    return get_db().fetch_incidents(limit=limit)


@app.get("/cases")
def list_cases(
    status: Optional[str] = None,
    token: str = Depends(require_token),
) -> Any:
    """Case queue via the case manager (auth required)."""
    from modules.case_manager import CaseManager

    return CaseManager().list_cases(status=status)


@app.get("/ti/iocs")
def search_iocs(
    q: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    token: str = Depends(require_token),
) -> Any:
    """IOC lookup via the threat-intel store (auth required).

    With ?q=, returns the enrichment record for that indicator value;
    without it, lists recent IOCs.
    """
    from modules.threat_intel import TIStore

    ti = TIStore()
    if q:
        return ti.enrich(q)
    return ti.list_iocs(limit=limit)


@app.get("/anomalies")
def list_anomalies(
    limit: int = Query(50, ge=1, le=500),
    token: str = Depends(require_token),
) -> List[Dict[str, Any]]:
    """ML anomaly incidents from the detection ledger (auth required).

    The v4 anomaly engine records High/Critical anomalies as incidents with
    classification 'ML_ANOMALY:<detector>' — this endpoint surfaces them.
    (The live in-memory detector belongs to the Streamlit process; the
    ledger is the honest cross-process source.)
    """
    from database.db_manager import get_db

    rows = get_db().fetch_incidents(limit=500)
    ml = [r for r in rows if str(r.get("classification", "")).startswith("ML_ANOMALY")]
    return ml[:limit]


@app.post("/websites/ingest")
def ingest_website_lines(
    body: WebsiteIngestBody,
    token: str = Depends(require_token),
) -> Dict[str, Any]:
    """v7: per-site HTTP log ingest (auth required).

    Ships raw access-log lines for an already-registered website — for
    remote servers that cannot expose a local log file. Lines run through
    the identical parse -> SIEM-event -> stats pipeline as the file tailer,
    so detection thresholds and auto-block behave the same. The site record
    keeps persistent ingest-source metadata ('file', 'file+http', ...).

    Requires the desktop app (website monitor singleton) to be running;
    otherwise returns 503 with an honest reason.
    """
    from modules.website_monitor import get_website_monitor

    mon = get_website_monitor()
    if mon is None:
        raise HTTPException(
            status_code=503,
            detail="website monitor is not running — start the Pak-CyberPulse "
                   "desktop app first",
        )
    if not body.site or not body.site.strip():
        raise HTTPException(status_code=422, detail="site is required")
    result = mon.ingest_lines(body.site, body.lines or [])
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
