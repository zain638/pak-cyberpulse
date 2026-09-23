"""HTTP-level tests for modules/rest_api.py via FastAPI TestClient.

Auth behavior and status codes are the real behavior under test. The
endpoints read from the app's own DB surface (read-only GETs); no writes
are performed by any request below.
"""

from fastapi.testclient import TestClient

from modules.rest_api import app

TOKEN = "DEMO-TOKEN-CHANGE-ME"
AUTH = {"Authorization": f"Bearer {TOKEN}"}

client = TestClient(app)


def test_health_is_public_and_ok():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["service"] == "pak-cyberpulse-api"


def test_alerts_requires_token():
    assert client.get("/alerts").status_code == 401
    r = client.get("/alerts", headers=AUTH)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_alerts_rejects_bad_token():
    r = client.get("/alerts", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_cases_status_filter():
    r = client.get("/cases", params={"status": "open"}, headers=AUTH)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    r2 = client.get("/cases", headers=AUTH)
    assert r2.status_code == 200


def test_ti_iocs_query():
    r = client.get("/ti/iocs", params={"q": "203.0.113"}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert "matches" in body and "stale_feeds" in body
    r2 = client.get("/ti/iocs", headers=AUTH)
    assert r2.status_code == 200 and isinstance(r2.json(), list)


def test_protected_routes_reject_missing_token():
    for path in ("/cases", "/ti/iocs"):
        assert client.get(path).status_code == 401


def test_anomalies_requires_token():
    assert client.get("/anomalies").status_code == 401
    r = client.get("/anomalies", headers=AUTH)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_anomalies_route_registered_before_main_block():
    # Regression: /anomalies must be registered at import time, not after
    # the `if __name__ == "__main__": uvicorn.run(...)` block.
    paths = {route.path for route in app.routes}
    assert "/anomalies" in paths


def test_health_reports_auth_mode_honestly():
    """v7: /health stays public but reports whether a custom token is set."""
    import os

    from modules.rest_api import _auth_mode

    os.environ.pop("PAKCYBER_API_TOKEN", None)
    assert _auth_mode() in ("demo-token-change-me", "custom-settings")
    os.environ["PAKCYBER_API_TOKEN"] = "env-token-for-test"
    try:
        assert _auth_mode() == "custom-env"
        body = client.get("/health").json()
        assert body["auth_mode"] == "custom-env"
    finally:
        del os.environ["PAKCYBER_API_TOKEN"]
    body = client.get("/health").json()
    assert body["auth_mode"] in ("demo-token-change-me", "custom-settings")


def test_valid_tokens_includes_db_token(tmp_db, monkeypatch):
    """v7: a token configured via Settings (SQLite) is accepted by the API."""
    import os

    monkeypatch.setattr("database.db_manager.get_db", lambda: tmp_db)
    monkeypatch.delenv("PAKCYBER_API_TOKEN", raising=False)
    tmp_db.set_setting("api_token", "settings-token-abc")
    from modules import rest_api

    tokens = rest_api._valid_tokens()
    assert "settings-token-abc" in tokens
    assert "DEMO-TOKEN-CHANGE-ME" in tokens  # fallback retained, flagged
    r = client.get("/alerts", headers={"Authorization": "Bearer settings-token-abc"})
    assert r.status_code == 200


def test_websites_ingest_requires_token():
    r = client.post("/websites/ingest", json={"site": "x", "lines": []})
    assert r.status_code in (401, 403)  # no bearer -> rejected before 503


def test_websites_ingest_503_without_running_app():
    """v7: honest 503 when the desktop app's monitor singleton isn't up."""
    from modules.website_monitor import get_website_monitor

    assert get_website_monitor() is None
    r = client.post(
        "/websites/ingest", json={"site": "x", "lines": ["a line"]}, headers=AUTH
    )
    assert r.status_code == 503
    assert "not running" in r.json()["detail"]


def test_websites_ingest_end_to_end_with_monitor(tmp_db, monkeypatch):
    """v7: with the monitor singleton running, lines are ingested for the site."""
    import modules.website_monitor as wm

    monkeypatch.setattr("database.db_manager.get_db", lambda: tmp_db)

    class _Engine:
        def __init__(self):
            self.events = []

        def append_event(self, ev):
            self.events.append(ev)

    eng = _Engine()
    mon = wm.WebsiteMonitor(tmp_db, eng)
    tmp_db.register_website("restsite", "/tmp/does-not-matter.log", "")
    monkeypatch.setattr(wm, "_MONITOR", mon)
    line = (
        '198.51.100.7 - - [22/Sep/2026:11:00:00 +0000] '
        '"GET /index.html HTTP/1.1" 200 512'
    )
    r = client.post(
        "/websites/ingest",
        json={"site": "restsite", "lines": [line, "garbage"]},
        headers=AUTH,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["parsed"] == 1 and body["skipped"] == 1
    assert any(e.get("event") == "HTTP_REQ" for e in eng.events)

    r2 = client.post(
        "/websites/ingest",
        json={"site": "no-such-site", "lines": [line]},
        headers=AUTH,
    )
    assert r2.status_code == 404
