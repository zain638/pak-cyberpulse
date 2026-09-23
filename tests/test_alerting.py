"""Dispatch, dedup and honest-failure tests for modules/alerting.py."""

import json
import smtplib
import urllib.request

import pytest

from modules.alerting import AlertDispatcher


def _alert(sev="Critical", title="Test alert"):
    return {
        "severity": sev,
        "title": title,
        "body": "body text",
        "destinations": {
            "email": ["soc@example.pk"],
            "webhook": ["https://example.pk/hook"],
        },
    }


def _boom(*a, **k):
    raise AssertionError("network path must not be reached in dry-run mode")


def test_dry_run_dispatch_touches_no_socket(tmp_db, monkeypatch):
    """Dry-run must return mode=dry_run without ever hitting SMTP/HTTP."""
    monkeypatch.setattr(smtplib, "SMTP", _boom)
    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    disp = AlertDispatcher(db=tmp_db, dry_run=True)

    records = disp.dispatch(_alert())
    assert records, "Critical routes to email+webhook"
    assert all(r["mode"] == "dry_run" for r in records)
    assert all(r["ok"] is True for r in records)
    statuses = {row["status"] for row in disp.fetch_log()}
    assert statuses == {"dry_run"}


def test_dedup_suppresses_second_identical_dispatch(tmp_db):
    disp = AlertDispatcher(db=tmp_db, dry_run=True)
    first = disp.dispatch(_alert(sev="Medium", title="Dedup probe"))
    assert first and not any(r.get("suppressed") for r in first)

    second = disp.dispatch(_alert(sev="Medium", title="Dedup probe"))
    assert len(second) == 1
    assert second[0]["suppressed"] is True
    assert second[0]["reason"] == "deduped"

    statuses = [row["status"] for row in disp.fetch_log()]
    assert "deduped" in statuses


def test_live_webhook_to_closed_port_fails_honestly(tmp_db, monkeypatch):
    """A live POST to a dead port must record failed + error text, not hang."""
    for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(var, raising=False)
    disp = AlertDispatcher(db=tmp_db, dry_run=False)
    rec = disp.send_webhook("http://127.0.0.1:9/hook", {"title": "probe"}, timeout=3)
    assert rec["ok"] is False
    assert rec["error"], "error text must be present"
    last = disp.fetch_log(limit=1)[0]
    assert last["status"] == "failed"
    assert last["channel"] == "webhook"


def test_live_email_to_closed_port_fails_honestly(tmp_db):
    disp = AlertDispatcher(
        db=tmp_db, dry_run=False, smtp_host="127.0.0.1", smtp_port=9
    )
    rec = disp.send_email("soc@example.pk", "subject", "body", dry_run=False)
    assert rec["ok"] is False and rec["mode"] == "live"
    assert rec["error"]
    last = disp.fetch_log(limit=1)[0]
    assert last["status"] == "failed"
    assert last["channel"] == "email"


def test_dispatch_log_records_delivery_detail(tmp_db):
    disp = AlertDispatcher(db=tmp_db, dry_run=True)
    disp.dispatch(_alert(sev="Low", title="low-probe"))  # Low routes nowhere
    disp.dispatch(_alert(sev="High", title="high-probe"))
    rows = disp.fetch_log()
    assert any(r["title"] == "high-probe" and r["status"] == "dry_run" for r in rows)
    detail = json.loads(
        next(r["detail"] for r in rows if r["title"] == "high-probe")
    )
    assert detail.get("mode") == "dry_run"
