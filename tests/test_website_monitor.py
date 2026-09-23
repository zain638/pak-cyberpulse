"""Tests for the Website Monitor (modules/website_monitor.py)."""

from __future__ import annotations

import json
import time

import pytest

from modules import website_monitor as wm
from modules.website_monitor import (
    WebsiteMonitor,
    access_events,
    parse_access_log_line,
)

SAMPLE = (
    '203.0.113.9 - frank [22/Sep/2026:12:34:56 +0500] '
    '"GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
)


def test_parse_access_log_line():
    p = parse_access_log_line(SAMPLE)
    assert p is not None
    assert p["ip"] == "203.0.113.9"
    assert p["method"] == "GET"
    assert p["url"] == "/index.html"
    assert p["status"] == 200
    assert p["user"] == "frank"


def test_parse_unparseable_returns_none():
    assert parse_access_log_line("not a log line") is None
    assert parse_access_log_line("") is None


def test_access_events_http_req_tagged():
    p = parse_access_log_line(SAMPLE)
    evs = access_events("myshop", p)
    assert len(evs) == 1
    ev = evs[0]
    assert ev["event"] == "HTTP_REQ"
    assert ev["host"] == "myshop"
    assert ev["site"] == "myshop"
    assert ev["vector"] == "WEBSITE_MONITOR"
    assert "GET /index.html" in ev["msg"]


def test_access_events_auth_fail_on_login_403():
    line = (
        '203.0.113.9 - - [22/Sep/2026:12:34:56 +0500] '
        '"POST /wp-login.php HTTP/1.1" 403 1234 "-" "curl/8.0"'
    )
    evs = access_events("myshop", parse_access_log_line(line))
    kinds = {e["event"] for e in evs}
    assert kinds == {"HTTP_REQ", "AUTH_FAIL"}
    af = next(e for e in evs if e["event"] == "AUTH_FAIL")
    assert af["src_ip"] == "203.0.113.9"


def test_access_events_no_auth_fail_on_normal_403():
    line = (
        '203.0.113.9 - - [22/Sep/2026:12:34:56 +0500] '
        '"GET /favicon.ico HTTP/1.1" 403 10 "-" "curl/8.0"'
    )
    evs = access_events("myshop", parse_access_log_line(line))
    assert {e["event"] for e in evs} == {"HTTP_REQ"}


def test_db_website_roundtrip(tmp_db):
    sid = tmp_db.register_website("myshop", "/tmp/x.log", "note")
    sites = tmp_db.list_websites()
    assert len(sites) == 1 and sites[0]["name"] == "myshop"
    bid = tmp_db.record_website_block(sid, "myshop", "203.0.113.9",
                                      "reason", "APPLICATION-LAYER ACCESS CONTROL BLOCK", "d")
    blocks = tmp_db.list_website_blocks(site_id=sid)
    assert len(blocks) == 1 and blocks[0]["source_ip"] == "203.0.113.9"
    tmp_db.mark_block_unblocked(bid)
    assert tmp_db.list_website_blocks(site_id=sid) == []
    assert len(tmp_db.list_website_blocks(site_id=sid, include_unblocked=True)) == 1
    tmp_db.set_website_enabled(sid, False)
    assert tmp_db.list_websites()[0]["enabled"] == 0
    tmp_db.remove_website(sid)
    assert tmp_db.list_websites() == []


def test_register_rejects_missing_log(tmp_db, siem_ctx):
    mon = WebsiteMonitor(tmp_db, siem_ctx["engine"])
    with pytest.raises(ValueError):
        mon.register_site("ghost", "/nonexistent/access.log")


def test_e2e_detection_to_block_threshold(siem_ctx, tmp_path):
    """3 SECRET_IN_URL hits (alert-action pattern) from one IP ->
    watcher threshold fires -> contain_source_ip called -> block recorded."""
    db, engine = siem_ctx["db"], siem_ctx["engine"]
    mon = WebsiteMonitor(db, engine)
    logf = tmp_path / "access.log"
    logf.write_text("")
    sid = mon.register_site("myshop", str(logf))

    ip = "203.0.113.77"
    payloads = [
        "/?password=hunter2alpha",
        "/?api_key=ZZZ999secret",
        "/?token=abcdef123456",
    ]
    for pl in payloads:
        p = parse_access_log_line(
            f'{ip} - - [22/Sep/2026:12:34:56 +0500] "GET {pl} HTTP/1.1" 200 10 "-" "x"'
        )
        for ev in access_events("myshop", p):
            engine._process_line(json.dumps(ev))

    snap = engine.snapshot()
    assert len(snap["patterns"]) >= 3, snap["patterns"]

    mon._watch_once()

    blocks = db.list_website_blocks(site_id=sid)
    assert len(blocks) == 1
    assert blocks[0]["source_ip"] == ip
    # siem_ctx forces unprivileged -> application-layer ACL fallback on tmp ACL
    acl_text = siem_ctx["acl"].read_text()
    assert f"DENY {ip} " in acl_text
    assert len(mon.last_blocks) == 1
    assert mon.last_blocks[0]["ip"] == ip


def test_watcher_does_not_double_block(siem_ctx, tmp_path):
    """Second watcher pass must not create a second block row."""
    db, engine = siem_ctx["db"], siem_ctx["engine"]
    mon = WebsiteMonitor(db, engine)
    logf = tmp_path / "access.log"
    logf.write_text("")
    sid = mon.register_site("myshop", str(logf))
    ip = "203.0.113.78"
    for pl in ["/?password=aaa111", "/?password=bbb222", "/?password=ccc333"]:
        p = parse_access_log_line(
            f'{ip} - - [22/Sep/2026:12:34:56 +0500] "GET {pl} HTTP/1.1" 200 10 "-" "x"'
        )
        for ev in access_events("myshop", p):
            engine._process_line(json.dumps(ev))
    mon._watch_once()
    mon._watch_once()
    assert len(db.list_website_blocks(site_id=sid)) == 1


def test_unblock_removes_acl_lines(siem_ctx, tmp_path):
    db, engine = siem_ctx["db"], siem_ctx["engine"]
    mon = WebsiteMonitor(db, engine)
    logf = tmp_path / "access.log"
    logf.write_text("")
    sid = mon.register_site("myshop", str(logf))
    ip = "203.0.113.79"
    for pl in ["/?password=aaa111", "/?password=bbb222", "/?password=ccc333"]:
        p = parse_access_log_line(
            f'{ip} - - [22/Sep/2026:12:34:56 +0500] "GET {pl} HTTP/1.1" 200 10 "-" "x"'
        )
        for ev in access_events("myshop", p):
            engine._process_line(json.dumps(ev))
    mon._watch_once()
    blocks = db.list_website_blocks(site_id=sid)
    assert blocks
    res = mon.unblock_ip(int(blocks[0]["block_id"]))
    assert res["ok"]
    assert f"DENY {ip} " not in siem_ctx["acl"].read_text()
    assert db.list_website_blocks(site_id=sid) == []
