"""Real-behavior tests for modules/siem_panel.py SIEMEngine.

The engine is instantiated WITHOUT start() (no tailer thread); crafted JSONL
lines are fed through _process_line(). The siem_ctx fixture isolates every
external boundary: get_db -> tmp DB, ACL_PATH -> tmp file, privilege probe ->
forced unprivileged, airgap trigger -> no-op.
"""

import json
import time
from collections import deque
from datetime import datetime, timedelta, timezone

import pytest

from database.db_manager import STATUS_UNDER_ATTACK
from modules import siem_panel


def _line(event, ip, user, ts, msg="probe", host="MOITT-PORTAL", asset="Standard"):
    iso = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    return json.dumps(
        {
            "ts": ts,
            "iso": iso,
            "event": event,
            "user": user,
            "src_ip": ip,
            "host": host,
            "asset_class": asset,
            "msg": msg,
        }
    )


def _fail_lines(ip, user, n, spacing=5.0, host="NADRA-IDC-ISB", asset="CII"):
    now = time.time()
    return [
        _line(
            "AUTH_FAIL",
            ip,
            user,
            now - (n - 1 - i) * spacing,
            msg=f"sshd: Failed password for {user} from {ip}",
            host=host,
            asset=asset,
        )
        for i in range(n)
    ]


def test_bruteforce_window_fires_at_10_fails(siem_ctx):
    engine, db, acl = siem_ctx["engine"], siem_ctx["db"], siem_ctx["acl"]
    ip, user = "198.51.100.10", "bf.target"
    for line in _fail_lines(ip, user, 10):
        engine._process_line(line, replay=False)

    attack_id = f"{ip}/{user}"
    assert attack_id in engine.active_attacks
    record = engine.active_attacks[attack_id]
    assert record["count"] >= 10
    assert record["rule"].startswith("PISF-05.2")
    # The firing must also promote the IAM control on the (tmp) DB.
    status = {
        c["control_id"]: c["status"] for c in db.fetch_controls()
    }["PISF-05.2"]
    assert status == STATUS_UNDER_ATTACK
    # And the automated containment must have written a DENY to the tmp ACL.
    assert f"DENY {ip}" in acl.read_text(encoding="utf-8")


def test_bruteforce_window_does_not_fire_at_9_fails(siem_ctx):
    engine = siem_ctx["engine"]
    ip, user = "198.51.100.11", "bf.almost"
    for line in _fail_lines(ip, user, 9):
        engine._process_line(line, replay=False)

    assert f"{ip}/{user}" not in engine.active_attacks
    assert len(engine.fail_windows[(ip, user)]) == 9


def test_bruteforce_is_per_ip_user_tuple(siem_ctx):
    """10 fails spread across 10 different users must NOT trip the window."""
    engine = siem_ctx["engine"]
    ip = "198.51.100.12"
    now = time.time()
    for i in range(10):
        engine._process_line(
            _line("AUTH_FAIL", ip, f"user{i}", now - i * 5,
                  msg=f"sshd: Failed password for user{i} from {ip}"),
            replay=False,
        )
    assert not engine.active_attacks


def test_sqli_and_xss_signature_detection(siem_ctx):
    engine = siem_ctx["engine"]
    ip = "198.51.100.13"
    engine._process_line(
        _line(
            "HTTP_REQ",
            ip,
            "portal.admin",
            time.time(),
            msg="GET /login?user=admin' OR '1'='1 <script>alert(1)</script> HTTP/1.1",
        ),
        replay=False,
    )
    sig_hits = [h for h in engine.injection_hits if h["src_ip"] == ip]
    assert sig_hits, "injection buffer must record the hit"
    assert "SQLi" in sig_hits[0]["signatures"]
    assert "XSS" in sig_hits[0]["signatures"]
    pat_ids = {h["pattern_id"] for h in engine.pattern_hits if h["src_ip"] == ip}
    assert {"SQLI", "XSS"} <= pat_ids


def test_ueba_new_ip_and_off_hours_anomaly(siem_ctx):
    engine = siem_ctx["engine"]
    user, office_ip, evil_ip = "ueba.test", "10.10.8.44", "185.220.101.99"
    # Baseline: 12 morning (09:00 UTC) logins from the office IP — replay only trains.
    day = datetime.now(timezone.utc).replace(hour=9, minute=10, second=0, microsecond=0)
    base_ts = day.timestamp()
    for i in range(12):
        engine._process_line(
            _line("AUTH_OK", office_ip, user, base_ts - (12 - i) * 5,
                  msg=f"sshd: Accepted publickey for {user} from {office_ip}"),
            replay=True,
        )
    assert not engine.anomaly_hits, "replay must train, never fire"

    # Trigger: 03:00 UTC login from a never-seen IP.
    evil_dt = datetime.now(timezone.utc).replace(hour=3, minute=7, second=0, microsecond=0)
    engine._process_line(
        _line("AUTH_OK", evil_ip, user, evil_dt.timestamp(),
              msg=f"sshd: Accepted publickey for {user} from {evil_ip}"),
        replay=False,
    )
    kinds = {h["kind"] for h in engine.anomaly_hits if h["user"] == user}
    assert kinds == {"NEW_IP", "OFF_HOURS"}


def test_telemetry_gap_fires_on_ingest_collapse(siem_ctx):
    engine = siem_ctx["engine"]
    m = int(time.time() // 60)
    # Honest v3: feed REAL event timestamps — 5 healthy minutes at 20 ev/min,
    # then the current minute collapsed to 1 event.
    now = m * 60 + 59.5
    for mm in range(m - 5, m):
        for i in range(20):
            engine.event_timestamps.append(mm * 60 + i)
    engine.event_timestamps.append(now - 5)
    engine._check_telemetry_gap(now)

    hits = [h for h in engine.pattern_hits if h["pattern_id"] == "TELEMETRY_GAP"]
    assert len(hits) == 1
    assert "1/min" in hits[0]["matched"] and "20/min" in hits[0]["matched"]
    # Dedup: calling again for the same minute must not re-fire.
    engine._check_telemetry_gap(now + 0.1)
    assert len([h for h in engine.pattern_hits if h["pattern_id"] == "TELEMETRY_GAP"]) == 1


def test_telemetry_gap_quiet_on_steady_rate(siem_ctx):
    engine = siem_ctx["engine"]
    m = int(time.time() // 60)
    now = m * 60 + 59.5
    for mm in range(m - 6, m + 1):
        for i in range(20):
            engine.event_timestamps.append(mm * 60 + i)
    engine._check_telemetry_gap(now)
    assert not [h for h in engine.pattern_hits if h["pattern_id"] == "TELEMETRY_GAP"]


def test_password_spray_pattern_fires(siem_ctx):
    engine = siem_ctx["engine"]
    ip = "198.51.100.77"
    now = time.time()
    n = 0
    for i in range(8):  # 8 users x 2 fails each, inside 120s
        for _ in range(2):
            engine._process_line(
                _line("AUTH_FAIL", ip, f"spray.u{i}", now - (16 - n) * 4,
                      msg=f"sshd: Failed password for spray.u{i} from {ip}"),
                replay=False,
            )
            n += 1
    pat_ids = {h["pattern_id"] for h in engine.pattern_hits}
    assert "PASSWORD_SPRAY" in pat_ids


def test_impossible_travel_fires(siem_ctx):
    engine = siem_ctx["engine"]
    user = "travel.test"
    now = time.time()
    engine._process_line(
        _line("AUTH_OK", "103.255.4.18", user, now - 300,
              msg=f"sshd: Accepted publickey for {user} from 103.255.4.18"),
        replay=False,
    )
    engine._process_line(
        _line("AUTH_OK", "172.58.91.200", user, now,
              msg=f"sshd: Accepted publickey for {user} from 172.58.91.200"),
        replay=False,
    )
    pat_ids = {h["pattern_id"] for h in engine.pattern_hits}
    assert "IMPOSSIBLE_TRAVEL" in pat_ids
