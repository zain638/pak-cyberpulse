"""Tests for modules/anomaly_engine.py (v4 statistical ML layer)."""

from __future__ import annotations

import time

import pytest

from modules.anomaly_engine import (
    AnomalyDetector,
    EWMAAnomalyDetector,
    UserBehaviorBaseline,
    entropy_outliers,
    fire_anomaly_demo,
    modified_zscore_outliers,
    shannon_entropy,
    zscore_outliers,
)


# ---------------------------------------------------------------------------
# Pure primitives
# ---------------------------------------------------------------------------

def test_zscore_flags_clear_outlier():
    vals = [10.0] * 20 + [100.0]
    out = zscore_outliers(vals, threshold=3.0)
    assert len(out) == 1
    idx, val, z = out[0]
    assert idx == 20 and val == 100.0 and z > 3.0


def test_zscore_empty_on_flat_data():
    assert zscore_outliers([5.0, 5.0, 5.0, 5.0]) == []


def test_zscore_needs_minimum_samples():
    assert zscore_outliers([1.0, 100.0]) == []


def test_zscore_no_false_positive_on_normal_spread():
    vals = [9.8, 10.1, 10.0, 9.9, 10.2, 9.7, 10.0, 10.1, 9.9, 10.0]
    assert zscore_outliers(vals) == []


def test_modified_zscore_catches_masked_outlier():
    # Masking demo: the two big values inflate mean/std so the classic
    # z-score misses them, but the MAD-based modified z-score catches them.
    vals = [10.0, 11.0, 9.0, 10.0, 12.0, 10.0, 11.0, 9.0, 90.0, 95.0]
    assert zscore_outliers(vals, threshold=3.0) == []  # masked by inflated std
    flagged = {v for _, v, _ in modified_zscore_outliers(vals, threshold=3.5)}
    assert 90.0 in flagged and 95.0 in flagged


def test_modified_zscore_flat_data():
    assert modified_zscore_outliers([3.0, 3.0, 3.0, 3.0, 3.0]) == []


def test_shannon_entropy_ordering():
    low = shannon_entropy("intranet-portal")
    high = shannon_entropy("x7qz9vm2krtp4w")
    assert high > low
    assert shannon_entropy("") == 0.0


def test_entropy_outliers_flags_random_string():
    strings = ["mail-server", "intranet-portal", "q7wzx9k2m4pva8s6d3f"]
    out = entropy_outliers(strings, threshold_bits=4.0)
    assert len(out) == 1 and out[0][1] == "q7wzx9k2m4pva8s6d3f"
    assert out[0][2] >= 4.0


def test_entropy_outliers_clean_list():
    assert entropy_outliers(["web", "mail", "db-primary"], threshold_bits=4.0) == []


# ---------------------------------------------------------------------------
# EWMA streaming detector
# ---------------------------------------------------------------------------

def test_ewma_learns_baseline_without_firing():
    det = EWMAAnomalyDetector(alpha=0.3, threshold=3.0, warmup=10)
    fired = [det.update(10.0 + (i % 3)) for i in range(30)]
    assert not any(f for f, _ in fired)


def test_ewma_fires_on_spike():
    det = EWMAAnomalyDetector(alpha=0.3, threshold=3.0, warmup=10)
    for _ in range(30):
        det.update(10.0)
    spike, z = det.update(60.0)
    assert spike and z >= 3.0


def test_ewma_ignores_dips():
    det = EWMAAnomalyDetector(alpha=0.3, threshold=3.0, warmup=10)
    for _ in range(30):
        det.update(10.0)
    spike, _ = det.update(0.5)  # one-sided: dips are not spikes
    assert not spike


# ---------------------------------------------------------------------------
# UEBA-lite baseline
# ---------------------------------------------------------------------------

def _auth_ok(user, ip, hour, day_offset=1):
    base = time.time() - day_offset * 86400
    import datetime as _dt

    dt = _dt.datetime.fromtimestamp(base, tz=_dt.timezone.utc).replace(
        hour=hour, minute=0, second=0, microsecond=0
    )
    ts = dt.timestamp()
    return {
        "ts": ts, "event": "AUTH_OK", "user": user,
        "src_ip": ip, "host": "WS-01",
    }


def test_ueba_learning_below_minimum_scores_zero():
    base = UserBehaviorBaseline()
    ev = _auth_ok("newbie", "10.0.0.1", 9)
    score, expl = base.risk_score("newbie", ev)  # no training yet
    assert score == 0.0 and expl == []


def test_ueba_new_ip_and_off_hours():
    base = UserBehaviorBaseline()
    for _ in range(8):
        base.observe(_auth_ok("alice", "10.0.0.5", 9))
    evil = _auth_ok("alice", "185.220.9.9", 3, day_offset=0)
    score, expl = base.risk_score("alice", evil)
    assert score >= 35.0
    text = " ".join(expl)
    assert "New source IP" in text and "Off-hours" in text


def test_ueba_normal_login_scores_zero():
    base = UserBehaviorBaseline()
    for _ in range(8):
        base.observe(_auth_ok("bob", "10.0.0.6", 9))
    normal = _auth_ok("bob", "10.0.0.6", 9, day_offset=0)
    score, _ = base.risk_score("bob", normal)
    assert score == 0.0


def test_ueba_fail_ratio_contributes():
    base = UserBehaviorBaseline()
    for _ in range(8):
        base.observe(_auth_ok("carol", "10.0.0.7", 9))
    for _ in range(10):
        base.observe({"event": "AUTH_FAIL", "user": "carol",
                      "src_ip": "10.0.0.7", "host": "WS-01", "ts": time.time()})
    ev = _auth_ok("carol", "10.0.0.7", 9, day_offset=0)
    score, expl = base.risk_score("carol", ev)
    assert score > 0
    assert any("failure ratio" in e for e in expl)


def test_ueba_scoring_does_not_train():
    base = UserBehaviorBaseline()
    for _ in range(8):
        base.observe(_auth_ok("dave", "10.0.0.8", 9))
    before = base.user_risk_table()[0]["logins_observed"]
    base.risk_score("dave", _auth_ok("dave", "1.2.3.4", 3, day_offset=0))
    after = base.user_risk_table()[0]["logins_observed"]
    assert before == after  # scoring must not poison the baseline


def test_ueba_risk_table_sorted():
    base = UserBehaviorBaseline()
    for _ in range(6):
        base.observe(_auth_ok("low", "10.0.0.1", 9))
    for _ in range(6):
        base.observe(_auth_ok("high", "10.0.0.2", 9))
    for _ in range(10):
        base.observe({"event": "AUTH_FAIL", "user": "high",
                      "src_ip": "10.0.0.2", "host": "WS-01", "ts": time.time()})
    table = base.user_risk_table()
    assert table[0]["user"] == "high"
    assert all("baseline_trusted" in r for r in table)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def test_detector_records_ueba_anomaly_with_explanation():
    det = AnomalyDetector()
    for _ in range(10):
        det.process_event(_auth_ok("erin", "10.0.0.9", 9))
    evil = _auth_ok("erin", "203.0.113.99", 3, day_offset=0)
    out = det.process_event(evil)
    assert len(out) >= 1
    a = out[0]
    assert a["detector"] == "UEBA user-risk"
    assert a["score"] >= 40
    assert a["severity"] in {"Medium", "High", "Critical"}
    assert "New source IP" in a["explanation"]
    assert det.recent_anomalies(10)


def test_detector_dedupes_identical_anomalies():
    det = AnomalyDetector()
    for _ in range(10):
        det.process_event(_auth_ok("frank", "10.0.0.10", 9))
    evil = _auth_ok("frank", "203.0.113.100", 3, day_offset=0)
    det.process_event(evil)
    det.process_event(dict(evil))  # same event twice
    kinds = [a["detector"] for a in det.recent_anomalies(50)]
    assert kinds.count("UEBA user-risk") == 1


def test_detector_ignores_malformed_event():
    det = AnomalyDetector()
    assert det.process_event("not-a-dict") == []
    assert det.process_event({}) == []


def test_detector_stats_shape():
    det = AnomalyDetector()
    s = det.stats()
    assert {"total_recorded", "by_severity", "by_detector",
            "ewma_samples", "ewma_baseline"} <= set(s)


def test_fire_anomaly_demo_end_to_end():
    det = AnomalyDetector()
    res = fire_anomaly_demo(det)
    assert res  # non-empty dict
    assert res["score"] >= 40
    assert "New source IP" in res["explanation"]


def test_severity_mapping():
    from modules.anomaly_engine import _severity_for

    assert _severity_for(85) == "Critical"
    assert _severity_for(70) == "High"
    assert _severity_for(50) == "Medium"
    assert _severity_for(10) == "Low"
