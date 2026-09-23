"""Registry integrity for modules/attack_patterns.py — 19 patterns."""

import re

import pytest

from modules.attack_patterns import (
    BEHAVIORAL_PATTERNS,
    PATTERN_BY_ID,
    PATTERNS,
    SIGNATURE_PATTERNS,
    owasp_coverage,
)

REQUIRED_KEYS = {
    "id",
    "name",
    "owasp",
    "pisf",
    "kind",
    "severity",
    "description",
    "indicators",
    "mitigation",
    "soar_action",
}


def test_registry_has_19_unique_patterns():
    assert len(PATTERNS) == 19
    assert len(PATTERN_BY_ID) == 19
    assert len({p["id"] for p in PATTERNS}) == 19  # no duplicate ids


def test_all_patterns_carry_required_keys():
    for p in PATTERNS:
        missing = REQUIRED_KEYS - set(p)
        assert not missing, f"{p.get('id')}: missing keys {missing}"
        assert p["kind"] in {"signature", "behavioral"}
        assert p["severity"] in {"Critical", "High", "Medium", "Low"}
        assert p["soar_action"] in {"block_ip", "kill_session", "quarantine", "alert"}
        assert isinstance(p["mitigation"], list) and len(p["mitigation"]) >= 1


def test_all_signature_regexes_compile_and_behave():
    for p in SIGNATURE_PATTERNS:
        assert p["signatures"], f"{p['id']} has no signatures"
        for sig in p["signatures"]:
            re.compile(sig)  # raises re.error if invalid


def test_kind_split_is_12_signature_7_behavioral():
    assert len(SIGNATURE_PATTERNS) == 12
    assert len(BEHAVIORAL_PATTERNS) == 7
    assert all(p["kind"] == "signature" for p in SIGNATURE_PATTERNS)
    assert all(p["kind"] == "behavioral" for p in BEHAVIORAL_PATTERNS)


def test_spot_check_signatures_hit_and_benign_misses():
    sqli = PATTERN_BY_ID["SQLI"]
    xss = PATTERN_BY_ID["XSS"]
    benign = "GET /index.html HTTP/1.1"
    hits = 0
    for p in SIGNATURE_PATTERNS:
        for sig in p["signatures"]:
            if re.search(sig, "' OR '1'='1"):
                assert p["id"] == "SQLI"
                hits += 1
            if re.search(sig, "1 UNION SELECT username,password FROM users"):
                assert p["id"] == "SQLI"
            if re.search(sig, "<script>alert(1)</script>"):
                assert p["id"] == "XSS"
            assert not re.search(sig, benign), f"{p['id']} false-positive on benign line"
    assert sqli["severity"] == "Critical" and xss["severity"] == "High"


def test_owasp_coverage_spans_all_19_patterns():
    cov = owasp_coverage()
    covered = {pid for pids in cov.values() for pid in pids}
    assert covered == set(PATTERN_BY_ID)
    assert "A03:2021 Injection" in cov  # SQLi/XSS/CMDi/SSTI family present
