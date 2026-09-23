"""Real-behavior tests for modules/soar_engine.py containment primitives.

The soar_ctx fixture monkeypatches ACL_PATH to a tmp file and forces the
privilege probe to report UNPRIVILEGED, so every test exercises the
APPLICATION-LAYER ACCESS CONTROL BLOCK path without touching the real ACL
file or (as root in CI) a real firewall.

The zero-trust session-revocation half is skipped until the sibling subagent
creates modules/session_registry.py (pytest.importorskip — never a failure).
"""

import pytest

FIELDS = {
    "timestamp": "2026-09-22 10:00:00 UTC",
    "source_ip": "203.0.113.9",
    "target_host": "NADRA-IDC-ISB",
    "classification": "Critical Information Infrastructure",
    "detection_rule": "PISF-05.2",
    "mitigating_action": "APPLICATION-LAYER ACCESS CONTROL BLOCK",
    "privilege_state": "UNPRIVILEGED (standard user)",
}

EXPECTED_CANONICAL = (
    "timestamp=2026-09-22 10:00:00 UTC|source_ip=203.0.113.9|"
    "target_host=NADRA-IDC-ISB|classification=Critical Information Infrastructure|"
    "detection_rule=PISF-05.2|mitigating_action=APPLICATION-LAYER ACCESS CONTROL BLOCK|"
    "privilege_state=UNPRIVILEGED (standard user)"
)


def test_canonical_record_is_order_locked(soar_ctx):
    se = soar_ctx["se"]
    # Same fields in scrambled insertion order must produce the identical string.
    scrambled = dict(reversed(list(FIELDS.items())))
    assert se.canonical_incident_record(scrambled) == se.canonical_incident_record(FIELDS)
    assert se.canonical_incident_record(FIELDS) == EXPECTED_CANONICAL


def test_canonical_record_missing_key_raises(soar_ctx):
    se = soar_ctx["se"]
    incomplete = {k: v for k, v in FIELDS.items() if k != "source_ip"}
    with pytest.raises(KeyError):
        se.canonical_incident_record(incomplete)


def test_sha256_hex_known_vector(soar_ctx):
    se = soar_ctx["se"]
    assert se.sha256_hex("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert se.sha256_hex("") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_contain_unprivileged_writes_deny_to_acl(soar_ctx):
    se, acl = soar_ctx["se"], soar_ctx["acl"]
    result = se.contain_source_ip("203.0.113.9")
    assert result.ok is True
    assert result.mode == "APPLICATION-LAYER ACCESS CONTROL BLOCK"
    body = acl.read_text(encoding="utf-8")
    assert "DENY 203.0.113.9" in body
    assert "APPLICATION-LAYER ACCESS CONTROL BLOCK" in body


def test_terminate_and_ban_session_refuses_empty_or_placeholder(soar_ctx):
    se, acl = soar_ctx["se"], soar_ctx["acl"]
    for bad in ("", "   ", "0.0.0.0", "-", "unknown"):
        result = se.terminate_and_ban_session(bad)
        assert result.ok is False, f"{bad!r} should be refused"
        assert result.mode == "DEMONSTRATION PROTOCOL MODE"
    assert not acl.exists() or acl.read_text(encoding="utf-8") == ""


def test_terminate_and_ban_session_writes_deny_and_ban_marker(soar_ctx):
    se, acl = soar_ctx["se"], soar_ctx["acl"]
    ip = "203.0.113.10"
    result = se.terminate_and_ban_session(ip)
    assert result.ok is True
    body = acl.read_text(encoding="utf-8")
    assert f"DENY {ip}" in body       # strongest-available containment path
    assert f"BAN {ip}" in body        # explicit zero-trust ban marker
    assert "terminate_and_ban_session" in body


def test_terminate_and_ban_session_revokes_zt_session(tmp_db, monkeypatch, soar_ctx):
    """Zero-trust revocation via session_registry (sibling-owned module).

    terminate_and_ban_session() constructs SessionRegistry() internally; the
    registry's get_db binding is redirected to the tmp DB so the real
    database/cyberpulse.db is never touched.
    """
    sr = pytest.importorskip(
        "modules.session_registry",
        reason="modules/session_registry.py not created yet (sibling subagent)",
    )
    monkeypatch.setattr(sr, "get_db", lambda: tmp_db)
    se, acl = soar_ctx["se"], soar_ctx["acl"]
    ip = "203.0.113.11"
    registry = sr.SessionRegistry(db=tmp_db)
    registry.upsert_active(ip=ip, user="analyst", host="MOITT-PORTAL")
    result = se.terminate_and_ban_session(ip)
    row = registry.get_session(ip)
    assert row["status"] == "revoked"
    assert row["revoked_at"]
    assert "REVOKED" in result.detail
