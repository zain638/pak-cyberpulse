"""Tests for modules/session_registry.py (zero-trust session store).

This module is owned by a sibling subagent and does not exist yet, so every
test here is skipped gracefully via pytest.importorskip — never a failure.
The tests below describe the contracted behavior:
  - upsert_active() inserts or refreshes an active session (last_seen updates)
  - revoke() sets status='revoked' and stamps revoked_at
  - revoke() of an unknown ip returns False
"""

import pytest

sr = pytest.importorskip(
    "modules.session_registry",
    reason="modules/session_registry.py not created yet (sibling subagent)",
)


@pytest.fixture
def registry(tmp_db):
    # Bind to the tmp DB — never the real one.
    return sr.SessionRegistry(db=tmp_db)


def test_upsert_active_inserts_and_refreshes_last_seen(registry):
    registry.upsert_active(ip="203.0.113.20", user="analyst", host="MOITT-PORTAL")
    first = registry.get_session("203.0.113.20")
    assert first["status"] == "active"
    first_seen = first["last_seen"]
    registry.upsert_active(ip="203.0.113.20", user="analyst", host="MOITT-PORTAL")
    second = registry.get_session("203.0.113.20")
    assert second["last_seen"] >= first_seen


def test_revoke_sets_status_and_revoked_at(registry):
    registry.upsert_active(ip="203.0.113.21", user="analyst", host="MOITT-PORTAL")
    assert registry.revoke("203.0.113.21") is True
    row = registry.get_session("203.0.113.21")
    assert row["status"] == "revoked"
    assert row["revoked_at"]


def test_revoke_unknown_ip_returns_false(registry):
    assert registry.revoke("198.51.100.250") is False
