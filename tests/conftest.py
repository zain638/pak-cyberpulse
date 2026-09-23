"""Shared fixtures for the Pak-CyberPulse v3 pytest suite.

Every DB-backed test gets a fresh, isolated SQLite file under tmp_path —
the real database/cyberpulse.db is never touched.

External boundaries that ARE monkeypatched (allowed):
  - database.db_manager.get_db / modules.siem_panel.get_db / modules.soar_engine.get_db
    -> tmp DatabaseManager (keeps detection tests off the real DB)
  - modules.soar_engine.ACL_PATH -> tmp file (keeps containment tests off mock_acl_rules.txt)
  - modules.soar_engine.detect_privilege -> forced unprivileged snapshot (we run as
    root in CI; a real privileged probe would attempt a real iptables call)
  - modules.soar_engine.maybe_trigger_airgap_on_attack -> no-op (would copy the
    real DB file into database/backups/)
"""

from __future__ import annotations

import pytest

from database.db_manager import DatabaseManager


@pytest.fixture
def tmp_db(tmp_path):
    """Fresh seeded DatabaseManager on a tmp SQLite file."""
    db = DatabaseManager(tmp_path / "t.db")
    db.initialize()
    return db


@pytest.fixture
def seeded_ti(tmp_db):
    from modules.threat_intel import TIStore

    ti = TIStore(db=tmp_db)
    ti.seed_feeds()
    return ti


@pytest.fixture
def rbac_mgr(tmp_db):
    from modules.rbac import RBACManager

    return RBACManager(db=tmp_db)


@pytest.fixture
def case_mgr(tmp_db):
    from modules.case_manager import CaseManager

    return CaseManager(db=tmp_db)


@pytest.fixture
def siem_ctx(tmp_path, monkeypatch):
    """Hermetic SIEM engine: tmp DB, tmp ACL, forced-unprivileged, no airgap."""
    import modules.siem_panel as sp
    import modules.soar_engine as se

    db = DatabaseManager(tmp_path / "siem.db")
    db.initialize()
    acl = tmp_path / "acl.txt"
    monkeypatch.setattr(sp, "get_db", lambda: db)
    monkeypatch.setattr(se, "get_db", lambda: db)
    # v4: the ML anomaly layer dispatches through modules.alerting — keep
    # those dispatches on the tmp DB too.
    import modules.alerting as al

    monkeypatch.setattr(al, "get_db", lambda: db)
    monkeypatch.setattr(se, "ACL_PATH", acl)
    monkeypatch.setattr(
        se,
        "detect_privilege",
        lambda: {
            "privileged": False,
            "uid": 1000,
            "platform": "linux",
            "method": "test-fixture",
            "euid": 1000,
            "firewall_binary": None,
        },
    )
    monkeypatch.setattr(se, "maybe_trigger_airgap_on_attack", lambda: None)
    return {"db": db, "engine": sp.SIEMEngine(), "acl": acl}


@pytest.fixture
def soar_ctx(tmp_path, monkeypatch):
    """Hermetic SOAR boundary: tmp ACL file, forced-unprivileged probe."""
    import modules.soar_engine as se

    acl = tmp_path / "acl.txt"
    monkeypatch.setattr(se, "ACL_PATH", acl)
    monkeypatch.setattr(
        se,
        "detect_privilege",
        lambda: {
            "privileged": False,
            "uid": 1000,
            "platform": "linux",
            "method": "test-fixture",
            "euid": 1000,
            "firewall_binary": None,
        },
    )
    return {"se": se, "acl": acl}
