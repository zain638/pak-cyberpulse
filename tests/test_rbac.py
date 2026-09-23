"""Account, login, permission-matrix and password-hygiene tests for rbac."""

import pytest

from modules.rbac import RBACManager, seed_demo_users


def test_create_user_validation(rbac_mgr):
    with pytest.raises(ValueError):
        rbac_mgr.create_user("u1", "longenough1", "SuperAdmin")  # bad role
    with pytest.raises(ValueError):
        rbac_mgr.create_user("u2", "short", "Analyst")           # short password
    with pytest.raises(ValueError):
        rbac_mgr.create_user("   ", "longenough1", "Analyst")   # blank username
    rbac_mgr.create_user("dup", "longenough1", "Analyst")
    with pytest.raises(ValueError):
        rbac_mgr.create_user("dup", "longenough1", "Analyst")    # duplicate


def test_login_success_wrong_password_unknown(rbac_mgr):
    rbac_mgr.create_user("alice", "CorrectHorse1", "Senior Analyst", "Alice")
    ok = rbac_mgr.login("alice", "CorrectHorse1")
    assert ok is not None and ok["username"] == "alice" and ok["role"] == "Senior Analyst"
    assert "password_hash" not in ok and "salt" not in ok  # never leak secrets
    assert rbac_mgr.login("alice", "WrongPassword1") is None
    assert rbac_mgr.login("nobody", "whatever123") is None


def test_inactive_user_cannot_login(rbac_mgr):
    rbac_mgr.create_user("bob", "BobPassword1", "Analyst")
    assert rbac_mgr.login("bob", "BobPassword1") is not None
    rbac_mgr.set_active("bob", False)
    assert rbac_mgr.login("bob", "BobPassword1") is None
    rbac_mgr.set_active("bob", True)
    assert rbac_mgr.login("bob", "BobPassword1") is not None


def test_permission_matrix(rbac_mgr):
    m = RBACManager.has_permission
    assert m("Analyst", "soar.execute") is False
    assert m("Analyst", "case.view") is True
    assert m("Senior Analyst", "soar.execute") is True
    assert m("Senior Analyst", "soar.kill_session") is True
    assert m("Senior Analyst", "user.manage") is False
    assert m("SOC Manager", "alerting.configure") is True
    assert m("Admin", "user.manage") is True
    assert m({"role": "Analyst"}, "case.view") is True      # dict form works too
    assert m("Analyst", "no.such.permission") is False


def test_seed_demo_users_idempotent_and_loggable(rbac_mgr):
    created = seed_demo_users(rbac_mgr.db)
    assert sorted(created) == ["admin", "analyst", "senior.analyst", "soc.manager"]
    assert seed_demo_users(rbac_mgr.db) == []               # second run: nothing
    assert rbac_mgr.login("admin", "Admin123!")["role"] == "Admin"
    assert rbac_mgr.login("analyst", "Analyst123")["role"] == "Analyst"
    assert len(rbac_mgr.list_users()) == 4


def test_no_plaintext_password_in_db_file(tmp_db, rbac_mgr):
    seed_demo_users(tmp_db)
    blob = tmp_db.path.read_bytes()
    assert b"Admin123!" not in blob
    assert b"Analyst123" not in blob
    # Same password twice must produce different hashes (random salt per user).
    rbac_mgr.create_user("x1", "SamePassword1", "Analyst")
    rbac_mgr.create_user("x2", "SamePassword1", "Analyst")
    with tmp_db.connect() as conn:
        rows = conn.execute(
            "SELECT password_hash FROM users WHERE username IN ('x1','x2')"
        ).fetchall()
    assert rows[0]["password_hash"] != rows[1]["password_hash"]


def test_change_role_validation(rbac_mgr):
    rbac_mgr.create_user("carol", "CarolPass123", "Analyst")
    rbac_mgr.change_role("carol", "Senior Analyst")
    assert rbac_mgr.login("carol", "CarolPass123")["role"] == "Senior Analyst"
    with pytest.raises(ValueError):
        rbac_mgr.change_role("carol", "SuperAdmin")
    with pytest.raises(ValueError):
        rbac_mgr.set_active("ghost", False)


def test_must_change_flag_in_login_and_public_records(rbac_mgr):
    rbac_mgr.create_user("flagme", "FlagMePass1", "Analyst", must_change=True)
    rec = rbac_mgr.login("flagme", "FlagMePass1")
    assert rec is not None and rec.get("must_change") == 1
    pub = [u for u in rbac_mgr.list_users() if u["username"] == "flagme"][0]
    assert pub.get("must_change") == 1
    assert "password_hash" not in rec and "salt" not in rec


def test_change_password_clears_must_change(rbac_mgr):
    rbac_mgr.create_user("changeme", "OldPassword1", "Analyst", must_change=True)
    assert rbac_mgr.change_password("changeme", "NewPassword2") is True
    rec = rbac_mgr.login("changeme", "NewPassword2")
    assert rec is not None and rec.get("must_change") == 0
    assert rbac_mgr.login("changeme", "OldPassword1") is None  # old pw dead
    with __import__("pytest").raises(ValueError):
        rbac_mgr.change_password("changeme", "short")
    with __import__("pytest").raises(ValueError):
        rbac_mgr.change_password("ghost", "NewPassword2")


def test_seed_demo_users_flagged_change_me(rbac_mgr):
    created = seed_demo_users(rbac_mgr.db)
    assert len(created) == 4
    flagged = {u["username"] for u in rbac_mgr.list_users() if u.get("must_change")}
    assert flagged == {"admin", "analyst", "senior.analyst", "soc.manager"}
