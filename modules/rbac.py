"""
Pak-CyberPulse RBAC — login + role-based access control.

Users are stored with PBKDF2-HMAC-SHA256 password hashes (200,000 iterations,
16-byte random salt via the secrets module). Plaintext passwords are NEVER
stored or logged.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

import streamlit as st

from database.db_manager import DatabaseManager, get_db


# ---------------------------------------------------------------------------
# Role / permission vocabulary
# ---------------------------------------------------------------------------
ROLES = ["Analyst", "Senior Analyst", "SOC Manager", "Admin"]

PERMISSIONS: Dict[str, Set[str]] = {
    "case.view": {"Analyst", "Senior Analyst", "SOC Manager", "Admin"},
    "case.manage": {"Analyst", "Senior Analyst", "SOC Manager", "Admin"},
    "case.assign": {"Senior Analyst", "SOC Manager", "Admin"},
    "ti.view": {"Analyst", "Senior Analyst", "SOC Manager", "Admin"},
    "ti.manage": {"Senior Analyst", "SOC Manager", "Admin"},
    "soar.execute": {"Senior Analyst", "SOC Manager", "Admin"},
    "soar.kill_session": {"Senior Analyst", "SOC Manager", "Admin"},
    "alerting.configure": {"SOC Manager", "Admin"},
    "user.manage": {"Admin"},
    "forensics.view": {"Analyst", "Senior Analyst", "SOC Manager", "Admin"},
}

_PBKDF2_ITERATIONS = 200_000


def ensure_schema(db: DatabaseManager) -> None:
    with db.lock:
        with db.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username      TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    salt          TEXT NOT NULL,
                    role          TEXT NOT NULL,
                    full_name     TEXT NOT NULL DEFAULT '',
                    created_at    TEXT NOT NULL,
                    is_active     INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            # v7 migration: must_change flags demo/default passwords ("change me").
            # Runs ONLY when the column is newly added: pre-existing seeded
            # demo accounts keep the flag until the user actually rotates the
            # password (change_password clears it permanently).
            try:
                conn.execute(
                    "ALTER TABLE users ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0"
                )
                conn.execute(
                    "UPDATE users SET must_change = 1 WHERE username IN "
                    "('admin', 'soc.manager', 'senior.analyst', 'analyst')"
                )
            except Exception:
                pass
            conn.commit()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    ).hex()


class RBACManager:
    """User accounts and permission checks backed by the shared SQLite store."""

    def __init__(self, db: Optional[DatabaseManager] = None) -> None:
        self.db = db or get_db()
        ensure_schema(self.db)

    # -- accounts ----------------------------------------------------------
    def create_user(self, username: str, password: str, role: str, full_name: str = "",
                    must_change: bool = False) -> Dict[str, Any]:
        username = (username or "").strip()
        if not username:
            raise ValueError("username must not be empty")
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; valid roles: {ROLES}")
        if len(password or "") < 8:
            raise ValueError("password must be at least 8 characters")
        salt = secrets.token_bytes(16)
        record = {
            "username": username,
            "password_hash": _hash_password(password, salt),
            "salt": salt.hex(),
            "role": role,
            "full_name": full_name or username,
            "created_at": _utc(),
            "is_active": 1,
            "must_change": 1 if must_change else 0,
        }
        with self.db.lock:
            with self.db.connect() as conn:
                try:
                    conn.execute(
                        """
                        INSERT INTO users
                            (username, password_hash, salt, role, full_name, created_at, is_active, must_change)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record["username"],
                            record["password_hash"],
                            record["salt"],
                            record["role"],
                            record["full_name"],
                            record["created_at"],
                            record["is_active"],
                            record["must_change"],
                        ),
                    )
                except Exception as exc:  # duplicate username
                    raise ValueError(f"user {username!r} already exists") from exc
                conn.commit()
        return self._public(record)

    def change_password(self, username: str, new_password: str) -> None:
        """Set a new password; clears the must_change ("change me") flag."""
        if len(new_password or "") < 8:
            raise ValueError("password must be at least 8 characters")
        salt = secrets.token_bytes(16)
        with self.db.lock:
            with self.db.connect() as conn:
                cur = conn.execute(
                    "UPDATE users SET password_hash = ?, salt = ?, must_change = 0 "
                    "WHERE username = ?",
                    (_hash_password(new_password, salt), salt.hex(), username),
                )
                if cur.rowcount == 0:
                    raise ValueError(f"unknown user {username!r}")
                conn.commit()
        return True

    def login(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Return the user record (no hash/salt) on success, else None."""
        with self.db.lock:
            with self.db.connect() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE username = ?", (username,)
                ).fetchone()
                record = dict(row) if row else None
        if not record or not record.get("is_active"):
            return None
        candidate = _hash_password(password or "", bytes.fromhex(record["salt"]))
        if not secrets.compare_digest(candidate, record["password_hash"]):
            return None
        return self._public(record)

    @staticmethod
    def _public(record: Dict[str, Any]) -> Dict[str, Any]:
        return {
            k: record[k]
            for k in ("username", "role", "full_name", "created_at", "is_active",
                      "must_change")
            if k in record
        }

    # -- permissions -------------------------------------------------------
    @staticmethod
    def has_permission(user_or_role: Any, permission: str) -> bool:
        role = user_or_role.get("role") if isinstance(user_or_role, dict) else user_or_role
        allowed = PERMISSIONS.get(permission, set())
        return role in allowed

    def permissions_for(self, user_or_role: Any) -> list[str]:
        role = user_or_role.get("role") if isinstance(user_or_role, dict) else user_or_role
        return sorted(p for p, roles in PERMISSIONS.items() if role in roles)

    # -- administration ----------------------------------------------------
    def list_users(self) -> list[Dict[str, Any]]:
        with self.db.lock:
            with self.db.connect() as conn:
                rows = conn.execute(
                    "SELECT username, role, full_name, created_at, is_active,"
                    " COALESCE(must_change, 0) AS must_change"
                    " FROM users ORDER BY created_at"
                ).fetchall()
        return [dict(r) for r in rows]

    def set_active(self, username: str, active: bool) -> None:
        with self.db.lock:
            with self.db.connect() as conn:
                cur = conn.execute(
                    "UPDATE users SET is_active = ? WHERE username = ?",
                    (1 if active else 0, username),
                )
                if cur.rowcount == 0:
                    raise ValueError(f"unknown user {username!r}")
                conn.commit()

    def change_role(self, username: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; valid roles: {ROLES}")
        with self.db.lock:
            with self.db.connect() as conn:
                cur = conn.execute(
                    "UPDATE users SET role = ? WHERE username = ?", (role, username)
                )
                if cur.rowcount == 0:
                    raise ValueError(f"unknown user {username!r}")
                conn.commit()


def seed_demo_users(db: Optional[DatabaseManager] = None) -> list[str]:
    """Create the four DEMO accounts if they are missing. Returns created usernames."""
    mgr = RBACManager(db)
    demos = [
        ("admin", "Admin123!", "Admin", "DEMO Administrator"),
        ("soc.manager", "Soc12345", "SOC Manager", "DEMO SOC Manager"),
        ("senior.analyst", "Senior123", "Senior Analyst", "DEMO Senior Analyst"),
        ("analyst", "Analyst123", "Analyst", "DEMO Analyst"),
    ]
    created: list[str] = []
    existing = {u["username"] for u in mgr.list_users()}
    for username, password, role, full_name in demos:
        if username not in existing:
            # Demo credentials are public knowledge -> flag "change me".
            mgr.create_user(username, password, role, full_name, must_change=True)
            created.append(username)
    return created


# ---------------------------------------------------------------------------
# RBAC gate for privileged SOC actions (shared by app.py panels)
# ---------------------------------------------------------------------------
def gate_action(permission: str) -> tuple[bool, str]:
    """
    RBAC gate for privileged SOC actions. Returns (allowed, banner_html).

    - No analyst logged in: allowed, but a cp-action banner marks DEMO mode.
    - Analyst logged in with the permission: allowed, no banner.
    - Analyst logged in WITHOUT the permission: denied, honest cp-critical banner.
    """
    user = st.session_state.get("rbac_user")
    if user is None:
        return True, (
            '<div class="cp-banner cp-action">RBAC: no analyst logged in — running in DEMO mode '
            f"(log in as Senior Analyst+ for gated <code>{permission}</code> execution).</div>"
        )
    if RBACManager.has_permission(user, permission):
        return True, ""
    return False, (
        '<div class="cp-banner cp-critical">RBAC DENIED — '
        f"{user.get('username')} ({user.get('role')}) lacks <code>{permission}</code>. "
        "Log in as Senior Analyst or above to execute.</div>"
    )


# ---------------------------------------------------------------------------
# Streamlit panel
# ---------------------------------------------------------------------------
def render_login_panel(rbac: Optional[RBACManager] = None) -> Optional[Dict[str, Any]]:
    """Login form / session card. Returns the logged-in user dict or None."""
    rbac = rbac or RBACManager()
    user = st.session_state.get("rbac_user")

    if user is None:
        st.markdown(
            '<div class="cp-banner cp-action">RESTRICTED — sign in to access SOC functions.</div>',
            unsafe_allow_html=True,
        )
        with st.form("rbac_login_form", clear_on_submit=False):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in")
        if submitted:
            record = rbac.login(username.strip(), password)
            if record:
                st.session_state["rbac_user"] = record
                st.rerun()
            else:
                st.error("Invalid credentials or disabled account.")
        st.caption("DEMO accounts: admin / soc.manager / senior.analyst / analyst")
        return None

    perms = rbac.permissions_for(user)
    import html as _html
    st.markdown(
        f'<div class="cp-banner cp-hardened">SIGNED IN — <b>{_html.escape(str(user["username"]))}</b>'
        f" &nbsp;|&nbsp; role: <b>{_html.escape(str(user['role']))}</b></div>",
        unsafe_allow_html=True,
    )
    if user.get("must_change"):
        st.markdown(
            '<div class="cp-banner cp-critical"><b>⚠ CHANGE ME —</b> this account '
            "is still using its public DEMO password. Set a new password now.</div>",
            unsafe_allow_html=True,
        )
        with st.form("rbac_change_pw", clear_on_submit=True):
            npw = st.text_input("New password (min 8 chars)", type="password")
            npw2 = st.text_input("Confirm new password", type="password")
            go = st.form_submit_button("Change password")
        if go:
            if npw != npw2:
                st.error("Passwords do not match.")
            else:
                try:
                    rbac.change_password(user["username"], npw)
                    rec = rbac.login(user["username"], npw)
                    st.session_state["rbac_user"] = rec or user
                    st.success("Password changed — demo flag cleared.")
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
    st.markdown("**Permissions granted:**")
    st.write(", ".join(f"`{p}`" for p in perms))
    col_a, col_b = st.columns([1, 3])
    with col_a:
        if st.button("Log out"):
            del st.session_state["rbac_user"]
            st.rerun()
    with col_b:
        st.caption(f"{user.get('full_name', '')} — session held in browser state only.")
    return user
