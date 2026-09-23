"""
Pak-CyberPulse zero-trust session registry.

Why this exists (honest v3 fix): the Zero-Trust Active Session Manager UI
rebuilds its "sessions" list from recent SIEM events, so when
terminate_and_ban_session() only appended DENY/BAN lines to the ACL file,
a kill had no persisted record — the row vanished and the kill looked
temporary. This module keeps a SQLite table (zt_sessions) with a genuine
status column ('active' / 'revoked'). A revoked session is NEVER re-upserted
as active by later traffic: upsert_active() only refreshes active rows, so
revoked rows stay visible as revoked — proof the kill persisted.

Session identity is the source IP (session_id == src_ip), matching how the
SIEM and SOAR engine identify network sessions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from database.db_manager import DatabaseManager, get_db

VALID_STATUSES = ("active", "revoked")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def ensure_schema(db: DatabaseManager) -> None:
    with db.lock:
        with db.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS zt_sessions (
                    session_id  TEXT PRIMARY KEY,
                    src_ip      TEXT NOT NULL,
                    user        TEXT NOT NULL DEFAULT '-',
                    host        TEXT NOT NULL DEFAULT '-',
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'revoked')),
                    revoked_at  TEXT,
                    revoked_by  TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_zt_sessions_status "
                "ON zt_sessions(status)"
            )
            conn.commit()


def _row_to_dict(row: Any) -> Dict[str, Any]:
    return {
        "session_id": row["session_id"],
        "src_ip": row["src_ip"],
        "user": row["user"],
        "host": row["host"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "status": row["status"],
        "revoked_at": row["revoked_at"],
        "revoked_by": row["revoked_by"],
    }


class SessionRegistry:
    """SQLite-backed record of zero-trust network sessions."""

    def __init__(self, db: Optional[DatabaseManager] = None) -> None:
        self.db = db or get_db()
        ensure_schema(self.db)

    # -- lifecycle ---------------------------------------------------------
    def upsert_active(
        self, ip: str = "", user: str = "-", host: str = "-", src_ip: str = ""
    ) -> Dict[str, Any]:
        """
        Insert a new active session or refresh last_seen/user/host of an
        existing one. A session already 'revoked' is left revoked (later
        traffic cannot resurrect it) — only its identity metadata refreshes.

        Accepts the session IP as `ip` or `src_ip` (both contracts supported).
        """
        ip = (ip or src_ip).strip()
        if not ip:
            raise ValueError("upsert_active requires an IP address")
        now = _utc()
        with self.db.lock:
            with self.db.connect() as conn:
                row = conn.execute(
                    "SELECT * FROM zt_sessions WHERE session_id = ?",
                    (ip,),
                ).fetchone()
                if row is None:
                    conn.execute(
                        """
                        INSERT INTO zt_sessions
                            (session_id, src_ip, user, host, first_seen,
                             last_seen, status)
                        VALUES (?, ?, ?, ?, ?, ?, 'active')
                        """,
                        (ip, ip, user, host, now, now),
                    )
                elif row["status"] == "active":
                    conn.execute(
                        """
                        UPDATE zt_sessions
                        SET last_seen = ?, user = ?, host = ?
                        WHERE session_id = ?
                        """,
                        (now, user, host, ip),
                    )
                else:
                    # Revoked: refresh identity metadata only; status stays revoked.
                    conn.execute(
                        """
                        UPDATE zt_sessions
                        SET user = ?, host = ?
                        WHERE session_id = ?
                        """,
                        (user, host, ip),
                    )
                conn.commit()
                fresh = conn.execute(
                    "SELECT * FROM zt_sessions WHERE session_id = ?",
                    (ip,),
                ).fetchone()
                return _row_to_dict(fresh)

    def revoke(
        self, src_ip: str = "", actor: str = "zero-trust-kill-switch", ip: str = ""
    ) -> bool:
        """
        Mark the session revoked. Returns True when a record was revoked,
        False when no record exists for the IP (nothing to revoke).

        Accepts the session IP as `src_ip` or `ip` (both contracts supported).
        """
        src_ip = (src_ip or ip).strip()
        now = _utc()
        with self.db.lock:
            with self.db.connect() as conn:
                row = conn.execute(
                    "SELECT session_id FROM zt_sessions WHERE session_id = ?",
                    (src_ip,),
                ).fetchone()
                if row is None:
                    return False
                conn.execute(
                    """
                    UPDATE zt_sessions
                    SET status = 'revoked', revoked_at = ?, revoked_by = ?
                    WHERE session_id = ?
                    """,
                    (now, actor, src_ip),
                )
                conn.commit()
                return True

    # -- reads -------------------------------------------------------------
    def get_session(self, src_ip: str) -> Optional[Dict[str, Any]]:
        with self.db.lock:
            with self.db.connect() as conn:
                row = conn.execute(
                    "SELECT * FROM zt_sessions WHERE session_id = ?",
                    (str(src_ip).strip(),),
                ).fetchone()
                return _row_to_dict(row) if row else None

    def list_sessions(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.db.lock:
            with self.db.connect() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM zt_sessions WHERE status = ? "
                        "ORDER BY last_seen DESC",
                        (status,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM zt_sessions ORDER BY last_seen DESC"
                    ).fetchall()
                return [_row_to_dict(r) for r in rows]
