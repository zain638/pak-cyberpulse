"""
Pak-CyberPulse incident case manager.

SQLite-persisted incident case lifecycle with a strict forward-only
transition model, per-severity SLAs computed from real UTC time, and an
analyst note thread. Status changes are recorded as system notes so
case_timeline() reconstructs the full audit trail from one query.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import streamlit as st

from database.db_manager import DatabaseManager, get_db, utc_now

STATUSES = ["open", "triage", "contained", "eradicated", "recovered", "closed"]

# Forward-only, single-step. closed -> triage is the explicit reopen path.
TRANSITIONS: dict[str, list[str]] = {
    "open": ["triage"],
    "triage": ["contained"],
    "contained": ["eradicated"],
    "eradicated": ["recovered"],
    "recovered": ["closed"],
    "closed": ["triage"],
}

SEVERITIES = ["Critical", "High", "Medium", "Low"]

SLA_HOURS: dict[str, int] = {
    "Critical": 4,
    "High": 24,
    "Medium": 72,
    "Low": 168,
}

SEV_BADGE = {
    "Critical": "sev-critical",
    "High": "sev-high",
    "Medium": "sev-medium",
}


def _parse_utc(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)


def sev_badge_html(severity: str) -> str:
    cls = SEV_BADGE.get(severity)
    if cls:
        return f"<span class='sev {cls}'>{severity}</span>"
    return (
        "<span style='display:inline-block;font-size:0.72rem;font-weight:600;"
        "padding:2px 10px;border-radius:999px;letter-spacing:0.04em;"
        "text-transform:uppercase;background:#1a1f2b;color:#9aa7bd;"
        "border:1px solid #2c3446;'>" + severity + "</span>"
    )


class CaseManager:
    """Case lifecycle store. All mutations take the manager lock."""

    def __init__(self, db: Optional[DatabaseManager] = None) -> None:
        self.db: DatabaseManager = db if db is not None else get_db()
        self._lock = threading.RLock()
        self.ensure_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def ensure_schema(self) -> None:
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS cases (
                        case_id           INTEGER PRIMARY KEY AUTOINCREMENT,
                        title             TEXT NOT NULL,
                        description       TEXT NOT NULL DEFAULT '',
                        severity          TEXT NOT NULL,
                        status            TEXT NOT NULL DEFAULT 'open',
                        assignee          TEXT NOT NULL DEFAULT '',
                        created_at        TEXT NOT NULL,
                        updated_at        TEXT NOT NULL,
                        sla_due           TEXT NOT NULL,
                        linked_incident_id INTEGER
                    );

                    CREATE TABLE IF NOT EXISTS case_notes (
                        note_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id    INTEGER NOT NULL,
                        author     TEXT NOT NULL,
                        note       TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (case_id) REFERENCES cases (case_id)
                    );
                    """
                )
                conn.commit()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def create_case(
        self,
        title: str,
        description: str,
        severity: str,
        assignee: str = "",
        linked_incident_id: Optional[int] = None,
    ) -> int:
        if not title.strip():
            raise ValueError("Case title is required")
        if severity not in SEVERITIES:
            raise ValueError(f"Invalid severity {severity!r}")
        now = datetime.now(timezone.utc)
        due = now + timedelta(hours=SLA_HOURS[severity])
        now_s = now.strftime("%Y-%m-%d %H:%M:%S UTC")
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO cases (
                        title, description, severity, status, assignee,
                        created_at, updated_at, sla_due, linked_incident_id
                    ) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?)
                    """,
                    (
                        title.strip(),
                        description.strip(),
                        severity,
                        assignee.strip(),
                        now_s,
                        now_s,
                        due.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        linked_incident_id,
                    ),
                )
                case_id = int(cur.lastrowid)
                conn.execute(
                    """
                    INSERT INTO case_notes (case_id, author, note, created_at)
                    VALUES (?, 'system', ?, ?)
                    """,
                    (
                        case_id,
                        f"Case opened with severity {severity} by {assignee or 'unassigned'}"
                        f"; SLA due {due.strftime('%Y-%m-%d %H:%M:%S UTC')}.",
                        now_s,
                    ),
                )
                conn.commit()
        return case_id

    def get_case(self, case_id: int) -> Optional[dict[str, Any]]:
        with self._lock:
            rows = self.db._rows("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        return rows[0] if rows else None

    def list_cases(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM cases"
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY case_id DESC"
        with self._lock:
            return self.db._rows(sql, tuple(params))

    def valid_transitions(self, case_id: int) -> list[str]:
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Unknown case {case_id}")
        return list(TRANSITIONS.get(case["status"], []))

    def transition(self, case_id: int, new_status: str, actor: str) -> None:
        if new_status not in STATUSES:
            raise ValueError(f"Invalid status {new_status!r}")
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                row = conn.execute(
                    "SELECT status FROM cases WHERE case_id = ?", (case_id,)
                ).fetchone()
                if row is None:
                    raise ValueError(f"Unknown case {case_id}")
                current = row["status"]
                if new_status not in TRANSITIONS.get(current, []):
                    raise ValueError(
                        f"Transition {current!r} -> {new_status!r} is not allowed; "
                        f"valid next states: {TRANSITIONS.get(current, [])}"
                    )
                now_s = utc_now()
                conn.execute(
                    "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                    (new_status, now_s, case_id),
                )
                conn.execute(
                    """
                    INSERT INTO case_notes (case_id, author, note, created_at)
                    VALUES (?, 'system', ?, ?)
                    """,
                    (
                        case_id,
                        f"Status changed: {current} -> {new_status} by {actor or 'analyst'}.",
                        now_s,
                    ),
                )
                conn.commit()

    def assign(self, case_id: int, analyst: str) -> None:
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                if conn.execute(
                    "SELECT 1 FROM cases WHERE case_id = ?", (case_id,)
                ).fetchone() is None:
                    raise ValueError(f"Unknown case {case_id}")
                now_s = utc_now()
                conn.execute(
                    "UPDATE cases SET assignee = ?, updated_at = ? WHERE case_id = ?",
                    (analyst.strip(), now_s, case_id),
                )
                conn.execute(
                    """
                    INSERT INTO case_notes (case_id, author, note, created_at)
                    VALUES (?, 'system', ?, ?)
                    """,
                    (case_id, f"Case assigned to {analyst.strip() or 'unassigned'}.", now_s),
                )
                conn.commit()

    def add_note(self, case_id: int, author: str, note: str) -> int:
        if not note.strip():
            raise ValueError("Note text is required")
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                if conn.execute(
                    "SELECT 1 FROM cases WHERE case_id = ?", (case_id,)
                ).fetchone() is None:
                    raise ValueError(f"Unknown case {case_id}")
                now_s = utc_now()
                cur = conn.execute(
                    """
                    INSERT INTO case_notes (case_id, author, note, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (case_id, author.strip() or "analyst", note.strip(), now_s),
                )
                conn.execute(
                    "UPDATE cases SET updated_at = ? WHERE case_id = ?",
                    (now_s, case_id),
                )
                conn.commit()
                return int(cur.lastrowid)

    def case_timeline(self, case_id: int) -> list[dict[str, Any]]:
        """Notes + system status-change records, chronological."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Unknown case {case_id}")
        events: list[dict[str, Any]] = [
            {
                "ts": case["created_at"],
                "kind": "created",
                "summary": f"Case #{case_id} opened: {case['title']}",
            }
        ]
        with self._lock:
            notes = self.db._rows(
                "SELECT * FROM case_notes WHERE case_id = ? ORDER BY note_id ASC",
                (case_id,),
            )
        for n in notes:
            kind = "status_change" if n["author"] == "system" else "note"
            events.append(
                {
                    "ts": n["created_at"],
                    "kind": kind,
                    "summary": n["note"],
                    "author": n["author"],
                }
            )
        events.sort(key=lambda e: (e["ts"], 0 if e["kind"] == "created" else 1))
        return events

    # ------------------------------------------------------------------
    # SLA
    # ------------------------------------------------------------------
    def sla_status(self, case: dict[str, Any]) -> str:
        """
        "closed" | "breached" | "warning" (<25% of the SLA window left) | "ok".
        """
        if case["status"] == "closed":
            return "closed"
        try:
            created = _parse_utc(case["created_at"])
            due = _parse_utc(case["sla_due"])
        except (ValueError, KeyError):
            return "ok"
        now = datetime.now(timezone.utc)
        total = (due - created).total_seconds()
        left = (due - now).total_seconds()
        if left <= 0:
            return "breached"
        if total > 0 and left / total < 0.25:
            return "warning"
        return "ok"

    def sla_remaining(self, case: dict[str, Any]) -> str:
        """Human-readable remaining SLA time (negative if breached)."""
        try:
            due = _parse_utc(case["sla_due"])
        except (ValueError, KeyError):
            return "n/a"
        delta = due - datetime.now(timezone.utc)
        sign = "" if delta.total_seconds() >= 0 else "-"
        secs = abs(int(delta.total_seconds()))
        h, rem = divmod(secs, 3600)
        m = rem // 60
        return f"{sign}{h}h {m}m"


# ---------------------------------------------------------------------------
# Streamlit panel
# ---------------------------------------------------------------------------
def _sla_badge(case: dict[str, Any], cm: CaseManager) -> str:
    status = cm.sla_status(case)
    remaining = cm.sla_remaining(case)
    if status == "closed":
        return "<span class='sev sev-medium'>SLA closed</span>"
    if status == "breached":
        return f"<span class='sev sev-critical'>SLA breached ({remaining})</span>"
    if status == "warning":
        return f"<span class='sev sev-high'>SLA warning ({remaining} left)</span>"
    return f"<span class='sev sev-medium'>SLA ok ({remaining} left)</span>"


def render_cases_panel(cm: Optional[CaseManager] = None) -> None:
    """Case panel: create form, case table with SLA badges, detail + transitions."""
    cm = cm or CaseManager()

    st.markdown(
        '<div class="cp-banner cp-hardened">'
        "<b>Incident cases.</b> Strict forward-only lifecycle with per-severity "
        "SLAs computed from real UTC time. Status changes are audit-logged as "
        "system notes."
        "</div>",
        unsafe_allow_html=True,
    )

    with st.expander("＋ New case", expanded=False):
        with st.form("cm-new-case", clear_on_submit=True):
            title = st.text_input("Title")
            description = st.text_area("Description")
            severity = st.selectbox("Severity", SEVERITIES, index=1)
            assignee = st.text_input("Assignee (analyst handle)")
            incident_opt = st.text_input(
                "Linked incident id (optional)",
                placeholder="e.g. 12",
            )
            if st.form_submit_button("Create case"):
                try:
                    linked = int(incident_opt) if incident_opt.strip() else None
                    cid = cm.create_case(title, description, severity, assignee, linked)
                    st.success(f"Case #{cid} created — SLA {SLA_HOURS[severity]}h from now.")
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))

    f1, f2 = st.columns(2)
    status_filter = f1.selectbox("Status filter", ["All"] + STATUSES, key="cm-f-status")
    sev_filter = f2.selectbox("Severity filter", ["All"] + SEVERITIES, key="cm-f-sev")
    cases = cm.list_cases(
        None if status_filter == "All" else status_filter,
        None if sev_filter == "All" else sev_filter,
    )
    if not cases:
        st.info("No cases match the filters.")
        return

    st.subheader("Cases")
    for c in cases:
        st.markdown(
            f"**#{c['case_id']}** {c['title']}<br>"
            f"{sev_badge_html(c['severity'])} "
            f"<span class='sev sev-medium'>{c['status']}</span> "
            f"{_sla_badge(c, cm)}<br>"
            f"<span style='opacity:.7'>Assignee: {c['assignee'] or 'unassigned'} · "
            f"Updated: {c['updated_at']}"
            + (f" · Linked incident: #{c['linked_incident_id']}" if c["linked_incident_id"] else "")
            + "</span>",
            unsafe_allow_html=True,
        )

    st.subheader("Case detail")
    case_id = st.selectbox(
        "Select case",
        [c["case_id"] for c in cases],
        format_func=lambda i: f"#{i} — "
        + next(c["title"] for c in cases if c["case_id"] == i),
        key="cm-detail",
    )
    case = cm.get_case(int(case_id))
    if not case:
        return

    st.markdown(f"### #{case['case_id']} {case['title']}")
    st.markdown(
        f"{sev_badge_html(case['severity'])} "
        f"<span class='sev sev-medium'>{case['status']}</span> "
        f"{_sla_badge(case, cm)}",
        unsafe_allow_html=True,
    )
    if case["description"]:
        st.write(case["description"])

    # Transitions — only the valid next states are offered.
    valid = cm.valid_transitions(case["case_id"])
    if valid:
        st.write("**Move to:**")
        cols = st.columns(len(valid))
        for col, nxt in zip(cols, valid):
            with col:
                if st.button(nxt.capitalize(), key=f"cm-tr-{case['case_id']}-{nxt}"):
                    actor = st.session_state.get("cm-actor", "analyst")
                    cm.transition(case["case_id"], nxt, actor)
                    st.success(f"Case moved to {nxt}.")
                    st.rerun()
    else:
        st.caption("Terminal state — no forward transitions from here.")

    c1, c2 = st.columns([3, 1])
    with c1:
        new_assignee = st.text_input(
            "Reassign", value=case["assignee"], key=f"cm-assignee-{case['case_id']}"
        )
    with c2:
        st.write("")
        st.write("")
        if st.button("Assign", key=f"cm-assign-{case['case_id']}"):
            cm.assign(case["case_id"], new_assignee)
            st.success("Assignee updated.")
            st.rerun()

    st.write("**Add note**")
    with st.form(f"cm-note-{case['case_id']}", clear_on_submit=True):
        author = st.text_input("Author", value="analyst")
        note = st.text_area("Note")
        if st.form_submit_button("Add note"):
            try:
                cm.add_note(case["case_id"], author, note)
                st.success("Note added.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))

    st.write("**Timeline**")
    for ev in cm.case_timeline(case["case_id"]):
        icon = {"created": "🆕", "status_change": "🔀", "note": "📝"}.get(ev["kind"], "•")
        author = f" — <i>{ev['author']}</i>" if ev.get("author") else ""
        st.markdown(f"{icon} `{ev['ts']}` {ev['summary']}{author}", unsafe_allow_html=True)
