"""
Pak-CyberPulse alerting — email + webhook dispatcher, dry-run by default.

Every delivery attempt (including suppressed duplicates) is written to the
alert_log table with an honest status: sent, dry_run, failed, or deduped.
"""

from __future__ import annotations

import hashlib
import json
import smtplib
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

import streamlit as st

from database.db_manager import DatabaseManager, get_db


DEFAULT_ROUTES: Dict[str, List[str]] = {
    "Critical": ["email", "webhook"],
    "High": ["email", "webhook"],
    "Medium": ["webhook"],
    "Low": [],
}


def ensure_schema(db: DatabaseManager) -> None:
    with db.lock:
        with db.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_log (
                    log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at  TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    title       TEXT NOT NULL,
                    channel     TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    detail      TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.commit()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class AlertDispatcher:
    """Routes alert dicts to email and webhook channels with dedup."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        dry_run: bool = True,
        smtp_host: str = "localhost",
        smtp_port: int = 1025,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        dedup_window_s: int = 900,
        routes: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self.db = db or get_db()
        ensure_schema(self.db)
        self.dry_run = dry_run
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.dedup_window_s = dedup_window_s
        self.routes: Dict[str, List[str]] = dict(routes) if routes else dict(DEFAULT_ROUTES)

    # -- persistence -------------------------------------------------------
    def _log(
        self,
        severity: str,
        title: str,
        channel: str,
        destination: str,
        status: str,
        detail: str = "",
    ) -> int:
        with self.db.lock:
            with self.db.connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO alert_log
                        (created_at, severity, title, channel, destination, status, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (_utc(), severity, title, channel, destination, status, detail[:2000]),
                )
                conn.commit()
                return int(cur.lastrowid)

    def fetch_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.db.lock:
            with self.db.connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM alert_log ORDER BY log_id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    # -- dedup -------------------------------------------------------------
    @staticmethod
    def _dedup_key(severity: str, title: str) -> str:
        return hashlib.sha256(f"{severity}\x00{title}".encode("utf-8")).hexdigest()

    def _recently_dispatched(self, key: str) -> bool:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.dedup_window_s)
        with self.db.lock:
            with self.db.connect() as conn:
                rows = conn.execute(
                    "SELECT created_at, detail, status FROM alert_log ORDER BY log_id DESC LIMIT 500"
                ).fetchall()
        for row in rows:
            try:
                detail = json.loads(row["detail"] or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            if detail.get("dedup_key") != key or row["status"] == "deduped":
                continue
            try:
                ts = datetime.strptime(row["created_at"], "%Y-%m-%d %H:%M:%S UTC").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                continue
            if ts >= cutoff:
                return True
        return False

    # -- channels ----------------------------------------------------------
    def send_email(
        self, to: str, subject: str, body: str, dry_run: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Send an email. In dry-run mode no network is touched."""
        eff_dry = self.dry_run if dry_run is None else dry_run
        if eff_dry:
            log_id = self._log("n/a", subject, "email", to, "dry_run",
                               json.dumps({"mode": "dry_run", "body_chars": len(body)}))
            return {"ok": True, "mode": "dry_run", "destination": to, "log_id": log_id}
        try:
            msg = EmailMessage()
            msg["From"] = self.smtp_user or "soc@pak-cyberpulse.local"
            msg["To"] = to
            msg["Subject"] = subject
            msg.set_content(body)
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as smtp:
                if self.smtp_user:
                    smtp.starttls()
                    smtp.login(self.smtp_user, self.smtp_password or "")
                smtp.send_message(msg)
        except Exception as exc:  # honest failure record
            log_id = self._log("n/a", subject, "email", to, "failed",
                               json.dumps({"error": str(exc)}))
            return {"ok": False, "mode": "live", "destination": to,
                    "error": str(exc), "log_id": log_id}
        log_id = self._log("n/a", subject, "email", to, "sent",
                           json.dumps({"mode": "live", "smtp": f"{self.smtp_host}:{self.smtp_port}"}))
        return {"ok": True, "mode": "live", "destination": to, "log_id": log_id}

    def send_webhook(
        self, url: str, payload: Dict[str, Any], timeout: int = 5,
        dry_run: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """POST a JSON payload. In dry-run mode no network is touched.
        Exceptions are recorded honestly as failed."""
        eff_dry = self.dry_run if dry_run is None else dry_run
        if eff_dry:
            log_id = self._log(
                "n/a", payload.get("title", ""), "webhook", url, "dry_run",
                json.dumps({"mode": "dry_run", "payload_chars": len(json.dumps(payload))}),
            )
            return {"ok": True, "mode": "dry_run", "destination": url, "log_id": log_id}
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json", "User-Agent": "Pak-CyberPulse/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status_code = resp.status
                body = resp.read(4096).decode("utf-8", "replace")
        except Exception as exc:
            log_id = self._log("n/a", payload.get("title", ""), "webhook", url, "failed",
                               json.dumps({"error": str(exc)}))
            return {"ok": False, "destination": url, "error": str(exc), "log_id": log_id}
        ok = 200 <= status_code < 300
        log_id = self._log(
            "n/a", payload.get("title", ""), "webhook", url,
            "sent" if ok else "failed",
            json.dumps({"http_status": status_code, "response": body[:500]}),
        )
        return {"ok": ok, "destination": url, "http_status": status_code, "log_id": log_id}

    # -- dispatch ----------------------------------------------------------
    def dispatch(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Route an alert dict with keys:
          severity, title, body, destinations {"email": [...], "webhook": [...]}
        Returns the list of delivery records.
        """
        severity = str(alert.get("severity", "Medium"))
        title = str(alert.get("title", "untitled"))
        body = str(alert.get("body", ""))
        destinations = alert.get("destinations") or {}
        key = self._dedup_key(severity, title)

        if self._recently_dispatched(key):
            self._log(severity, title, "dedup", "-",
                      "deduped", json.dumps({"dedup_key": key}))
            return [{"ok": False, "suppressed": True, "reason": "deduped",
                     "dedup_key": key, "title": title}]

        records: List[Dict[str, Any]] = []
        channels = self.routes.get(severity, [])
        payload = {
            "title": title,
            "severity": severity,
            "body": body,
            "time": _utc(),
            "source": "pak-cyberpulse",
        }
        if "email" in channels:
            for to in destinations.get("email", []):
                rec = self.send_email(to, f"[{severity}] {title}", body)
                rec.update({"channel": "email", "dedup_key": key})
                self._stamp_key(rec.get("log_id"), key)
                records.append(rec)
        if "webhook" in channels:
            for url in destinations.get("webhook", []):
                rec = self.send_webhook(url, payload)
                rec.update({"channel": "webhook", "dedup_key": key})
                self._stamp_key(rec.get("log_id"), key)
                records.append(rec)
        return records

    def _stamp_key(self, log_id: Optional[int], key: str) -> None:
        if not log_id:
            return
        with self.db.lock:
            with self.db.connect() as conn:
                row = conn.execute(
                    "SELECT detail FROM alert_log WHERE log_id = ?", (log_id,)
                ).fetchone()
                detail = {}
                if row and row["detail"]:
                    try:
                        detail = json.loads(row["detail"])
                    except (json.JSONDecodeError, TypeError):
                        detail = {"raw": row["detail"]}
                detail["dedup_key"] = key
                conn.execute(
                    "UPDATE alert_log SET detail = ? WHERE log_id = ?",
                    (json.dumps(detail), log_id),
                )
                conn.commit()


# ---------------------------------------------------------------------------
# Streamlit panel
# ---------------------------------------------------------------------------
def render_alerting_panel(dispatcher: Optional[AlertDispatcher] = None) -> None:
    disp = dispatcher or AlertDispatcher()
    st.subheader("Alert dispatch — email + webhook")

    mode = "DRY-RUN (no network)" if disp.dry_run else "LIVE"
    st.markdown(
        f'<div class="cp-banner cp-action">MODE: {mode} — every attempt is logged honestly.</div>',
        unsafe_allow_html=True,
    )

    st.markdown("**Routing per severity**")
    for sev in ["Critical", "High", "Medium", "Low"]:
        current = disp.routes.get(sev, [])
        chosen = st.multiselect(
            f"{sev} channels", ["email", "webhook"], default=current, key=f"route_{sev}"
        )
        disp.routes[sev] = chosen

    st.markdown("**Send a test alert (dry-run)**")
    col1, col2 = st.columns(2)
    with col1:
        test_sev = st.selectbox("Severity", ["Critical", "High", "Medium", "Low"])
        test_email = st.text_input("Test email destination", "soc@example.pk")
    with col2:
        test_url = st.text_input("Test webhook URL", "https://example.pk/hook")
    if st.button("Dispatch test alert"):
        records = disp.dispatch(
            {
                "severity": test_sev,
                "title": "Pak-CyberPulse test alert",
                "body": "Dry-run dispatch from the alerting panel.",
                "destinations": {"email": [test_email], "webhook": [test_url]},
            }
        )
        st.json(records)

    st.markdown("**Delivery log**")
    rows = disp.fetch_log(limit=50)
    if rows:
        st.dataframe(rows, use_container_width=True)
    else:
        st.caption("No delivery attempts recorded yet.")
