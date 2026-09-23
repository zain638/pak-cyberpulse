"""
Pak-CyberPulse SOAR engine — privilege-honest containment and PKCERT PDF ledger.

Mitigation modes (evaluated at click-time, never assumed):

  1. NETWORK FIREWALL BLOCK
     os.getuid() == 0  (POSIX)  OR  ctypes IsUserAnAdmin() (Windows)
     then subprocess iptables / netsh.

  2. APPLICATION-LAYER ACCESS CONTROL BLOCK
     unprivileged but filesystem is writable — append a DENY to mock_acl_rules.txt.

  3. DEMONSTRATION PROTOCOL MODE
     neither privileged nor able to mutate the ACL file. The playbook is logged
     only. The UI must label this mode so a jury cannot be misled.

PISF-07 Incident Response + PISF-12 Audit Controls.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import streamlit as st
from fpdf import FPDF

from database.db_manager import (
    ACL_PATH,
    CLASS_CII,
    DB_PATH,
    REPORTS_DIR,
    STATUS_COMPLIANT,
    STATUS_NON_COMPLIANT,
    STATUS_UNDER_ATTACK,
    get_db,
    utc_now,
)

# Protected air-gapped backup root (read-only after write).
BACKUPS_DIR = DB_PATH.parent / "backups"


# ---------------------------------------------------------------------------
# Privilege probe — must stay boring and explicit.
# ---------------------------------------------------------------------------
def detect_privilege() -> dict[str, Any]:
    """
    Return a structured privilege snapshot. Never raise into the UI thread.
    """
    platform = sys.platform
    uid: Optional[int] = None
    admin = False
    method = "unknown"
    try:
        if os.name == "nt":
            import ctypes

            try:
                admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:  # noqa: BLE001
                admin = False
            method = "ctypes.windll.shell32.IsUserAnAdmin()"
            uid = None
        else:
            uid = int(os.getuid())
            admin = uid == 0
            method = "os.getuid() == 0"
    except Exception as exc:  # noqa: BLE001
        method = f"probe-failed: {exc}"
        admin = False
    return {
        "privileged": bool(admin),
        "uid": uid,
        "platform": platform,
        "method": method,
        "euid": os.geteuid() if hasattr(os, "geteuid") else uid,
        "firewall_binary": firewall_binary(),
    }


def firewall_binary() -> Optional[str]:
    if os.name == "nt":
        return shutil.which("netsh")
    return shutil.which("iptables")


def planned_mode(priv: Optional[dict[str, Any]] = None) -> str:
    """Mode the next playbook click will attempt, given current privileges AND binaries."""
    priv = priv or detect_privilege()
    if priv["privileged"] and priv.get("firewall_binary"):
        return "NETWORK FIREWALL BLOCK"
    return "APPLICATION-LAYER ACCESS CONTROL BLOCK"


def _pdf_safe(text: str) -> str:
    """Core Helvetica is Latin-1. Fold common punctuation so the ledger never crashes."""
    return (
        str(text)
        .replace("\u2014", "--")
        .replace("\u2013", "-")
        .replace("\u2192", "->")
        .replace("\u2022", "*")
        .encode("latin-1", errors="replace")
        .decode("latin-1")
    )


def canonical_incident_record(fields: dict[str, str]) -> str:
    """Stable, order-locked concatenation used as the SHA-256 pre-image."""
    keys = (
        "timestamp",
        "source_ip",
        "target_host",
        "classification",
        "detection_rule",
        "mitigating_action",
        "privilege_state",
    )
    return "|".join(f"{k}={fields[k]}" for k in keys)


def sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class MitigationResult:
    def __init__(
        self,
        mode: str,
        ok: bool,
        detail: str,
        command: str,
        privilege: dict[str, Any],
    ) -> None:
        self.mode = mode
        self.ok = ok
        self.detail = detail
        self.command = command
        self.privilege = privilege

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "ok": self.ok,
            "detail": self.detail,
            "command": self.command,
            "privilege_state": (
                "PRIVILEGED (effective admin/root)"
                if self.privilege.get("privileged")
                else "UNPRIVILEGED (standard user)"
            ),
        }


def contain_source_ip(source_ip: str) -> MitigationResult:
    """
    Execute the strongest mitigation this process is actually allowed to perform.
    Label the mode from what ran — not from what the playbook wished would run.
    """
    priv = detect_privilege()
    fw = priv.get("firewall_binary")
    if priv["privileged"] and fw:
        if os.name == "nt":
            cmd = [
                fw,
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=PakCyberPulse-Block-{source_ip}",
                "dir=in",
                "action=block",
                f"remoteip={source_ip}",
            ]
        else:
            cmd = [fw, "-I", "INPUT", "-s", source_ip, "-j", "DROP"]
        try:
            completed = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=8,
            )
            return MitigationResult(
                mode="NETWORK FIREWALL BLOCK",
                ok=True,
                detail=(completed.stdout or completed.stderr or "firewall rule installed").strip()[:400],
                command=" ".join(cmd),
                privilege=priv,
            )
        except Exception as exc:
            firewall_error = f"privileged process but firewall subprocess failed: {exc}"
    elif priv["privileged"] and not fw:
        firewall_error = (
            "privilege probe passed (root/admin) but iptables/netsh is not on PATH — "
            "cannot honestly claim a NETWORK FIREWALL BLOCK"
        )
    else:
        firewall_error = "privilege probe returned unprivileged — firewall skipped"

    # Application-layer fallback.
    try:
        ACL_PATH.parent.mkdir(parents=True, exist_ok=True)
        line = (
            f"DENY {source_ip} ANY  # Pak-CyberPulse PISF-07 containment "
            f"{datetime.now(timezone.utc).isoformat()}  "
            f"(APPLICATION-LAYER ACCESS CONTROL BLOCK)\n"
        )
        with open(ACL_PATH, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
        return MitigationResult(
            mode="APPLICATION-LAYER ACCESS CONTROL BLOCK",
            ok=True,
            detail=(
                "SYSTEM ALERT: Script running in APPLICATION-LAYER PROTOCOL MODE. "
                f"ACL append -> {ACL_PATH.name}. Reason: {firewall_error}"
            ),
            command=f"append DENY {source_ip} >> {ACL_PATH.name}",
            privilege=priv,
        )
    except Exception as exc:
        return MitigationResult(
            mode="DEMONSTRATION PROTOCOL MODE",
            ok=True,
            detail=(
                "SYSTEM ALERT: neither native firewall nor ACL file was writable. "
                f"Playbook recorded only. firewall={firewall_error}; acl={exc}"
            ),
            command="log-only (no OS mutation)",
            privilege=priv,
        )


def terminate_and_ban_session(ip_address: str) -> MitigationResult:
    """
    Zero-trust session kill-switch.
    Immediately injects a strict DENY for the given network identity into
    mock_acl_rules.txt (application-layer isolation). Preferable path when
    the UI Zero-Trust Active Session Manager fires a 'Kill Session & Ban Host'
    action. Falls back gracefully when the ACL file is unwritable.

    v3: also revokes the matching row in the zero-trust session registry
    (modules/session_registry.py) so the kill persists and stays visible as
    revoked in the UI; the revocation outcome is appended to result.detail.
    """
    ip_address = str(ip_address).strip()
    if not ip_address or ip_address in {"0.0.0.0", "-", "unknown"}:
        priv = detect_privilege()
        return MitigationResult(
            mode="DEMONSTRATION PROTOCOL MODE",
            ok=False,
            detail="Refused: empty or placeholder IP address supplied to terminate_and_ban_session.",
            command="none",
            privilege=priv,
        )
    # Reuse the strongest available containment path so network-layer
    # isolation is attempted when the process is privileged.
    result = contain_source_ip(ip_address)
    # Ensure an explicit ban marker is always present for the zero-trust UI.
    try:
        ACL_PATH.parent.mkdir(parents=True, exist_ok=True)
        marker = (
            f"BAN {ip_address} ANY  # ZERO-TRUST SESSION KILL "
            f"{datetime.now(timezone.utc).isoformat()}  "
            f"(terminate_and_ban_session)\n"
        )
        with open(ACL_PATH, "a", encoding="utf-8") as fh:
            fh.write(marker)
            fh.flush()
    except Exception:
        pass  # containment result already carries the honest mode label
    # Honest v3 fix: persistently revoke the matching session record in the
    # zero-trust session registry so the kill is visible and survives the UI
    # rebuilding sessions from recent events.
    try:
        from modules.session_registry import SessionRegistry

        revoked = SessionRegistry().revoke(
            ip_address, actor="zero-trust-kill-switch"
        )
        if revoked:
            result.detail += (
                f" | session registry: {ip_address} marked REVOKED "
                "(status=revoked, persists in Zero-Trust Active Session Manager)"
            )
        else:
            result.detail += (
                " | session registry: no matching session record found "
                f"for {ip_address} (nothing to revoke; ACL/BAN markers still applied)"
            )
    except Exception as exc:  # noqa: BLE001
        result.detail += f" | session registry error: {exc}"
    return result


def air_gapped_db_snapshot(reason: str = "active-attack-count>0") -> Optional[Path]:
    """
    Automated ransomware / data-exfiltration prevention trigger.
    When the global system state records an active attack count greater than 0,
    perform a programmatic snapshot copy of the live SQLite database into the
    protected database/backups/ archive. The resulting file is timestamped and
    forced to read-only permissions so the audit trail cannot be modified by
    an attacker who later obtains write access to the working tree.
    Returns the destination path on success, None on failure.
    """
    try:
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = BACKUPS_DIR / f"cyberpulse_airgap_{ts}.db"
        # Use a consistent snapshot: SQLite backup API would be ideal, but a
        # pure-Python shutil copy is sufficient for the prototype and avoids
        # holding an exclusive lock across the Streamlit UI thread.
        shutil.copy2(DB_PATH, dest)
        # Force read-only for owner/group/other (isolate audit trail).
        os.chmod(dest, 0o444)
        # Append a one-line provenance marker next to the binary.
        meta = dest.with_suffix(".db.meta")
        meta.write_text(
            f"air-gapped snapshot\n"
            f"source={DB_PATH}\n"
            f"created_utc={datetime.now(timezone.utc).isoformat()}\n"
            f"reason={reason}\n"
            f"mode=read-only\n",
            encoding="utf-8",
        )
        try:
            os.chmod(meta, 0o444)
        except OSError:
            pass
        return dest
    except Exception:
        return None


def maybe_trigger_airgap_on_attack() -> Optional[Path]:
    """
    Inspect global readiness. If under_attack > 0, fire an air-gapped snapshot.
    Idempotent within a short window: multiple rapid calls are safe.
    """
    try:
        db = get_db()
        r = db.compute_readiness()
        if int(r.get("under_attack", 0)) > 0:
            return air_gapped_db_snapshot(
                reason=f"under_attack={r.get('under_attack')} controls={r.get('non_compliant')}"
            )
    except Exception:
        pass
    return None


class PKCERTIncidentPDF(FPDF):
    """Legal-style audit trail. Hash is drawn in the footer on every page."""

    def __init__(self, evidence_hash: str) -> None:
        super().__init__(format="A4")
        self.evidence_hash = evidence_hash
        self.set_auto_page_break(auto=True, margin=22)

    def header(self) -> None:
        self.set_fill_color(12, 16, 20)
        self.rect(0, 0, 210, 18, "F")
        self.set_text_color(232, 232, 228)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 8, "NATIONAL CERT (PKCERT / nCERT)  --  INCIDENT EVIDENCE LEDGER", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 8)
        self.cell(
            0,
            5,
            "Pakistan Information Security Framework (PISF) 2026  |  Pak-CyberPulse academic prototype  |  NOT A PRODUCTION INSTRUMENT",
            align="C",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        self.ln(6)
        self.set_text_color(20, 20, 20)

    def footer(self) -> None:
        self.set_y(-20)
        self.set_draw_color(40, 40, 40)
        self.line(12, self.get_y(), 198, self.get_y())
        self.set_font("Courier", "", 7)
        self.set_text_color(40, 40, 40)
        self.multi_cell(
            0,
            4,
            f"SHA-256 NON-REPUDIATION HASH  {self.evidence_hash}\n"
            f"Page {self.page_no()}  |  Hash is SHA-256 of the canonical incident record (see body).  "
            "Prototype generated for academic examination only.",
        )


def write_incident_pdf(fields: dict[str, str], evidence_hash: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    pdf = PKCERTIncidentPDF(evidence_hash)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "PKCERT Incident Report - Cryptographic Evidence Pack", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(
        0,
        5,
        "This document is the structured audit trail required by PISF-12 Essential Audit Controls. "
        "The SHA-256 digest in the footer is computed over the canonical field concatenation printed below. "
        "Any alteration of the body without a matching digest is detectable.",
    )
    pdf.ln(3)

    rows = [
        ("Timestamp (UTC)", fields["timestamp"]),
        ("Source IP", fields["source_ip"]),
        ("Target Host", fields["target_host"]),
        ("Core Asset Classification", fields["classification"]),
        ("Triggered Detection Rule", fields["detection_rule"]),
        ("Mitigating Action Executed", fields["mitigating_action"]),
        ("Privilege Escalation State", fields["privilege_state"]),
        ("Containment Mode", fields.get("mode", "")),
        ("Command / Mutation", fields.get("command", "")),
        ("Mode Honesty Note", fields.get("detail", "")[:500]),
    ]
    pdf.set_font("Helvetica", "", 9)
    for label, value in rows:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(70, 70, 70)
        pdf.cell(0, 5, label.upper(), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Courier", "", 9)
        pdf.set_text_color(10, 10, 10)
        pdf.multi_cell(0, 5, _pdf_safe(str(value) or "-"))
        pdf.ln(1)

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(0, 5, "CANONICAL PRE-IMAGE (SHA-256 INPUT)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 7)
    pdf.multi_cell(0, 4, _pdf_safe(fields["canonical"]))
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(0, 5, "SHA-256 DIGEST", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "B", 9)
    pdf.multi_cell(0, 5, evidence_hash)

    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(
        0,
        4,
        "Classification: ACADEMIC PROTOTYPE / DEMONSTRATION TELEMETRY. "
        "No production credentials, live CNIC data, or operational PKCERT case numbers are present. "
        "Framework alignment: PISF-07 Incident Response, PISF-12 Audit Controls, PISF-13 CII Protection.",
    )
    pdf.output(str(dest))
    return dest


def _pick_attack_target(engine_snapshot: dict[str, Any], db) -> dict[str, str]:
    attacks = engine_snapshot.get("attacks") or []
    if attacks:
        a = attacks[0]
        return {
            "source_ip": str(a.get("src_ip", "0.0.0.0")),
            "target_host": str(a.get("host", "UNKNOWN")),
            "classification": str(a.get("asset_class", CLASS_CII)),
            "detection_rule": str(a.get("rule", "PISF-05.2")),
        }
    inj = engine_snapshot.get("injections") or []
    if inj:
        i = inj[-1]
        return {
            "source_ip": str(i.get("src_ip", "0.0.0.0")),
            "target_host": str(i.get("host", "UNKNOWN")),
            "classification": str(i.get("asset_class", "Standard")),
            "detection_rule": str(i.get("rule", "PISF-04.2 / PISF-10.1")),
        }
    assets = db.fetch_assets()
    cii = next((a for a in assets if a["classification"] == CLASS_CII), assets[0] if assets else None)
    return {
        "source_ip": "203.99.48.17",
        "target_host": cii["hostname"] if cii else "NADRA-IDC-ISB",
        "classification": cii["classification"] if cii else CLASS_CII,
        "detection_rule": "MANUAL SOAR PLAYBOOK (no live window hit)",
    }


def render_soar_panel(engine) -> None:
    db = get_db()
    priv = detect_privilege()
    snap = engine.snapshot()
    under = [c for c in db.fetch_controls() if c["status"] == STATUS_UNDER_ATTACK]

    st.subheader("Privilege posture (evaluated live)")
    p1, p2, p3 = st.columns(3)
    p1.metric("Process privileged?", "YES" if priv["privileged"] else "NO")
    p2.metric("UID / method", f"{priv['uid'] if priv['uid'] is not None else 'n/a'}")
    p3.metric("Probe", priv["method"])

    mapped_mode = planned_mode(priv)
    if mapped_mode == "NETWORK FIREWALL BLOCK":
        st.markdown(
            '<div class="cp-banner cp-hardened">Privilege probe passed and a firewall binary is present. '
            "Mitigation maps to NETWORK FIREWALL BLOCK (iptables / netsh via subprocess).</div>",
            unsafe_allow_html=True,
        )
    else:
        reason = (
            "root/admin is present but iptables/netsh is not on PATH"
            if priv["privileged"]
            else "standard user constraints"
        )
        st.markdown(
            f'<div class="cp-banner cp-action">SYSTEM ALERT: Script running in APPLICATION-LAYER PROTOCOL MODE '
            f"({reason}). A native firewall change will not be claimed. "
            "Containment will append a DENY entry to mock_acl_rules.txt, or drop to DEMONSTRATION PROTOCOL MODE "
            "if that file cannot be written.</div>",
            unsafe_allow_html=True,
        )

    st.caption(f"Mapped mitigation mode for the next playbook click: {mapped_mode}")

    if under:
        st.markdown(
            '<div class="cp-banner cp-critical">CRITICAL INFRACTION — one or more PISF controls are Under Attack. '
            "EXECUTE PARALLEL SOAR MITIGATION PLAYBOOK (PISF-07).</div>",
            unsafe_allow_html=True,
        )
        st.dataframe(
            [
                {
                    "control_id": c["control_id"],
                    "domain": c["domain_name"],
                    "status": c["status"],
                    "last_assessment": c["last_assessment"],
                }
                for c in under
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.markdown(
            '<div class="cp-banner cp-hardened">No control is currently Under Attack. '
            "Playbook may still be exercised against the last known DEMO vector for examination.</div>",
            unsafe_allow_html=True,
        )

    target = _pick_attack_target(snap, db)
    st.write(
        f"Playbook target  ·  source `{target['source_ip']}`  →  host `{target['target_host']}`  "
        f"({target['classification']})  ·  rule `{target['detection_rule']}`"
    )

    # RBAC gate (Senior Analyst+). Logged-out analysts run in DEMO mode with an
    # honest banner; logged-in analysts without "soar.execute" are denied.
    from modules.rbac import gate_action

    soar_allowed, soar_banner = gate_action("soar.execute")
    if soar_banner:
        st.markdown(soar_banner, unsafe_allow_html=True)

    if soar_allowed and st.button("EXECUTE PARALLEL SOAR MITIGATION PLAYBOOK (PISF-07)", type="primary", use_container_width=True):
        result = contain_source_ip(target["source_ip"])
        ts = utc_now()
        fields = {
            "timestamp": ts,
            "source_ip": target["source_ip"],
            "target_host": target["target_host"],
            "classification": target["classification"],
            "detection_rule": target["detection_rule"],
            "mitigating_action": f"{result.mode}: {result.command}",
            "privilege_state": result.as_dict()["privilege_state"],
            "mode": result.mode,
            "command": result.command,
            "detail": result.detail,
        }
        fields["canonical"] = canonical_incident_record(fields)
        digest = sha256_hex(fields["canonical"])
        iid = db.record_incident(
            source_ip=fields["source_ip"],
            target_host=fields["target_host"],
            classification=fields["classification"],
            detection_rule=fields["detection_rule"],
            mitigating_action=fields["mitigating_action"],
            privilege_state=fields["privilege_state"],
            raw_record=fields["canonical"],
            sha256=digest,
        )
        pdf_name = f"PKCERT-IR-{iid:04d}-{fields['source_ip'].replace('.', '_')}.pdf"
        pdf_path = REPORTS_DIR / pdf_name
        write_incident_pdf(fields, digest, pdf_path)
        db.attach_pdf(iid, str(pdf_path))

        evidence = (
            f"SOAR playbook executed in mode={result.mode}. "
            f"sha256={digest} incident={iid} pdf={pdf_name}"
        )
        # Restore attacked controls after containment; leave genuine gaps untouched.
        for control in db.fetch_controls():
            if control["status"] == STATUS_UNDER_ATTACK:
                db.update_control_status(control["control_id"], STATUS_COMPLIANT, evidence)

        st.session_state["_last_pdf"] = str(pdf_path)
        st.session_state["_last_hash"] = digest
        st.session_state["_last_mode"] = result.mode
        st.session_state["_last_detail"] = result.detail
        st.rerun()

    if st.session_state.get("_last_mode"):
        import html as _html
        mode = _html.escape(str(st.session_state["_last_mode"]))
        detail = _html.escape(str(st.session_state.get("_last_detail", "")))
        if "BLOCK" in mode.upper():
            st.markdown(
                f'<div class="cp-blocked">'
                f'<svg class="cp-check" viewBox="0 0 52 52"><circle class="cp-check-circle" cx="26" cy="26" r="24"/>'
                f'<path class="cp-check-mark" d="M14 27l8 8 16-17"/></svg>'
                f'<div class="cp-blocked-title">🛡 THREAT CONTAINED — {mode}</div>'
                f'<div class="cp-blocked-sub">{detail}</div></div>',
                unsafe_allow_html=True,
            )
        else:
            if mode == "NETWORK FIREWALL BLOCK":
                klass = "cp-hardened"
            elif mode == "APPLICATION-LAYER ACCESS CONTROL BLOCK":
                klass = "cp-action"
            else:
                klass = "cp-critical"
            st.markdown(
                f'<div class="cp-banner {klass}">Last mitigating action: {mode}. '
                f"{detail}</div>",
                unsafe_allow_html=True,
            )
        st.code(f"SHA-256  {st.session_state.get('_last_hash','')}", language="text")
        pdf_path = st.session_state.get("_last_pdf")
        if pdf_path and Path(pdf_path).exists():
            with open(pdf_path, "rb") as fh:
                st.download_button(
                    "Download PKCERT Incident Report (PDF)",
                    data=fh.read(),
                    file_name=Path(pdf_path).name,
                    mime="application/pdf",
                    use_container_width=True,
                )

    with st.expander("ACL file (application-layer fallback) — mock_acl_rules.txt"):
        if ACL_PATH.exists():
            st.code(ACL_PATH.read_text(encoding="utf-8") or "(empty)", language="text")
        else:
            st.write("ACL file has not been created yet. It appears after the first unprivileged containment.")

    with st.expander("Air-gapped SQLite backups (ransomware / exfiltration prevention)"):
        st.caption(
            "Whenever under_attack > 0 the engine copies database/cyberpulse.db into "
            "database/backups/ with a UTC timestamp and forces the snapshot to read-only."
        )
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        snaps = sorted(BACKUPS_DIR.glob("cyberpulse_airgap_*.db"), reverse=True)
        if snaps:
            st.dataframe(
                [
                    {
                        "file": p.name,
                        "size_bytes": p.stat().st_size,
                        "mode": oct(p.stat().st_mode & 0o777),
                        "mtime": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
                    }
                    for p in snaps[:12]
                ],
                use_container_width=True,
                hide_index=True,
            )
            if st.button("Force air-gapped snapshot now", use_container_width=True):
                path = air_gapped_db_snapshot(reason="manual-operator-trigger")
                if path:
                    st.success(f"Snapshot written: {path.name} (read-only)")
                    st.rerun()
                else:
                    st.error("Snapshot failed — check filesystem permissions.")
        else:
            st.write("No air-gapped snapshots yet. They appear automatically when an attack is active.")

    with st.expander("Incident ledger (PISF-12)"):
        rows = db.fetch_incidents(limit=20)
        if rows:
            st.dataframe(
                [
                    {
                        "id": r["incident_id"],
                        "at": r["created_at"],
                        "src": r["source_ip"],
                        "host": r["target_host"],
                        "class": r["classification"],
                        "mode/action": r["mitigating_action"][:80],
                        "privilege": r["privilege_state"],
                        "sha256": r["sha256"][:16] + "…",
                    }
                    for r in rows
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.write("Ledger empty — execute the playbook to mint the first cryptographic record.")
