"""
Pak-CyberPulse technical safeguards.

PISF-06  Data Protection and Privacy — labelled DEMO CNIC vectors + Fernet.
PISF-10  SSDLC — plaintext secret / password assignment scanner.
PISF-11  Supply Chain — SCA against an explicit internal vulnerable baseline.

OWASP Top 10 Detection & Attached Mitigation (live-log parsers live in the
SIEM tailer; this module exposes the signature catalogue and a callable
mitigation bridge so the GRC surface can re-trigger containment without
duplicating SOAR logic).

Educational safety: the Fernet key is generated per session, displayed masked,
and never written to the SIEM stream. Mock CNICs are clearly demarcated and
must match ^[0-9]{5}-[0-9]{7}-[0-9]{1}$.
"""

from __future__ import annotations

import re
from typing import Any, Optional

import streamlit as st
from cryptography.fernet import Fernet, InvalidToken

from database.db_manager import (
    STATUS_COMPLIANT,
    STATUS_NON_COMPLIANT,
    STATUS_UNDER_ATTACK,
    get_db,
    utc_now,
)

# ---------------------------------------------------------------------------
# OWASP Top 10 signature catalogue (shared with SIEM tailer semantics)
# ---------------------------------------------------------------------------
OWASP_SQLI_RE = re.compile(
    r"(?i)('\s*or\s+'?1'?\s*=\s*'?1)|union\s+select|drop\s+table|insert\s+into|"
    r"sleep\s*\(|xp_cmdshell|information_schema|select\s+.+\s+from"
)
OWASP_XSS_RE = re.compile(
    r"(?i)<script|javascript:|onerror\s*=|onload\s*=|<img\s+src=|document\.cookie|alert\s*\("
)
OWASP_BAC_RE = re.compile(
    r"(?i)(/admin|/config|/wp-admin|/phpmyadmin|/backup|/console|/actuator|/env|/debug|/swagger|/api/v1/admin|/internal)"
)


def scan_owasp_payload(message: str) -> list[str]:
    """Return list of OWASP class labels matched in a log / request line."""
    hits: list[str] = []
    if OWASP_SQLI_RE.search(message):
        hits.append("SQLi")
    if OWASP_XSS_RE.search(message):
        hits.append("XSS")
    if OWASP_BAC_RE.search(message):
        hits.append("BAC")
    return hits


def attach_owasp_mitigation(src_ip: str, signatures: list[str], evidence: str) -> dict[str, Any]:
    """
    Direct mitigation trigger: append the offending Source IP to
    mock_acl_rules.txt via the SOAR engine and mark the relevant system
    controls Non-Compliant / Under Attack in the database state.
    """
    db = get_db()
    db.update_control_status("PISF-04.2", STATUS_UNDER_ATTACK, evidence)
    db.update_control_status("PISF-10.1", STATUS_UNDER_ATTACK, evidence)
    if "BAC" in signatures:
        db.update_control_status("PISF-05.1", STATUS_UNDER_ATTACK, evidence + " (Broken Access Control)")
    result: dict[str, Any] = {"src_ip": src_ip, "signatures": signatures, "mitigated": False}
    try:
        from modules.soar_engine import contain_source_ip, maybe_trigger_airgap_on_attack

        mr = contain_source_ip(src_ip)
        maybe_trigger_airgap_on_attack()
        result["mitigated"] = bool(mr.ok)
        result["mode"] = mr.mode
        result["detail"] = mr.detail
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
    return result

CNIC_RE = re.compile(r"^[0-9]{5}-[0-9]{7}-[0-9]{1}$")

# Clearly demarcated demonstration vectors — NOT live citizen data.
DEMO_CNIC_VECTORS = (
    "35202-8451231-3",  # DEMO VECTOR — Lahore-pattern, synthetic
    "61101-1234567-1",  # DEMO VECTOR — Islamabad-pattern, synthetic
    "41303-9988776-5",  # DEMO VECTOR — Karachi-pattern, synthetic
)

DEMO_SOURCE_ARTEFACT = '''# DEMO source artefact — deliberately dirty for the PISF-10 token review.
# This file does not ship in production. All secrets below are fictional.

import os

db_password = "SuperSecret123"
API_KEY = "sk-live-nadra-demo-not-real"
secret = 'rotate-me-immediately'
token = os.environ.get("HONEST_TOKEN")  # this assignment is environment-backed (clean)
cnic = "35202-8451231-3"  # DEMO VECTOR — labelled mock CNIC
smtp_password="plain-in-kwargs"
# the next line is a comment: password = "ignored"
'''

DEMO_MANIFEST = """# DEMO package manifest (requirements-style). Not a production lockfile.
log4j-core==2.14.1
flask==2.3.3
django==3.0.10
requests==2.18.4
pyyaml==5.3.1
pillow==10.3.0
cryptography==44.0.0
urllib3==1.25.8
"""

# Explicit internal vulnerable baseline. A component is flagged when the
# parsed installed version is less than or equal to max_vulnerable.
VULN_BASELINE: dict[str, dict[str, str]] = {
    "log4j-core": {
        "max_vulnerable": "2.14.1",
        "cve": "CVE-2021-44228",
        "fixed": "2.17.1",
        "note": "Log4Shell — any 2.x at or below 2.14.1 is treated as exploitable.",
    },
    "django": {
        "max_vulnerable": "3.0.13",
        "cve": "CVE-2021-35042",
        "fixed": "3.2.21",
        "note": "Query-filter SQL injection class in 3.0.x / 3.1.x / 3.2 < 3.2.4.",
    },
    "requests": {
        "max_vulnerable": "2.19.1",
        "cve": "CVE-2018-18074",
        "fixed": "2.20.0",
        "note": "Remain-redirect credential leak.",
    },
    "pyyaml": {
        "max_vulnerable": "5.3.1",
        "cve": "CVE-2020-14343",
        "fixed": "5.4",
        "note": "FullLoader RCE via crafted YAML.",
    },
    "urllib3": {
        "max_vulnerable": "1.25.9",
        "cve": "CVE-2020-26137",
        "fixed": "1.25.10",
        "note": "CRLF injection in method / URL.",
    },
    "flask": {
        "max_vulnerable": "0.12.2",
        "cve": "CVE-2018-1000656",
        "fixed": "1.0",
        "note": "Pinned here to show a *clean* contrast against a known-bad pin.",
    },
    "pillow": {
        "max_vulnerable": "8.3.1",
        "cve": "CVE-2021-34552",
        "fixed": "8.3.2",
        "note": "Buffer overflow in Convert.c; 10.3.0 is above baseline (clean).",
    },
}

SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    ^\s*
    (?:
        (?P<name>\w*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|token))
        \s*=\s*
        (?P<q>['"])(?P<val>[^'"]+)(?P=q)
      |
        (?P<name2>\w*(?:password|passwd|secret|api[_-]?key))
        \s*=\s*
        (?P<val2>[^'\"\s#]+)
    )
    """
)


def mask_key(raw: bytes) -> str:
    text = raw.decode("utf-8")
    if len(text) < 12:
        return "••••••••"
    return f"{text[:4]}••••••••••••{text[-4:]}"


def parse_semver(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for token in re.split(r"[^\d]+", value.strip()):
        if token:
            parts.append(int(token))
    return tuple(parts) if parts else (0,)


def is_vulnerable(installed: str, max_vulnerable: str) -> bool:
    return parse_semver(installed) <= parse_semver(max_vulnerable)


def scan_secrets(source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for idx, line in enumerate(source.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        match = SECRET_ASSIGNMENT.search(line)
        if not match:
            continue
        name = match.group("name") or match.group("name2")
        val = match.group("val") or match.group("val2") or ""
        findings.append(
            {
                "line": idx,
                "identifier": name,
                "masked_value": (val[:2] + "•" * max(0, len(val) - 4) + val[-2:]) if len(val) > 4 else "••••",
                "excerpt": line.strip()[:120],
            }
        )
    return findings


def parse_manifest(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
        elif "@" in line:
            name, version = line.split("@", 1)
        else:
            name, version = line, "0"
        name = name.strip().lower()
        version = version.strip()
        baseline = VULN_BASELINE.get(name)
        if baseline and is_vulnerable(version, baseline["max_vulnerable"]):
            status = "VULNERABLE"
            note = f"{baseline['cve']} — {baseline['note']} (fixed in {baseline['fixed']})"
        elif baseline:
            status = "CLEAR"
            note = f"Installed {version} > {baseline['max_vulnerable']} ({baseline['cve']} gated)."
        else:
            status = "NO BASELINE"
            note = "Not in the internal vulnerable baseline dictionary."
        rows.append(
            {
                "component": name,
                "installed": version,
                "status": status,
                "note": note,
            }
        )
    return rows


def render_tech_panel() -> None:
    db = get_db()
    tabs = st.tabs(
        [
            "PISF-06  Data protection (CNIC / Fernet)",
            "PISF-10  Secret token review",
            "PISF-11  Software composition analysis",
        ]
    )

    # ------------------------------------------------------------------ 06
    with tabs[0]:
        st.markdown(
            '<div class="cp-banner cp-action">EDUCATIONAL SAFETY PARAMETER — '
            "this session uses an ephemeral Fernet key generated in-process. "
            "The production key block is MASKED. Never embed key material in source control, "
            "client logs, or SIEM streams. Production deployments must use a hardware-backed KMS.</div>",
            unsafe_allow_html=True,
        )
        if "fernet_key" not in st.session_state:
            st.session_state.fernet_key = Fernet.generate_key()
        key: bytes = st.session_state.fernet_key
        st.code(
            f"Fernet key (MASKED)  {mask_key(key)}\n"
            f"Algorithm             AES-128-CBC + HMAC-SHA256 (Fernet)\n"
            f"Lifetime              session-ephemeral — regenerated on server restart",
            language="text",
        )
        st.caption(
            "Labelled DEMO Pakistani CNIC vectors (format ^[0-9]{5}-[0-9]{7}-[0-9]{1}$). "
            "These are synthetic and must not be treated as citizen records."
        )
        st.code("\n".join(f"DEMO VECTOR  {v}" for v in DEMO_CNIC_VECTORS), language="text")

        plaintext = st.text_area(
            "Drop a DEMO CNIC (or any short string) to encrypt",
            value=DEMO_CNIC_VECTORS[0],
            height=80,
        ).strip()
        col_a, col_b = st.columns(2)
        with col_a:
            run = st.button("Validate format and encrypt (PISF-06)", use_container_width=True)
        with col_b:
            if st.button("Rotate ephemeral session key", use_container_width=True):
                st.session_state.fernet_key = Fernet.generate_key()
                st.session_state.pop("last_token", None)
                st.rerun()

        if run:
            if not CNIC_RE.match(plaintext):
                st.markdown(
                    '<div class="cp-banner cp-action">Format rejected. '
                    "A Pakistani CNIC test vector must match XXXXX-XXXXXXX-X. "
                    "Encryption was not attempted.</div>",
                    unsafe_allow_html=True,
                )
            else:
                token = Fernet(key).encrypt(plaintext.encode("utf-8"))
                st.session_state.last_token = token
                db.update_control_status(
                    "PISF-06.1",
                    STATUS_COMPLIANT,
                    f"DEMO CNIC vector encrypted under session Fernet key (masked). ts={utc_now()}",
                )
                db.update_control_status(
                    "PISF-06.2",
                    STATUS_COMPLIANT,
                    "Key-management hygiene demonstrated: ephemeral key, masked display, no SIEM leak.",
                )
                st.markdown(
                    '<div class="cp-banner cp-hardened">CNIC format valid. Ciphertext minted. '
                    "PISF-06.1 / PISF-06.2 marked Compliant with encryption evidence.</div>",
                    unsafe_allow_html=True,
                )
                st.code(token.decode("utf-8"), language="text")

        if st.session_state.get("last_token"):
            try:
                recovered = Fernet(key).decrypt(st.session_state.last_token).decode("utf-8")
                # Mask recovered CNIC for display — still a demo vector.
                masked_cnic = recovered[:3] + "••-•••••••-" + recovered[-1] if CNIC_RE.match(recovered) else recovered
                st.caption(f"Round-trip decrypt (masked for display): {masked_cnic}")
            except InvalidToken:
                st.warning("Token no longer decrypts under the current session key (rotation occurred).")

    # ------------------------------------------------------------------ 10
    with tabs[1]:
        st.write(
            "PISF-10.2 static token review. The scanner flags *assignments* of password / secret / "
            "api_key / token identifiers to string literals. Comments and environment lookups are ignored."
        )
        source = st.text_area("Source artefact", value=DEMO_SOURCE_ARTEFACT, height=240)
        if st.button("Run token review (PISF-10.2)", use_container_width=True):
            findings = scan_secrets(source)
            if findings:
                st.markdown(
                    f'<div class="cp-banner cp-action">ACTION REQUIRED — {len(findings)} plaintext secret '
                    "assignment(s). PISF-10.2 remains Non-Compliant until the artefact is cleaned and re-scanned.</div>",
                    unsafe_allow_html=True,
                )
                st.dataframe(findings, use_container_width=True, hide_index=True)
                db.update_control_status(
                    "PISF-10.2",
                    "Non-Compliant",
                    f"Token review raised {len(findings)} literal secret assignments.",
                )
            else:
                st.markdown(
                    '<div class="cp-banner cp-hardened">No plaintext secret assignments. '
                    "PISF-10.2 marked Compliant.</div>",
                    unsafe_allow_html=True,
                )
                db.update_control_status(
                    "PISF-10.2",
                    STATUS_COMPLIANT,
                    "Token review clean — no literal password/secret/api_key assignments.",
                )

    # ------------------------------------------------------------------ 11
    with tabs[2]:
        st.write(
            "PISF-11 software composition analysis. Each `name==version` line is compared with "
            "`parse_semver(installed) <= parse_semver(max_vulnerable)` against the internal baseline "
            "dictionary in this module — no live internet CVE feed is consulted, by design."
        )
        manifest = st.text_area("Package manifest", value=DEMO_MANIFEST, height=220)
        if st.button("Run SCA against internal baseline (PISF-11)", use_container_width=True):
            rows = parse_manifest(manifest)
            st.dataframe(rows, use_container_width=True, hide_index=True)
            vuln = [r for r in rows if r["status"] == "VULNERABLE"]
            if vuln:
                st.markdown(
                    f'<div class="cp-banner cp-action">ACTION REQUIRED — {len(vuln)} component(s) match the '
                    "vulnerable baseline. PISF-11.1 / PISF-11.2 marked Non-Compliant.</div>",
                    unsafe_allow_html=True,
                )
                evidence = "SCA hits: " + ", ".join(f"{r['component']}=={r['installed']}" for r in vuln)
                db.update_control_status("PISF-11.1", "Non-Compliant", evidence)
                db.update_control_status("PISF-11.2", "Non-Compliant", evidence)
            else:
                st.markdown(
                    '<div class="cp-banner cp-hardened">Manifest is clear of the internal baseline. '
                    "PISF-11 marked Compliant.</div>",
                    unsafe_allow_html=True,
                )
                db.update_control_status("PISF-11.1", STATUS_COMPLIANT, "SCA clean against internal baseline.")
                db.update_control_status("PISF-11.2", STATUS_COMPLIANT, "No third-party exception required.")

        with st.expander("Internal vulnerable baseline dictionary (explicit, version-pinned)"):
            st.dataframe(
                [
                    {
                        "component": k,
                        "max_vulnerable": v["max_vulnerable"],
                        "cve": v["cve"],
                        "fixed": v["fixed"],
                        "note": v["note"],
                    }
                    for k, v in VULN_BASELINE.items()
                ],
                use_container_width=True,
                hide_index=True,
            )
