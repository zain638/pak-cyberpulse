"""
Pak-CyberPulse MITRE ATT&CK mapping.

Best-effort, honest mapping of every Pak-CyberPulse attack-pattern id to a
real MITRE ATT&CK technique (https://attack.mitre.org). Technique ids,
names and tactics follow the ATT&CK knowledge base; where a pattern spans
more than one technique the closest single technique is chosen and the
choice is documented in the panel.

No network access: the mapping is a static registry.
"""

from __future__ import annotations

from typing import Any, Optional

import streamlit as st

from modules.attack_patterns import PATTERN_BY_ID

ATTACK_BASE = "https://attack.mitre.org/techniques"


def _url(tid: str) -> str:
    """Technique URL, e.g. T1110/001/ for T1110.003."""
    parts = tid.split(".")
    return f"{ATTACK_BASE}/{'/'.join(parts)}/"


# pattern_id -> real ATT&CK technique mapping
TECHNIQUES: dict[str, dict[str, Any]] = {
    # -- signature patterns -------------------------------------------------
    "SQLI": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
    },
    "XSS": {
        "technique_id": "T1189",
        "technique": "Drive-by Compromise",
        "tactics": ["Initial Access"],
    },
    "CMDI": {
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
    },
    "SSTI": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
    },
    "LOG4SHELL": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
    },
    "SSRF": {
        "technique_id": "T1090",
        "technique": "Proxy",
        "tactics": ["Command and Control"],
    },
    "LFI_TRAVERSAL": {
        "technique_id": "T1005",
        "technique": "Data from Local System",
        "tactics": ["Collection"],
    },
    "MISCONFIG_PROBE": {
        "technique_id": "T1595.002",
        "technique": "Active Scanning: Vulnerability Scanning",
        "tactics": ["Reconnaissance"],
    },
    "DESERIAL": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
    },
    "SECRET_IN_URL": {
        "technique_id": "T1552",
        "technique": "Unsecured Credentials",
        "tactics": ["Credential Access"],
    },
    "BAC_PROBE": {
        "technique_id": "T1083",
        "technique": "File and Directory Discovery",
        "tactics": ["Discovery"],
    },
    "BUSINESS_LOGIC_ABUSE": {
        "technique_id": "T1565.001",
        "technique": "Data Manipulation: Stored Data Manipulation",
        "tactics": ["Impact"],
    },
    # -- behavioral patterns ------------------------------------------------
    "BRUTEFORCE": {
        "technique_id": "T1110.001",
        "technique": "Brute Force: Password Guessing",
        "tactics": ["Credential Access"],
    },
    "PASSWORD_SPRAY": {
        "technique_id": "T1110.003",
        "technique": "Brute Force: Password Spraying",
        "tactics": ["Credential Access"],
    },
    "DISTRIBUTED_BRUTEFORCE": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactics": ["Credential Access"],
    },
    "IMPOSSIBLE_TRAVEL": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
    },
    "UEBA_ANOMALY": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
    },
    "EXFILTRATION": {
        "technique_id": "T1020",
        "technique": "Automated Exfiltration",
        "tactics": ["Exfiltration"],
    },
    "TELEMETRY_GAP": {
        "technique_id": "T1562",
        "technique": "Impair Defenses",
        "tactics": ["Defense Evasion"],
    },
}

for _pid, _m in TECHNIQUES.items():
    _m["url"] = _url(_m["technique_id"])
del _pid, _m


def get_mapping(pattern_id: str) -> Optional[dict[str, Any]]:
    """Return the ATT&CK mapping for a pattern id, or None if unknown."""
    m = TECHNIQUES.get(pattern_id)
    return dict(m) if m else None


def all_mappings() -> dict[str, dict[str, Any]]:
    """Full pattern-id -> mapping registry (copies)."""
    return {pid: dict(m) for pid, m in TECHNIQUES.items()}


def annotate_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Return a copy of *alert* annotated with MITRE keys:
    mitre_technique_id, mitre_technique, mitre_tactics, mitre_url.
    Alerts with an unknown pattern id are returned unchanged.
    """
    pattern_id = alert.get("pattern_id") or alert.get("classification") or ""
    mapping = TECHNIQUES.get(str(pattern_id).upper())
    if not mapping:
        return alert
    annotated = dict(alert)
    annotated["mitre_technique_id"] = mapping["technique_id"]
    annotated["mitre_technique"] = mapping["technique"]
    annotated["mitre_tactics"] = list(mapping["tactics"])
    annotated["mitre_url"] = mapping["url"]
    return annotated


def technique_coverage() -> dict[str, Any]:
    """Summary stats: techniques mapped, patterns covered, tactics touched."""
    tactics: dict[str, int] = {}
    technique_ids: set[str] = set()
    for m in TECHNIQUES.values():
        technique_ids.add(m["technique_id"])
        for t in m["tactics"]:
            tactics[t] = tactics.get(t, 0) + 1
    return {
        "mapped_patterns": len(TECHNIQUES),
        "total_patterns": len(PATTERN_BY_ID),
        "distinct_techniques": len(technique_ids),
        "tactics_covered": sorted(tactics),
        "tactic_counts": tactics,
    }


# ---------------------------------------------------------------------------
# Streamlit panel
# ---------------------------------------------------------------------------
def render_mitre_panel() -> None:
    """MITRE ATT&CK coverage panel: pattern -> technique -> tactics."""
    cov = technique_coverage()

    st.markdown(
        '<div class="cp-banner cp-hardened">'
        "<b>MITRE ATT&CK mapping.</b> Every detection pattern is mapped to a "
        "real ATT&CK technique so alerts carry tactic context. Mapping is a "
        "best-effort static registry — no live ATT&CK queries."
        "</div>",
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns(3)
    c1.metric("Patterns mapped", f"{cov['mapped_patterns']}/{cov['total_patterns']}")
    c2.metric("Distinct techniques", cov["distinct_techniques"])
    c3.metric("Tactics covered", len(cov["tactics_covered"]))

    st.subheader("Tactic coverage")
    for tactic in cov["tactics_covered"]:
        st.markdown(
            f"<span class='sev sev-medium'>{tactic}</span> "
            f"{cov['tactic_counts'][tactic]} pattern(s)",
            unsafe_allow_html=True,
        )

    st.subheader("Pattern -> technique map")
    rows = []
    for pid in sorted(TECHNIQUES, key=lambda p: PATTERN_BY_ID.get(p, {}).get("name", p)):
        m = TECHNIQUES[pid]
        pat = PATTERN_BY_ID.get(pid, {})
        rows.append(
            {
                "Pattern": f"{pid} — {pat.get('name', '')}",
                "Technique": f"{m['technique_id']} — {m['technique']}",
                "Tactics": ", ".join(m["tactics"]),
                "Reference": m["url"],
            }
        )
    st.dataframe(rows, use_container_width=True)

    st.subheader("ATT&CK references")
    for pid, m in sorted(TECHNIQUES.items()):
        st.markdown(
            f"**{pid}** → [{m['technique_id']} — {m['technique']}]({m['url']})",
        )
