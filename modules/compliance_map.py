"""
Pak-CyberPulse compliance mapping — PISF controls to external frameworks.

Best-effort, honest alignment references: each PISF control is mapped to real
control codes from NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, PCI-DSS 4.0, and
PECA 2016 (Pakistan). These mappings are alignment aids for gap analysis —
they are NOT certifications and must not be presented as such.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import streamlit as st

from database.db_manager import STATUS_COMPLIANT, DatabaseManager, get_db


FRAMEWORKS: Dict[str, str] = {
    "nist_csf_2_0": "NIST CSF 2.0",
    "iso_27001_2022": "ISO/IEC 27001:2022",
    "pci_dss_4": "PCI-DSS 4.0",
    "peca_2016": "PECA 2016 (Pakistan)",
}

# PISF control -> {framework_key: [real control references]}.
# NIST CSF 2.0: GV/ID/PR/DE/RS/RC functions with subcategory codes.
# ISO 27001:2022: Annex A codes A.5.x-A.8.x.
# PCI-DSS 4.0: requirement numbers (1-12) with sub-requirements.
# PECA 2016: section numbers of the Prevention of Electronic Crimes Act.
CONTROL_FRAMEWORK_MAP: Dict[str, Dict[str, List[str]]] = {
    # -- PISF-01 Governance -------------------------------------------------
    "PISF-01.1": {
        "nist_csf_2_0": ["GV.PO-01", "GV.RR-01"],
        "iso_27001_2022": ["A.5.1", "A.5.8"],
        "pci_dss_4": ["12.1.1"],
        "peca_2016": ["s.49", "s.43"],
    },
    "PISF-01.2": {
        "nist_csf_2_0": ["GV.RR-01", "GV.OV-01"],
        "iso_27001_2022": ["A.5.2", "A.5.4"],
        "pci_dss_4": ["12.4"],
        "peca_2016": ["s.43"],
    },
    "PISF-01.3": {
        "nist_csf_2_0": ["GV.OV-02", "ID.IM-01"],
        "iso_27001_2022": ["A.5.35", "A.5.1"],
        "pci_dss_4": ["12.5"],
        "peca_2016": ["s.43"],
    },
    # -- PISF-02 Asset & Risk ------------------------------------------------
    "PISF-02.1": {
        "nist_csf_2_0": ["ID.AM-01", "ID.AM-08"],
        "iso_27001_2022": ["A.5.9", "A.5.12"],
        "pci_dss_4": ["2.2"],
        "peca_2016": ["s.31"],
    },
    "PISF-02.2": {
        "nist_csf_2_0": ["ID.RA-01", "ID.RA-04"],
        "iso_27001_2022": ["A.5.7"],
        "pci_dss_4": ["12.3"],
        "peca_2016": ["s.43"],
    },
    # -- PISF-03 Training ----------------------------------------------------
    "PISF-03.1": {
        "nist_csf_2_0": ["PR.AT-01"],
        "iso_27001_2022": ["A.6.3"],
        "pci_dss_4": ["12.6.1"],
        "peca_2016": ["s.49"],
    },
    "PISF-03.2": {
        "nist_csf_2_0": ["PR.AT-02"],
        "iso_27001_2022": ["A.6.3"],
        "pci_dss_4": ["12.6.2"],
        "peca_2016": ["s.49"],
    },
    # -- PISF-04 System & Communication Protection ---------------------------
    "PISF-04.1": {
        "nist_csf_2_0": ["DE.CM-01", "PR.IR-01"],
        "iso_27001_2022": ["A.8.16", "A.8.20"],
        "pci_dss_4": ["11.4", "11.4.1"],
        "peca_2016": ["s.4", "s.10"],
    },
    "PISF-04.2": {
        "nist_csf_2_0": ["DE.CM-02", "PR.PS-02"],
        "iso_27001_2022": ["A.8.7", "A.8.28"],
        "pci_dss_4": ["6.4.2"],
        "peca_2016": ["s.5"],
    },
    # -- PISF-05 IAM ----------------------------------------------------------
    "PISF-05.1": {
        "nist_csf_2_0": ["PR.AC-01", "PR.AC-04"],
        "iso_27001_2022": ["A.5.16", "A.5.17"],
        "pci_dss_4": ["8.2", "8.6"],
        "peca_2016": ["s.16", "s.3"],
    },
    "PISF-05.2": {
        "nist_csf_2_0": ["PR.AC-07"],
        "iso_27001_2022": ["A.5.17", "A.8.5"],
        "pci_dss_4": ["8.3.6"],
        "peca_2016": ["s.3"],
    },
    "PISF-05.3": {
        "nist_csf_2_0": ["DE.AE-02", "DE.AE-03"],
        "iso_27001_2022": ["A.8.16"],
        "pci_dss_4": ["10.4.1"],
        "peca_2016": ["s.3", "s.7"],
    },
    # -- PISF-06 Data Protection & Privacy -----------------------------------
    "PISF-06.1": {
        "nist_csf_2_0": ["PR.DS-01", "PR.DS-02"],
        "iso_27001_2022": ["A.8.24", "A.5.34"],
        "pci_dss_4": ["3.5", "4.2"],
        "peca_2016": ["s.31"],
    },
    "PISF-06.2": {
        "nist_csf_2_0": ["PR.DS-01"],
        "iso_27001_2022": ["A.8.24"],
        "pci_dss_4": ["3.6"],
        "peca_2016": ["s.31"],
    },
    # -- PISF-07 Incident Response --------------------------------------------
    "PISF-07.1": {
        "nist_csf_2_0": ["RS.MA-01", "RS.CO-02"],
        "iso_27001_2022": ["A.5.24", "A.5.26"],
        "pci_dss_4": ["12.10"],
        "peca_2016": ["s.49"],
    },
    "PISF-07.2": {
        "nist_csf_2_0": ["RS.MA-02", "RS.MA-03"],
        "iso_27001_2022": ["A.5.25", "A.5.26"],
        "pci_dss_4": ["12.10"],
        "peca_2016": ["s.5", "s.10"],
    },
    # -- PISF-08 Physical Security --------------------------------------------
    "PISF-08.1": {
        "nist_csf_2_0": ["PR.AC-02", "DE.CM-01"],
        "iso_27001_2022": ["A.7.2"],
        "pci_dss_4": ["9.4"],
        "peca_2016": ["s.3"],
    },
    "PISF-08.2": {
        "nist_csf_2_0": ["PR.AC-02"],
        "iso_27001_2022": ["A.7.2"],
        "pci_dss_4": ["9.4"],
        "peca_2016": ["s.43"],
    },
    # -- PISF-09 Data Centre & Hosting ----------------------------------------
    "PISF-09.1": {
        "nist_csf_2_0": ["PR.IR-01", "DE.CM-01"],
        "iso_27001_2022": ["A.8.22", "A.8.20"],
        "pci_dss_4": ["1.3", "1.2"],
        "peca_2016": ["s.4", "s.49"],
    },
    "PISF-09.2": {
        "nist_csf_2_0": ["DE.CM-01", "RS.CO-02"],
        "iso_27001_2022": ["A.8.16", "A.5.24"],
        "pci_dss_4": ["10.4", "12.10"],
        "peca_2016": ["s.49", "s.28"],
    },
    # -- PISF-10 SSDLC ---------------------------------------------------------
    "PISF-10.1": {
        "nist_csf_2_0": ["PR.PS-01"],
        "iso_27001_2022": ["A.8.28", "A.8.26"],
        "pci_dss_4": ["6.2", "6.4.2"],
        "peca_2016": ["s.5"],
    },
    "PISF-10.2": {
        "nist_csf_2_0": ["PR.PS-01"],
        "iso_27001_2022": ["A.8.9", "A.8.28"],
        "pci_dss_4": ["6.2", "2.2"],
        "peca_2016": ["s.5"],
    },
    # -- PISF-11 Supply Chain --------------------------------------------------
    "PISF-11.1": {
        "nist_csf_2_0": ["GV.SC-01"],
        "iso_27001_2022": ["A.8.8", "A.5.21"],
        "pci_dss_4": ["6.3"],
        "peca_2016": ["s.6"],
    },
    "PISF-11.2": {
        "nist_csf_2_0": ["GV.SC-02", "RS.MA-01"],
        "iso_27001_2022": ["A.5.20", "A.5.22"],
        "pci_dss_4": ["6.3"],
        "peca_2016": ["s.6", "s.43"],
    },
    # -- PISF-12 Audit ----------------------------------------------------------
    "PISF-12.1": {
        "nist_csf_2_0": ["GV.OV-03", "ID.IM-02"],
        "iso_27001_2022": ["A.5.35", "A.5.28"],
        "pci_dss_4": ["10.3", "10.7"],
        "peca_2016": ["s.32"],
    },
    "PISF-12.2": {
        "nist_csf_2_0": ["RS.CO-02", "RS.CO-03"],
        "iso_27001_2022": ["A.5.25", "A.5.28"],
        "pci_dss_4": ["12.10"],
        "peca_2016": ["s.49", "s.31"],
    },
    # -- PISF-13 CII Protection --------------------------------------------------
    "PISF-13.1": {
        "nist_csf_2_0": ["ID.AM-01", "ID.AM-08"],
        "iso_27001_2022": ["A.5.9", "A.5.12"],
        "pci_dss_4": ["2.2"],
        "peca_2016": ["s.4", "s.49"],
    },
    "PISF-13.2": {
        "nist_csf_2_0": ["DE.CM-01", "DE.AE-04"],
        "iso_27001_2022": ["A.8.16"],
        "pci_dss_4": ["11.4"],
        "peca_2016": ["s.4", "s.10"],
    },
}

# PECA section subjects, shown in the UI so references stay legible.
PECA_NOTES: Dict[str, str] = {
    "s.3": "unauthorised access to information system or data",
    "s.4": "unauthorised copying/transmission of critical infrastructure data",
    "s.5": "interference with information system or data",
    "s.6": "misuse of devices",
    "s.7": "unauthorised interception",
    "s.10": "cyber terrorism",
    "s.16": "unauthorised use of identity information",
    "s.28": "international cooperation",
    "s.31": "retention of traffic data",
    "s.32": "disclosure of content data under warrant",
    "s.43": "federal government power to make rules",
    "s.49": "establishment of National CERT",
}


def framework_coverage(
    db: DatabaseManager, framework_key: str
) -> Dict[str, Any]:
    """
    Live coverage for one external framework, computed from the current
    pisf_compliance statuses. A PISF control counts toward the framework's
    "compliant" tally only when its live PISF status is Compliant.
    """
    if framework_key not in FRAMEWORKS:
        raise ValueError(f"unknown framework {framework_key!r}")
    controls = db.fetch_controls()
    status_of = {c["control_id"]: c["status"] for c in controls}
    mapped = [cid for cid in CONTROL_FRAMEWORK_MAP if framework_key in CONTROL_FRAMEWORK_MAP[cid]]
    compliant = sum(1 for cid in mapped if status_of.get(cid) == STATUS_COMPLIANT)
    by_status: Dict[str, int] = {}
    for cid in mapped:
        st_ = status_of.get(cid, "Unknown")
        by_status[st_] = by_status.get(st_, 0) + 1
    total = len(mapped)
    return {
        "framework": FRAMEWORKS[framework_key],
        "framework_key": framework_key,
        "total_mapped": total,
        "compliant": compliant,
        "coverage_pct": round(100.0 * compliant / total, 1) if total else 0.0,
        "by_status": by_status,
    }


# ---------------------------------------------------------------------------
# Streamlit panel
# ---------------------------------------------------------------------------
def render_compliance_panel(db: Optional[DatabaseManager] = None) -> None:
    db = db or get_db()
    st.subheader("Cross-framework control mapping")

    cols = st.columns(len(FRAMEWORKS))
    for col, (key, name) in zip(cols, FRAMEWORKS.items()):
        cov = framework_coverage(db, key)
        with col:
            st.metric(name, f"{cov['coverage_pct']}%",
                      f"{cov['compliant']}/{cov['total_mapped']} compliant")
            st.progress(min(max(cov["coverage_pct"] / 100.0, 0.0), 1.0))

    st.markdown("**PISF -> external framework matrix**")
    controls = db.fetch_controls()
    status_of = {c["control_id"]: c["status"] for c in controls}
    rows = []
    for cid in sorted(CONTROL_FRAMEWORK_MAP):
        mapping = CONTROL_FRAMEWORK_MAP[cid]
        rows.append(
            {
                "PISF control": cid,
                "NIST CSF 2.0": ", ".join(mapping["nist_csf_2_0"]),
                "ISO 27001:2022": ", ".join(mapping["iso_27001_2022"]),
                "PCI-DSS 4.0": ", ".join(mapping["pci_dss_4"]),
                "PECA 2016": ", ".join(mapping["peca_2016"]),
                "PISF status": status_of.get(cid, "Unknown"),
            }
        )
    st.dataframe(rows, use_container_width=True)

    with st.expander("PECA 2016 section reference"):
        for sec, note in sorted(PECA_NOTES.items()):
            st.caption(f"{sec} — {note}")

    st.markdown(
        '<div class="cp-banner cp-action">ALIGNMENT REFERENCES ONLY — these mappings aid gap '
        "analysis and do not constitute certification or legal advice.</div>",
        unsafe_allow_html=True,
    )
