"""
Pak-CyberPulse GRC panel.

PISF-01 Governance — policy matrix and control depth.
PISF-02 Asset & Risk — institutional risk rating from CII weights + open gaps.
PISF-03 Security Training — five-item literacy assessment in a state-aware form.
PISF-13 CII Protection — designated node register and elevated-risk view.
"""

from __future__ import annotations

import streamlit as st

from database.db_manager import (
    CLASS_CII,
    STATUS_COMPLIANT,
    STATUS_NON_COMPLIANT,
    STATUS_UNDER_ATTACK,
    get_db,
)

QUIZ = [
    {
        "q": "How many core control domains comprise the Pakistan Information Security Framework published by National CERT?",
        "options": ["8", "10", "13", "17"],
        "answer": "13",
        "why": "PISF is structured as thirteen essential policy documents (Governance through CII Protection).",
    },
    {
        "q": "Under CERT Rules 2023, which organisation formulates PISF for federal and provincial public bodies and designated CII?",
        "options": [
            "Pakistan Telecommunication Authority only",
            "National CERT (PKCERT / nCERT)",
            "State Bank of Pakistan",
            "NADRA",
        ],
        "answer": "National CERT (PKCERT / nCERT)",
        "why": "Rule 13(1) of the CERT Rules 2023 assigns PISF formulation to National CERT in consultation with domain experts.",
    },
    {
        "q": "What does CII stand for in PISF-13?",
        "options": [
            "Centralised Identity Index",
            "Critical Information Infrastructure",
            "Certified Internal Inspectorate",
            "Cyber Incident Inventory",
        ],
        "answer": "Critical Information Infrastructure",
        "why": "PISF-13 is Essential CII Protection Controls — specialised requirements for designated critical infrastructure.",
    },
    {
        "q": "Which PISF domain owns unique identification, authentication, and brute-force resistance?",
        "options": [
            "PISF-01 Essential Governance Controls",
            "PISF-05 Essential Identity and Access Management Controls",
            "PISF-08 Essential Physical Security Controls",
            "PISF-12 Essential Audit Controls",
        ],
        "answer": "PISF-05 Essential Identity and Access Management Controls",
        "why": "IAM is document 5. This prototype's sliding-window detector (10 fails / 60s) evidences PISF-05.2.",
    },
    {
        "q": "The CyberSilo / nCERT summary cites which outer bound for incident reporting to the Sectoral CERT?",
        "options": ["4 hours", "24 hours", "72 hours", "30 days"],
        "answer": "72 hours",
        "why": "Public summaries of PISF cite incident reporting to the Sectoral CERT within 72 hours, with annual internal and external audits.",
    },
]


def _status_rank(status: str) -> int:
    return {STATUS_UNDER_ATTACK: 2, STATUS_NON_COMPLIANT: 1, STATUS_COMPLIANT: 0}.get(status, 1)


def compute_institutional_risk(db) -> dict[str, float | int | str]:
    """
    Combine asset inherent risk with live control gaps.

    rating = mean(CII risk_score) * (1 + 0.08 * under_attack + 0.03 * non_compliant)
    clamped to 100, then banded into LOW / ELEVATED / SEVERE.
    """
    assets = db.fetch_assets()
    controls = db.fetch_controls()
    cii = [a for a in assets if a["classification"] == CLASS_CII]
    base = sum(int(a["risk_score"]) for a in cii) / max(len(cii), 1)
    under = sum(1 for c in controls if c["status"] == STATUS_UNDER_ATTACK)
    gaps = sum(1 for c in controls if c["status"] == STATUS_NON_COMPLIANT)
    raw = base * (1.0 + 0.08 * under + 0.03 * gaps)
    score = round(min(100.0, raw), 1)
    if under:
        band = "SEVERE"
    elif score >= 88 or gaps >= 4:
        band = "ELEVATED"
    else:
        band = "LOW"
    return {
        "score": score,
        "band": band,
        "cii_count": len(cii),
        "under": under,
        "gaps": gaps,
        "base": round(base, 1),
    }


def render_governance_panel() -> None:
    db = get_db()
    readiness = db.compute_readiness()
    risk = compute_institutional_risk(db)
    domains = db.fetch_domains()
    controls = db.fetch_controls()
    assets = db.fetch_assets()

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Institutional risk rating", f"{risk['score']}", help="CII-weighted, gap-amplified")
    k2.metric("Risk band", str(risk["band"]))
    k3.metric("CII nodes in register", f"{risk['cii_count']}")
    k4.metric("Open GRC gaps", f"{risk['gaps']} gap / {risk['under']} attack")

    if risk["band"] == "SEVERE":
        st.markdown(
            '<div class="cp-banner cp-critical">CRITICAL INFRACTION — live Under Attack controls elevate the '
            "institutional rating into the SEVERE band. Containment is a PISF-07 duty.</div>",
            unsafe_allow_html=True,
        )
    elif risk["band"] == "ELEVATED":
        st.markdown(
            '<div class="cp-banner cp-action">ACTION REQUIRED — residual gaps (training, cryptography, supply chain) '
            "keep the rating above the hardened band.</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="cp-banner cp-hardened">HARDENED — no live attacks and residual gaps are within tolerance.</div>',
            unsafe_allow_html=True,
        )

    st.subheader("PISF 2026 control matrix — 13 PKCERT domains")
    st.caption(
        "Each domain carries multiple sub-controls (PISF-XX.1, PISF-XX.2, …). "
        "Status is live SQLite state, not a hard-coded dashboard."
    )
    st.dataframe(
        [
            {
                "domain": d["domain_id"],
                "name": d["domain_name"],
                "controls": d["control_count"],
                "compliant": d["compliant_count"],
                "gaps": d["gap_count"],
                "under_attack": d["attack_count"],
                "weight": d["weight_sum"],
            }
            for d in domains
        ],
        use_container_width=True,
        hide_index=True,
    )

    with st.expander("Full sub-control ledger (every PISF-XX.N row)"):
        st.dataframe(
            [
                {
                    "control_id": c["control_id"],
                    "domain": c["domain_id"],
                    "status": c["status"],
                    "weight": c["risk_weight"],
                    "last_assessment": c["last_assessment"],
                    "description": c["control_description"],
                }
                for c in controls
            ],
            use_container_width=True,
            hide_index=True,
        )

    st.subheader("PISF-02 / PISF-13  asset × residual-risk grid")
    grid = []
    for asset in assets:
        # Heightened CII row: inherit the worst live control status as a qualitative tag.
        worst = max(controls, key=lambda c: _status_rank(c["status"])) if controls else None
        tag = "CII-PRIORITY" if asset["classification"] == CLASS_CII else "STANDARD"
        if worst and worst["status"] == STATUS_UNDER_ATTACK and asset["classification"] == CLASS_CII:
            tag = "CII-ESCALATED"
        grid.append(
            {
                "hostname": asset["hostname"],
                "ip": asset["ip_address"],
                "classification": asset["classification"],
                "inherent_risk": asset["risk_score"],
                "tag": tag,
            }
        )
    st.dataframe(grid, use_container_width=True, hide_index=True)
    st.caption(
        f"Readiness index uses control weights (currently {readiness['score']}). "
        f"Institutional risk uses mean CII inherent score {risk['base']} amplified by live gaps."
    )

    st.subheader("PISF-03  security literacy assessment")
    st.write(
        "Five-item, state-aware form. A score of 4/5 or better marks PISF-03.1 and PISF-03.2 Compliant "
        "and writes the result into the evidence log. Below that, the domain stays Non-Compliant."
    )
    with st.form("pisf_literacy_quiz"):
        responses: list[str] = []
        for i, item in enumerate(QUIZ):
            responses.append(
                st.radio(f"{i + 1}. {item['q']}", item["options"], index=None, key=f"quiz_{i}")
            )
        submitted = st.form_submit_button("Submit literacy assessment")

    if submitted:
        if any(r is None for r in responses):
            st.markdown(
                '<div class="cp-banner cp-action">ACTION REQUIRED — answer every item before the ledger will accept the attempt.</div>',
                unsafe_allow_html=True,
            )
        else:
            score = sum(1 for r, item in zip(responses, QUIZ) if r == item["answer"])
            passed = score >= 4
            rows = []
            for item, resp in zip(QUIZ, responses):
                ok = resp == item["answer"]
                rows.append(
                    {
                        "item": item["q"][:72] + ("…" if len(item["q"]) > 72 else ""),
                        "your_answer": resp,
                        "result": "CORRECT" if ok else "INCORRECT",
                        "rationale": item["why"],
                    }
                )
            st.dataframe(rows, use_container_width=True, hide_index=True)
            evidence = f"Literacy assessment scored {score}/5 (pass≥4). passed={passed}"
            if passed:
                db.update_control_status("PISF-03.1", STATUS_COMPLIANT, evidence)
                db.update_control_status("PISF-03.2", STATUS_COMPLIANT, evidence)
                st.markdown(
                    f'<div class="cp-banner cp-hardened">HARDENED — {score}/5. '
                    "PISF-03.1 and PISF-03.2 marked Compliant.</div>",
                    unsafe_allow_html=True,
                )
            else:
                db.update_control_status("PISF-03.1", STATUS_NON_COMPLIANT, evidence)
                db.update_control_status("PISF-03.2", STATUS_NON_COMPLIANT, evidence)
                st.markdown(
                    f'<div class="cp-banner cp-action">ACTION REQUIRED — {score}/5 is below the literacy gate. '
                    "PISF-03 remains Non-Compliant.</div>",
                    unsafe_allow_html=True,
                )

    with st.expander("Authoritative PKCERT domain register (the 13 documents)"):
        st.markdown(
            """
| ID | PKCERT document |
| --- | --- |
| PISF-01 | Essential Governance Controls |
| PISF-02 | Essential Asset and Risk Management Controls |
| PISF-03 | Essential Security Training Controls |
| PISF-04 | Essential System and Communication Protection Controls |
| PISF-05 | Essential Identity and Access Management Controls |
| PISF-06 | Essential Data Protection and Privacy Controls |
| PISF-07 | Essential Incident Response Controls |
| PISF-08 | Essential Physical Security Controls |
| PISF-09 | Essential Data Centre and Web Hosting Services Controls |
| PISF-10 | Essential Secure Software Development Life Cycle Controls |
| PISF-11 | Essential Supply Chain Management Controls |
| PISF-12 | Essential Audit Controls |
| PISF-13 | Essential CII Protection Controls |
"""
        )
        st.caption(
            "Source: National CERT PISF merged text (thirteen documents), National Cyber Security Policy 2021, "
            "CERT Rules 2023. This prototype is an academic mapping, not a PKCERT accreditation instrument."
        )
