"""
Pak-CyberPulse forensics: incident timeline reconstruction and
attack-chain graph data.

  build_timeline(db, incident_id)
      Chronological reconstruction: incident creation, linked case notes,
      and related incidents sharing the same source_ip (from incident_ledger).

  attack_chain_graph(db, incident_id)
      JSON-serializable layered graph:
          attacker_ip -> technique -> victim_host -> mitigating action,
      plus related incidents as extra victim nodes.

  graph_to_html(graph)
      Pure-SVG layered diagram generated in Python (no external JS) so it
      renders offline inside Streamlit via st.components.v1.html.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Optional

import streamlit as st

from database.db_manager import DatabaseManager
from modules.attack_patterns import PATTERN_BY_ID

try:
    from modules.mitre_map import annotate_alert
except Exception:  # mitre_map must never break forensics
    annotate_alert = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
def _incident_row(db: DatabaseManager, incident_id: int) -> Optional[dict[str, Any]]:
    rows = db._rows(
        "SELECT * FROM incident_ledger WHERE incident_id = ?", (incident_id,)
    )
    return rows[0] if rows else None


def build_timeline(
    db: DatabaseManager, incident_id: int
) -> dict[str, Any]:
    """
    Return {"incident": {...}, "events": [...]}.

    Events are chronological and each carries ts, kind and summary:
      - the incident creation itself
      - notes on cases linked to this incident (via cases.linked_incident_id)
      - related incidents sharing the same source_ip
    """
    incident = _incident_row(db, incident_id)
    if incident is None:
        raise ValueError(f"Unknown incident {incident_id}")

    events: list[dict[str, Any]] = [
        {
            "ts": incident["created_at"],
            "kind": "incident_created",
            "summary": (
                f"Incident #{incident['incident_id']} detected: "
                f"{incident['classification']} from {incident['source_ip']} "
                f"against {incident['target_host']} "
                f"(rule: {incident['detection_rule']}; "
                f"action: {incident['mitigating_action']})"
            ),
        }
    ]

    # Case notes from linked cases (only if the case tables exist).
    try:
        cases = db._rows(
            "SELECT case_id, title, status FROM cases WHERE linked_incident_id = ?",
            (incident_id,),
        )
    except Exception:
        cases = []
    for case in cases:
        try:
            notes = db._rows(
                "SELECT author, note, created_at FROM case_notes "
                "WHERE case_id = ? ORDER BY note_id ASC",
                (case["case_id"],),
            )
        except Exception:
            notes = []
        events.append(
            {
                "ts": case.get("created_at", incident["created_at"]),
                "kind": "case_linked",
                "summary": (
                    f"Case #{case['case_id']} '{case['title']}' "
                    f"({case['status']}) linked to this incident"
                ),
            }
        )
        for n in notes:
            events.append(
                {
                    "ts": n["created_at"],
                    "kind": "case_note",
                    "summary": f"[Case #{case['case_id']}] {n['note']}",
                    "author": n["author"],
                }
            )

    # Related incidents sharing the attacker IP.
    related = db._rows(
        """
        SELECT incident_id, created_at, target_host, classification,
               mitigating_action
        FROM incident_ledger
        WHERE source_ip = ? AND incident_id != ?
        ORDER BY incident_id ASC
        """,
        (incident["source_ip"], incident_id),
    )
    for r in related:
        events.append(
            {
                "ts": r["created_at"],
                "kind": "related_incident",
                "summary": (
                    f"Related incident #{r['incident_id']}: {r['classification']} "
                    f"from same source IP against {r['target_host']} "
                    f"(action: {r['mitigating_action']})"
                ),
            }
        )

    events.sort(key=lambda e: (e["ts"], e["kind"] != "incident_created"))
    return {"incident": incident, "events": events}


# ---------------------------------------------------------------------------
# Attack-chain graph
# ---------------------------------------------------------------------------
def _resolve_pattern_id(incident: dict[str, Any]) -> Optional[str]:
    """Best-effort pattern-id lookup from the incident's rule/classification."""
    rule = str(incident.get("detection_rule", "") or "")
    cls = str(incident.get("classification", "") or "")
    for pid, pat in PATTERN_BY_ID.items():
        if pid in rule.upper():
            return pid
    for pid, pat in PATTERN_BY_ID.items():
        if pat["name"].lower() in cls.lower() or pat["name"].lower() in rule.lower():
            return pid
    return None


def _technique_label(pattern_id: Optional[str], fallback: str) -> tuple[str, dict[str, Any]]:
    """(label, mitre extras) for the technique node."""
    if pattern_id:
        pat = PATTERN_BY_ID.get(pattern_id, {})
        alert = {"pattern_id": pattern_id}
        mapping: dict[str, Any] = {}
        if annotate_alert is not None:
            try:
                mapping = annotate_alert(alert) or {}
            except Exception:
                mapping = {}
        label = pat.get("name", pattern_id)
        if mapping.get("mitre_technique_id"):
            label = f"{mapping['mitre_technique_id']} {mapping['mitre_technique']}"
            mapping["pattern_name"] = pat.get("name", pattern_id)
        return label, mapping
    return fallback, {}


def attack_chain_graph(
    db: DatabaseManager, incident_id: int
) -> dict[str, Any]:
    """
    JSON-serializable attack chain.

    Layers: attacker_ip -> technique -> victim_host -> action,
    plus one extra victim node per related incident (same source_ip).
    """
    incident = _incident_row(db, incident_id)
    if incident is None:
        raise ValueError(f"Unknown incident {incident_id}")

    src = str(incident["source_ip"])
    victim = str(incident["target_host"])
    action = str(incident["mitigating_action"]) or "no action recorded"

    pattern_id = _resolve_pattern_id(incident)
    tech_label, mitre = _technique_label(pattern_id, str(incident["classification"]))

    nodes: list[dict[str, Any]] = [
        {"id": f"ip:{src}", "label": src, "type": "attacker_ip",
         "meta": {"role": "attacker source IP"}},
        {
            "id": f"tech:{pattern_id or 'unknown'}",
            "label": tech_label,
            "type": "technique",
            "meta": {
                "pattern_id": pattern_id,
                "mitre_technique_id": mitre.get("mitre_technique_id"),
                "mitre_technique": mitre.get("mitre_technique"),
                "mitre_tactics": mitre.get("mitre_tactics", []),
                "mitre_url": mitre.get("mitre_url"),
            },
        },
        {"id": f"host:{victim}", "label": victim, "type": "victim_host",
         "meta": {"role": "target"}},
        {"id": "action:mitigation", "label": action[:60], "type": "action",
         "meta": {"role": "mitigating action"}},
    ]
    edges: list[dict[str, str]] = [
        {"from": f"ip:{src}", "to": f"tech:{pattern_id or 'unknown'}",
         "label": "exploits via"},
        {"from": f"tech:{pattern_id or 'unknown'}", "to": f"host:{victim}",
         "label": "targets"},
        {"from": f"host:{victim}", "to": "action:mitigation",
         "label": "mitigated by"},
    ]

    related = db._rows(
        "SELECT incident_id, target_host, classification FROM incident_ledger "
        "WHERE source_ip = ? AND incident_id != ? ORDER BY incident_id ASC",
        (src, incident_id),
    )
    for r in related:
        nid = f"host:{r['target_host']}#inc{r['incident_id']}"
        nodes.append(
            {
                "id": nid,
                "label": f"{r['target_host']} (#{r['incident_id']})",
                "type": "victim_host",
                "meta": {
                    "role": "also targeted",
                    "incident_id": r["incident_id"],
                    "classification": r["classification"],
                },
            }
        )
        edges.append(
            {"from": f"ip:{src}", "to": nid, "label": "also targeted"}
        )

    return {
        "incident_id": incident_id,
        "nodes": nodes,
        "edges": edges,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


# ---------------------------------------------------------------------------
# Pure-SVG rendering (offline friendly)
# ---------------------------------------------------------------------------
_NODE_STYLE = {
    "attacker_ip": ("#3a1216", "#ff9d9d", "#7a2b2e"),
    "technique": ("#2b1c0d", "#ffcf8a", "#7a5a2b"),
    "victim_host": ("#1c2540", "#a9c3ff", "#2f4a7a"),
    "action": ("#0d1c14", "#d5eee0", "#2f7a4d"),
}

_LAYER_ORDER = ["attacker_ip", "technique", "victim_host", "action"]
_LAYER_TITLES = {
    "attacker_ip": "ATTACKER",
    "technique": "TECHNIQUE",
    "victim_host": "VICTIM",
    "action": "RESPONSE",
}

NODE_W, NODE_H, COL_GAP, ROW_GAP = 230, 54, 90, 26


def _short(text: str, n: int = 30) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def graph_to_html(graph: dict[str, Any]) -> str:
    """
    Render the attack-chain graph as a self-contained layered SVG string.

    Pure Python-generated SVG: no external JS libraries, works offline in
    st.components.v1.html.
    """
    by_type: dict[str, list[dict[str, Any]]] = {t: [] for t in _LAYER_ORDER}
    for node in graph.get("nodes", []):
        by_type.setdefault(node["type"], []).append(node)

    layers = [(t, by_type[t]) for t in _LAYER_ORDER if by_type[t]]
    n_layers = len(layers)
    max_rows = max(len(ns) for _, ns in layers)
    width = n_layers * NODE_W + (n_layers - 1) * COL_GAP + 60
    height = 60 + max_rows * (NODE_H + ROW_GAP) + 40

    pos: dict[str, tuple[float, float]] = {}
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        'font-family="monospace" font-size="12">'
    )
    parts.append(
        '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#8a93a6"/></marker></defs>'
    )

    for li, (ltype, nodes) in enumerate(layers):
        x = 30 + li * (NODE_W + COL_GAP)
        parts.append(
            f'<text x="{x}" y="22" fill="#8a93a6" font-size="11" '
            f'letter-spacing="2">{html.escape(_LAYER_TITLES.get(ltype, ltype.upper()))}</text>'
        )
        for ri, node in enumerate(nodes):
            y = 60 + ri * (NODE_H + ROW_GAP)
            pos[node["id"]] = (x, y)
            bg, fg, border = _NODE_STYLE.get(ltype, ("#222", "#ddd", "#555"))
            label = _short(str(node["label"]), 32)
            sub = _short(str(node["meta"].get("mitre_tactics", [""])[0]
                             if node["type"] == "technique" and node["meta"].get("mitre_tactics")
                             else node["meta"].get("role", "")), 30)
            parts.append(
                f'<rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" rx="8" '
                f'fill="{bg}" stroke="{border}" stroke-width="1.5"/>'
            )
            parts.append(
                f'<text x="{x + 12}" y="{y + 23}" fill="{fg}" font-weight="bold">'
                f'{html.escape(label)}</text>'
            )
            if sub:
                parts.append(
                    f'<text x="{x + 12}" y="{y + 41}" fill="{fg}" opacity="0.65" '
                    f'font-size="10">{html.escape(sub)}</text>'
                )

    for edge in graph.get("edges", []):
        a, b = pos.get(edge["from"]), pos.get(edge["to"])
        if not a or not b:
            continue
        x1, y1 = a[0] + NODE_W, a[1] + NODE_H / 2
        x2, y2 = b[0], b[1] + NODE_H / 2
        parts.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#8a93a6" '
            'stroke-width="1.5" marker-end="url(#arr)"/>'
        )
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 6
        parts.append(
            f'<text x="{mx}" y="{my}" fill="#8a93a6" font-size="10" '
            f'text-anchor="middle">{html.escape(str(edge.get("label", "")))}</text>'
        )

    parts.append("</svg>")
    svg = "".join(parts)
    return (
        '<div style="background:#0e1117;border:1px solid #2c3446;border-radius:10px;'
        'padding:12px;overflow-x:auto;">'
        '<div style="color:#8a93a6;font-size:11px;margin-bottom:8px;">'
        "ATTACK CHAIN — generated offline, pure SVG</div>" + svg + "</div>"
    )


# ---------------------------------------------------------------------------
# Streamlit panel
# ---------------------------------------------------------------------------
_KIND_BADGE = {
    "incident_created": "sev-critical",
    "case_linked": "sev-high",
    "case_note": "sev-medium",
    "related_incident": "sev-high",
}


def render_forensics_panel(db: Optional[DatabaseManager] = None) -> None:
    """Forensics panel: incident selector, timeline, SVG attack-chain, JSON export."""
    from database.db_manager import get_db as _get_db

    db = db or _get_db()

    st.markdown(
        '<div class="cp-banner cp-hardened">'
        "<b>Forensics.</b> Timeline reconstruction and attack-chain graphs are "
        "built live from the incident ledger — no canned data."
        "</div>",
        unsafe_allow_html=True,
    )

    incidents = db.fetch_incidents(limit=100)
    if not incidents:
        st.info("No incidents in the ledger yet — forensics activates after detections.")
        return

    sel = st.selectbox(
        "Select incident",
        [i["incident_id"] for i in incidents],
        format_func=lambda i: (
            f"#{i} — "
            + next(
                f"{x['classification']} from {x['source_ip']} → {x['target_host']}"
                for x in incidents
                if x["incident_id"] == i
            )
        ),
        key="for-incident",
    )
    incident_id = int(sel)

    st.subheader("Timeline reconstruction")
    timeline = build_timeline(db, incident_id)
    for ev in timeline["events"]:
        badge = _KIND_BADGE.get(ev["kind"], "sev-medium")
        author = f" — <i>{html.escape(str(ev['author']))}</i>" if ev.get("author") else ""
        st.markdown(
            f"<span class='sev {badge}'>{ev['kind'].replace('_', ' ')}</span> "
            f"`{ev['ts']}`<br>{html.escape(ev['summary'])}{author}",
            unsafe_allow_html=True,
        )

    st.subheader("Attack-chain graph")
    graph = attack_chain_graph(db, incident_id)
    n_layers = len({n["type"] for n in graph["nodes"]})
    height = 120 + max(
        sum(1 for n in graph["nodes"] if n["type"] == t)
        for t in {n["type"] for n in graph["nodes"]}
    ) * 80
    st.components.v1.html(graph_to_html(graph), height=height, scrolling=True)

    st.subheader("Export")
    payload = {"timeline": timeline, "graph": graph}
    st.download_button(
        "Download forensics JSON",
        data=json.dumps(payload, indent=2, default=str),
        file_name=f"forensics_incident_{incident_id}.json",
        mime="application/json",
        key=f"for-dl-{incident_id}",
    )
