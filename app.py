"""
Pak-CyberPulse — locally deployable SIEM / SOAR / GRC prototype.

Viewport entry point: black / red / green tactical SOC theme, animated
loading splash, live log-stream / analysis / threat / block animations,
and a single background SIEM worker started through st.cache_resource
so Streamlit reruns cannot spawn duplicate tailers.

Launch:  streamlit run app.py
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from database.db_manager import get_db
from modules.alerting import render_alerting_panel
from modules.anomaly_engine import AnomalyDetector, render_anomaly_panel
from modules.case_manager import render_cases_panel
from modules.compliance_map import render_compliance_panel
from modules.connectors import render_connectors_panel
from modules.forensics import render_forensics_panel
from modules.governance import render_governance_panel
from modules.log_ingest import ensure_listener_running, ensure_system_log_running, render_ingest_panel
from modules.rbac import render_login_panel, seed_demo_users
from modules.siem_panel import get_siem_engine, render_siem_panel
from modules.settings_panel import render_settings_panel
from modules.website_monitor import (
    ensure_website_monitor_running,
    render_website_monitor,
)

__version__ = "7.0.0"
from modules.soar_engine import (
    detect_privilege,
    maybe_trigger_airgap_on_attack,
    planned_mode,
    render_soar_panel,
)
from modules.tech_controls import render_tech_panel
from modules.threat_intel import render_ti_panel

st.set_page_config(
    page_title="Pak-CyberPulse  ·  PISF SOC",
    layout="wide",
    initial_sidebar_state="expanded",
)

ROOT = Path(__file__).resolve().parent

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

:root {
  --bg: #000000;
  --bg-elevated: #050505;
  --bg-subtle: #0a0c0a;
  --fg: #f2f5f2;
  --fg-muted: #a9b5a9;
  --fg-subtle: #6d7d6d;
  --border: rgba(0, 230, 118, 0.16);
  --border-red: rgba(255, 43, 43, 0.35);
  --red: #ff2b2b;
  --red-soft: #ff6b6b;
  --red-deep: #3d0a0a;
  --green: #00e676;
  --green-soft: #69f0ae;
  --green-deep: #0a2a18;
  --amber: #ffb300;
  --font-sans: "IBM Plex Sans", "Segoe UI", sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, monospace;
}

/* ============ base ============ */
html, body, .stApp, [data-testid="stAppViewContainer"] {
  background: var(--bg);
  color: var(--fg);
  font-family: var(--font-sans);
}
[data-testid="stHeader"] { background: rgba(0, 0, 0, 0.94); }
[data-testid="stToolbar"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"],
.stDeployButton,
div[data-testid="stToolbarActions"] { display: none !important; visibility: hidden !important; }
#MainMenu, footer { visibility: hidden; }
.stApp h1, .stApp h2, .stApp h3, .stApp h4,
[data-testid="stHeading"] h1,
[data-testid="stHeading"] h2,
[data-testid="stHeading"] h3 {
  font-family: var(--font-sans) !important;
  letter-spacing: -0.02em;
  color: var(--fg) !important;
  font-weight: 700 !important;
}
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #050505 0%, #070a07 100%);
  border-right: 1px solid var(--border);
}
[data-testid="stSidebar"] * { font-family: var(--font-sans); }
[data-testid="stMarkdownContainer"] p, .stMarkdown, label, .stCaption {
  color: var(--fg);
}
.stCaption, [data-testid="stCaptionContainer"] { color: var(--fg-muted) !important; }
h1, h2, h3, h4 { font-family: var(--font-sans); letter-spacing: -0.02em; color: var(--fg); }

/* ============ metrics ============ */
[data-testid="stMetricValue"] {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  color: var(--green-soft) !important;
  font-weight: 700;
}
[data-testid="stMetricLabel"] { color: var(--fg-muted); font-weight: 600; }
[data-testid="stMetric"] {
  background: linear-gradient(160deg, #060906 0%, #030303 100%);
  border: 1px solid var(--border);
  border-left: 3px solid var(--green);
  padding: 12px 14px;
  border-radius: 12px;
  animation: cp-fadein 0.5s ease;
}

/* ============ buttons: high-contrast, glowing ============ */
.stButton > button, .stDownloadButton > button {
  background: var(--green) !important;
  color: #00130a !important;
  border: 1px solid var(--green) !important;
  border-radius: 10px !important;
  font-weight: 700 !important;
  font-size: 0.92rem !important;
  min-height: 46px !important;
  letter-spacing: 0.01em;
  transition: box-shadow 0.18s ease, transform 0.18s ease, filter 0.18s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover {
  filter: brightness(1.08);
  box-shadow: 0 0 20px rgba(0, 230, 118, 0.55), 0 0 4px rgba(0, 230, 118, 0.9);
  transform: translateY(-1px);
}
.stButton > button:active, .stDownloadButton > button:active { transform: translateY(0); }
.stButton > button[kind="primary"] {
  background: var(--red) !important;
  color: #ffffff !important;
  border: 1px solid var(--red) !important;
}
.stButton > button[kind="primary"]:hover {
  box-shadow: 0 0 24px rgba(255, 43, 43, 0.65), 0 0 4px rgba(255, 43, 43, 0.95);
  filter: brightness(1.1);
}
.stButton > button:disabled, .stDownloadButton > button:disabled {
  background: #161616 !important;
  color: #6a6a6a !important;
  border: 1px solid #2c2c2c !important;
  box-shadow: none !important;
}
.stButton > button:focus-visible, .stDownloadButton > button:focus-visible {
  outline: 2px solid var(--green-soft);
  outline-offset: 2px;
}

/* ============ tabs: bright, legible on black ============ */
div[data-testid="stTabs"] [data-baseweb="tab-list"] {
  gap: 6px;
  border-bottom: 1px solid var(--border);
  flex-wrap: wrap;
}
div[data-testid="stTabs"] [data-baseweb="tab"],
div[data-testid="stTabs"] [role="tab"] {
  color: #c9d4c9 !important;
  font-weight: 600 !important;
  font-size: 0.92rem !important;
  padding: 10px 14px !important;
  border-radius: 8px 8px 0 0;
  background: transparent;
}
div[data-testid="stTabs"] [data-baseweb="tab"]:hover,
div[data-testid="stTabs"] [role="tab"]:hover {
  color: #ffffff !important;
  background: rgba(0, 230, 118, 0.08);
}
div[data-testid="stTabs"] [data-baseweb="tab"][aria-selected="true"],
div[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
  color: var(--green) !important;
  font-weight: 700 !important;
  background: rgba(0, 230, 118, 0.10);
}
div[data-testid="stTabs"] [data-baseweb="tab-highlight"] {
  background-color: var(--red) !important;
  height: 3px !important;
}

/* ============ inputs ============ */
[data-testid="stTextInput"] input, [data-testid="stNumberInput"] input,
[data-testid="stSelectbox"] [data-baseweb="select"] > div,
[data-testid="stMultiSelect"] [data-baseweb="select"] > div {
  background: #0a0a0a !important;
  color: var(--fg) !important;
  border: 1px solid #2a2f2a !important;
  border-radius: 8px !important;
}
[data-testid="stTextInput"] input:focus, [data-testid="stNumberInput"] input:focus {
  border-color: var(--green) !important;
  box-shadow: 0 0 0 1px rgba(0, 230, 118, 0.5) !important;
}
div[data-baseweb="select"] svg { fill: var(--green) !important; }
[data-testid="stExpander"] {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 12px;
}
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary * {
  color: var(--fg) !important;
  font-weight: 600;
}
[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 8px; }
code, pre, .stCode, [data-testid="stCode"] {
  font-family: var(--font-mono) !important;
  font-size: 0.78rem !important;
}
[data-testid="stCode"] {
  background: #040604 !important;
  border: 1px solid var(--border) !important;
  border-radius: 10px !important;
}
[data-testid="stCode"] code { color: var(--green-soft) !important; }
.stAlert {
  background: #060a07 !important;
  border: 1px solid var(--border) !important;
  border-radius: 10px !important;
  color: var(--fg) !important;
}
hr { border-color: var(--border) !important; }

/* ============ masthead / banners / cards ============ */
.cp-mast {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 10px 0 6px 0;
  border-bottom: 2px solid var(--border);
  margin-bottom: 16px;
  animation: cp-fadein 0.5s ease;
}
.cp-kicker {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--green-soft);
}
.cp-title {
  font-size: 1.65rem;
  font-weight: 700;
  letter-spacing: -0.03em;
  margin: 0;
  color: #ffffff;
  text-shadow: 0 0 24px rgba(0, 230, 118, 0.35);
}
.cp-sub { color: var(--fg-muted); font-size: 0.92rem; margin: 0; }
.cp-classbar {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--fg-muted);
  border: 1px solid var(--border);
  padding: 8px 12px;
  border-radius: 8px;
  background: #060806;
  margin: 8px 0 14px 0;
}
.cp-banner {
  font-family: var(--font-sans);
  font-size: 0.92rem;
  line-height: 1.45;
  padding: 12px 14px;
  border-radius: 10px;
  margin: 8px 0 14px 0;
  border: 1px solid var(--border);
  animation: cp-fadein 0.45s ease;
}
.cp-hardened {
  background: linear-gradient(90deg, #04120a, #031007);
  color: #c9f5da;
  border-left: 4px solid var(--green);
}
.cp-action {
  background: linear-gradient(90deg, #170f02, #100b02);
  color: #ffe1a8;
  border-left: 4px solid var(--amber);
}
.cp-critical {
  background: linear-gradient(90deg, #1c0606, #120404);
  color: #ffc9c9;
  border-left: 4px solid var(--red);
  animation: cp-fadein 0.45s ease, cp-threat 1.1s ease-in-out 0.45s infinite;
}
@keyframes cp-threat {
  0%, 100% { box-shadow: inset 0 0 0 0 rgba(255, 43, 43, 0); background: linear-gradient(90deg, #1c0606, #120404); }
  50% { box-shadow: 0 0 26px rgba(255, 43, 43, 0.5), inset 0 0 0 1px rgba(255, 43, 43, 0.55); background: linear-gradient(90deg, #3d0a0a, #220505); }
}
@keyframes cp-fadein {
  from { opacity: 0; transform: translateY(7px); }
  to { opacity: 1; transform: none; }
}
.cp-score {
  font-family: var(--font-mono);
  font-size: 2.4rem;
  font-weight: 700;
  letter-spacing: -0.04em;
  line-height: 1;
  color: var(--green);
  text-shadow: 0 0 22px rgba(0, 230, 118, 0.45);
}
.cp-score-label {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--fg-subtle);
  margin-bottom: 6px;
}
.sev {
  display: inline-block;
  font-size: 0.72rem;
  font-weight: 700;
  padding: 2px 10px;
  border-radius: 999px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.sev-critical { background: #3d0a0a; color: #ff9d9d; border: 1px solid var(--red); animation: cp-sevblink 1.2s ease-in-out infinite; }
.sev-high { background: #2b1c0d; color: #ffcf8a; border: 1px solid var(--amber); }
.sev-medium { background: #0a1420; color: #a9c3ff; border: 1px solid #2f4a7a; }
@keyframes cp-sevblink { 0%, 100% { box-shadow: 0 0 0 rgba(255,43,43,0); } 50% { box-shadow: 0 0 12px rgba(255,43,43,.8); } }
.pat-card {
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 10px 14px;
  margin: 6px 0;
  background: #070907;
}
.pat-card summary {
  cursor: pointer;
  font-weight: 600;
  font-size: 0.92rem;
  list-style: none;
  color: var(--fg);
}
.pat-card summary::-webkit-details-marker { display: none; }
.pat-meta { font-size: 0.78rem; color: var(--fg-muted); margin-top: 2px; }
.pat-playbook { margin: 8px 0 2px 0; padding-left: 18px; font-size: 0.85rem; }

/* ============ LIVE animations ============ */
/* pulsing LIVE dot (log ingestion) */
.cp-live-dot {
  display: inline-block;
  width: 11px; height: 11px;
  border-radius: 50%;
  background: var(--green);
  margin-right: 9px;
  vertical-align: 1px;
  animation: cp-live 1.4s ease-in-out infinite;
}
@keyframes cp-live {
  0%, 100% { box-shadow: 0 0 0 0 rgba(0, 230, 118, 0.7); }
  50% { box-shadow: 0 0 0 10px rgba(0, 230, 118, 0); }
}
.cp-live-dot.red { background: var(--red); animation-name: cp-live-red; }
@keyframes cp-live-red {
  0%, 100% { box-shadow: 0 0 0 0 rgba(255, 43, 43, 0.7); }
  50% { box-shadow: 0 0 0 10px rgba(255, 43, 43, 0); }
}
/* streaming ingest bar */
.cp-streambar {
  height: 5px; background: #070707; border-radius: 99px;
  overflow: hidden; margin-top: 10px;
  border: 1px solid rgba(0, 230, 118, 0.2);
}
.cp-streambar-fill {
  height: 100%; width: 40%;
  background: linear-gradient(90deg, transparent, var(--green), transparent);
  animation: cp-stream 1.8s linear infinite;
}
@keyframes cp-stream {
  0% { transform: translateX(-110%); }
  100% { transform: translateX(360%); }
}
/* rotating analysis ring */
.cp-scanring {
  display: inline-block; width: 15px; height: 15px;
  border-radius: 50%;
  border: 2px solid rgba(0, 230, 118, 0.22);
  border-top-color: var(--green);
  animation: cp-spin 0.9s linear infinite;
  vertical-align: -2px; margin-right: 9px;
}
.cp-scanring.red { border-color: rgba(255,43,43,.22); border-top-color: var(--red); }
@keyframes cp-spin { to { transform: rotate(360deg); } }
.cp-analyzing {
  display: inline-flex; align-items: center;
  font-family: var(--font-mono); font-size: 0.74rem; font-weight: 700;
  letter-spacing: 0.14em; color: var(--green-soft);
  border: 1px solid var(--border); border-radius: 999px;
  padding: 7px 16px; margin: 4px 0 12px 0;
  background: rgba(0, 230, 118, 0.06);
  animation: cp-fadein 0.5s ease;
}
.cp-analyzing.red {
  color: #ffb3b3; border-color: var(--border-red); background: rgba(255, 43, 43, 0.07);
}
/* LIVE / DEMO / NO-SOURCE provenance badge */
.cp-livebar {
  display: flex; align-items: center; gap: 10px;
  font-family: var(--font-mono); font-size: 0.78rem; font-weight: 700;
  letter-spacing: 0.12em;
  color: var(--green-soft);
  border: 1px solid var(--border); border-radius: 10px;
  background: rgba(0, 230, 118, 0.07);
  padding: 10px 16px; margin: 2px 0 12px 0;
  animation: cp-fadein 0.5s ease;
}
.cp-livebar.demo {
  color: #ffd58a; border-color: rgba(255, 179, 0, 0.45);
  background: rgba(255, 179, 0, 0.07);
}
.cp-livebar.off {
  color: #ff9d9d; border-color: var(--border-red);
  background: rgba(255, 43, 43, 0.07);
}
/* scanline marker: the code block right after it gets a sweeping scan beam */
.cp-scanline {
  display: flex; align-items: center; gap: 10px;
  font-family: var(--font-mono); font-size: 0.72rem; font-weight: 700;
  letter-spacing: 0.16em; color: var(--green-soft);
  margin: 2px 0 6px 0;
}
.cp-scanline .cp-scanring { margin-right: 0; }
div.element-container:has(.cp-scanline) + div.element-container [data-testid="stCode"] {
  position: relative; overflow: hidden;
}
div.element-container:has(.cp-scanline) + div.element-container [data-testid="stCode"]::after {
  content: ""; position: absolute; left: 0; right: 0; height: 52px; top: -60px;
  background: linear-gradient(180deg, transparent, rgba(0, 230, 118, 0.13), transparent);
  animation: cp-sweep 3s linear infinite; pointer-events: none;
}
@keyframes cp-sweep { 0% { top: -60px; } 100% { top: 110%; } }
/* threat detection: flashing red card */
.cp-threat-card {
  border: 1px solid var(--red); border-radius: 12px;
  background: linear-gradient(90deg, #220606, #120303);
  padding: 12px 16px; margin: 10px 0;
  display: flex; align-items: center; gap: 12px;
  animation: cp-threat 1s ease-in-out infinite;
}
.cp-threat-card .cp-threat-id {
  font-family: var(--font-mono); font-weight: 700; color: #ffb3b3; font-size: 0.95rem;
}
.cp-threat-card .cp-threat-sub { color: var(--fg-muted); font-size: 0.82rem; }
/* block / termination: red -> green transition with drawing checkmark */
.cp-blocked {
  position: relative; overflow: hidden;
  border: 1px solid rgba(0, 230, 118, 0.55); border-radius: 12px;
  padding: 14px 16px 14px 68px; margin: 10px 0;
  background: linear-gradient(90deg, #2a0a0a 0%, #2a0a0a 30%, #0a2417 100%);
  background-size: 220% 100%;
  animation: cp-blocked-bg 2.6s ease forwards, cp-fadein 0.4s ease;
  color: #d8f5e4;
}
@keyframes cp-blocked-bg {
  0% { background-position: 0% 0; box-shadow: 0 0 0 rgba(255,43,43,0); }
  35% { background-position: 30% 0; box-shadow: 0 0 26px rgba(255, 43, 43, 0.55); }
  100% { background-position: 100% 0; box-shadow: 0 0 18px rgba(0, 230, 118, 0.4); }
}
.cp-blocked .cp-check {
  position: absolute; left: 14px; top: 50%;
  transform: translateY(-50%); width: 40px; height: 40px;
}
.cp-check-circle {
  fill: none; stroke: var(--green); stroke-width: 3;
  stroke-dasharray: 160; stroke-dashoffset: 160;
  animation: cp-draw 0.9s ease 0.35s forwards;
}
.cp-check-mark {
  fill: none; stroke: var(--green); stroke-width: 4.5;
  stroke-linecap: round; stroke-linejoin: round;
  stroke-dasharray: 60; stroke-dashoffset: 60;
  animation: cp-draw 0.5s ease 1.1s forwards;
}
@keyframes cp-draw { to { stroke-dashoffset: 0; } }
.cp-blocked .cp-blocked-title {
  font-weight: 700; letter-spacing: 0.06em; color: var(--green-soft);
  font-size: 0.95rem; margin-bottom: 2px;
}
.cp-blocked .cp-blocked-sub { font-size: 0.84rem; color: var(--fg-muted); }
.cp-blocked-failed {
  border-color: var(--border-red);
  background: linear-gradient(90deg, #2a0a0a, #1c0606);
  animation: cp-fadein 0.4s ease;
  color: #ffd7d7;
}
/* smooth transitions for interactive elements */
.stButton > button, [data-testid="stMetric"], .cp-banner, .cp-blocked,
[data-testid="stExpander"], .pat-card {
  transition: box-shadow 0.2s ease, border-color 0.2s ease, background 0.3s ease;
}

/* ============ loading splash ============ */
#cp-splash {
  position: fixed; inset: 0; z-index: 2147483647;
  background: radial-gradient(ellipse at center, #060906 0%, #000000 70%);
  display: flex; align-items: center; justify-content: center;
  animation: cp-splash-out 0.7s ease 4.2s forwards;
}
@keyframes cp-splash-out {
  to { opacity: 0; visibility: hidden; pointer-events: none; }
}
.cp-splash-inner { text-align: center; padding: 24px; }
.cp-splash-rings { position: relative; width: 128px; height: 128px; margin: 0 auto 24px; }
.cp-splash-rings span {
  position: absolute; inset: 0; border-radius: 50%;
  border: 2px solid transparent; border-top-color: var(--green);
  animation: cp-spin 1.6s linear infinite;
}
.cp-splash-rings span:nth-child(2) {
  inset: 15px; border-top-color: var(--red);
  animation-duration: 1.1s; animation-direction: reverse;
}
.cp-splash-rings span:nth-child(3) {
  inset: 30px; border-top-color: var(--green); opacity: 0.45;
  animation-duration: 2.3s;
}
.cp-splash-core {
  position: absolute; inset: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 2.4rem; color: var(--green);
  animation: cp-core-pulse 1.6s ease-in-out infinite;
}
@keyframes cp-core-pulse {
  0%, 100% { transform: scale(1); text-shadow: 0 0 14px rgba(0, 230, 118, 0.6); }
  50% { transform: scale(1.16); text-shadow: 0 0 30px rgba(0, 230, 118, 1); }
}
.cp-splash-title {
  font-size: 1.9rem; font-weight: 700; letter-spacing: 0.26em;
  color: #ffffff; margin: 0 0 6px 0.26em;
  text-shadow: 0 0 26px rgba(0, 230, 118, 0.5);
}
.cp-splash-sub {
  font-family: var(--font-mono); font-size: 0.72rem; letter-spacing: 0.3em;
  color: var(--green-soft); margin-bottom: 4px;
}
.cp-splash-tag {
  font-family: var(--font-mono); font-size: 0.66rem; letter-spacing: 0.2em;
  color: var(--fg-subtle); margin-bottom: 6px;
}
.cp-splash-bar {
  width: 330px; max-width: 70vw; height: 7px;
  background: #0a0a0a; border: 1px solid rgba(0, 230, 118, 0.3);
  border-radius: 99px; margin: 24px auto 14px; overflow: hidden;
}
.cp-splash-fill {
  height: 100%; width: 0;
  background: linear-gradient(90deg, var(--green), var(--red));
  border-radius: 99px;
  animation: cp-splash-fill 3.9s ease forwards;
  box-shadow: 0 0 14px rgba(0, 230, 118, 0.7);
}
@keyframes cp-splash-fill {
  0% { width: 0; } 55% { width: 68%; } 80% { width: 88%; } 100% { width: 100%; }
}
.cp-splash-stages { position: relative; height: 1.7rem; }
.cp-stage {
  position: absolute; inset: 0; opacity: 0;
  font-family: var(--font-mono); font-size: 0.8rem; letter-spacing: 0.08em;
  color: var(--fg-muted);
  animation: cp-stage 4.1s linear infinite;
}
.cp-stage.s2 { animation-delay: 1.02s; }
.cp-stage.s3 { animation-delay: 2.04s; }
.cp-stage.s4 { animation-delay: 3.06s; }
@keyframes cp-stage {
  0% { opacity: 0; } 4% { opacity: 1; } 21% { opacity: 1; } 25% { opacity: 0; } 100% { opacity: 0; }
}

/* ============ responsive ============ */
@media (max-width: 1500px) {
  .cp-title { font-size: 1.42rem; }
  .cp-score { font-size: 2.05rem; }
  div[data-testid="stTabs"] [data-baseweb="tab"],
  div[data-testid="stTabs"] [role="tab"] { font-size: 0.86rem !important; padding: 9px 10px !important; }
}
@media (max-width: 1240px) {
  div[data-testid="stHorizontalBlock"] { flex-wrap: wrap !important; }
  div[data-testid="column"] { flex: 1 1 210px !important; min-width: 210px; }
  [data-testid="stSidebar"] { min-width: 230px; }
  .cp-splash-title { font-size: 1.45rem; }
}
@media (max-width: 760px) {
  div[data-testid="column"] { flex: 1 1 100% !important; min-width: 0; }
  .cp-score { font-size: 1.7rem; }
  .cp-blocked { padding-left: 60px; }
}

@media (prefers-reduced-motion: reduce) {
  .cp-critical, .cp-threat-card, .sev-critical, .cp-live-dot,
  .cp-streambar-fill, .cp-scanring, .cp-splash-rings span, .cp-splash-core,
  .cp-splash-fill, .cp-stage, #cp-splash { animation: none !important; }
  #cp-splash { display: none !important; }
}
</style>
"""

SPLASH_HTML = """
<div id="cp-splash" aria-hidden="true">
  <div class="cp-splash-inner">
    <div class="cp-splash-rings"><span></span><span></span><span></span><div class="cp-splash-core">&#9673;</div></div>
    <div class="cp-splash-title">PAK-CYBERPULSE</div>
    <div class="cp-splash-sub">PISF 2026 &middot; SOC OPERATIONS CONSOLE</div>
    <div class="cp-splash-tag">NATIONAL CERT ALIGNED &middot; ACADEMIC PROTOTYPE</div>
    <div class="cp-splash-bar"><div class="cp-splash-fill"></div></div>
    <div class="cp-splash-stages">
      <span class="cp-stage s1">Initializing SOC sensors&hellip;</span>
      <span class="cp-stage s2">Loading threat intelligence&hellip;</span>
      <span class="cp-stage s3">Starting log monitor&hellip;</span>
      <span class="cp-stage s4">Arming SOAR containment&hellip;</span>
    </div>
  </div>
</div>
"""


@st.cache_resource
def boot_runtime():
    """
    Runs exactly once per server process. Streamlit script reruns (widget
    interaction, fragment ticks) reuse this object, so the tailer thread is
    never duplicated.
    """
    db = get_db()
    db.initialize()
    seed_demo_users(db)  # idempotent: creates the four DEMO RBAC accounts if missing
    engine = get_siem_engine()
    engine.start()
    # Zero-config first run: syslog listener auto-starts on 127.0.0.1:1514
    # (TCP+UDP). Never raises; the Log ingest tab keeps manual start/stop.
    try:
        ensure_listener_running()
    except Exception:
        pass
    # Zero-config first run: native OS logs (Windows Event Log / journald /
    # /var/log fallback). Never raises; the Log ingest tab keeps a toggle.
    try:
        ensure_system_log_running()
    except Exception:
        pass
    # Zero-config first run: website access-log tailers for all registered
    # sites + the auto-block watcher. Never raises.
    try:
        ensure_website_monitor_running(db, engine)
    except Exception:
        pass
    # v7: scheduled live threat-intel refresh (Abuse.ch + OTX). Never raises.
    try:
        from modules.threat_intel import ensure_ti_refresh_running
        ensure_ti_refresh_running()
    except Exception:
        pass
    # v7: honest startup warnings for anything still on demo credentials.
    try:
        from modules.app_config import log_to_desktop, warn_if_demo_credentials
        for _w in warn_if_demo_credentials():
            log_to_desktop(f"startup-warning: {_w}")
    except Exception:
        pass
    return engine


def inject_theme() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def inject_splash() -> None:
    """Full-screen animated boot splash — once per browser session.

    Streamlit reruns the script on every widget interaction, so the splash
    is gated on st.session_state: it plays on the first paint of a fresh
    session (app start / page reload) and never on reruns.
    """
    if st.session_state.get("_cp_splash_done"):
        return
    st.session_state["_cp_splash_done"] = True
    st.markdown(SPLASH_HTML, unsafe_allow_html=True)


def score_tone(score: float, under: int) -> str:
    if under > 0 or score < 45:
        return "cp-critical"
    if score < 75:
        return "cp-action"
    return "cp-hardened"


@st.fragment(run_every=2.0)
def render_kpi_header() -> None:
    db = get_db()
    r = db.compute_readiness()
    # Automated air-gapped backup trigger whenever active attack count > 0.
    if int(r.get("under_attack", 0)) > 0:
        try:
            maybe_trigger_airgap_on_attack()
        except Exception:
            pass
    tone = score_tone(r["score"], r["under_attack"])
    left, a, b, c, d = st.columns((1.4, 1, 1, 1, 1))
    with left:
        st.markdown(
            f'<div class="cp-score-label">Global PISF 2026 Readiness Index</div>'
            f'<div class="cp-score">{r["score"]:.1f}</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<div class="cp-banner {tone}" style="margin-top:10px;">'
            f'{r["compliant"]}/{r["total"]} controls Compliant · '
            f'{r["non_compliant"]} gap · {r["under_attack"]} under attack'
            f"</div>",
            unsafe_allow_html=True,
        )
    a.metric("Compliant", f"{r['compliant']}")
    b.metric("Gaps", f"{r['non_compliant']}")
    c.metric("Attacks", f"{r['under_attack']}")
    d.metric("CII nodes", f"{r['cii_assets']}")


@st.fragment(run_every=2.0)
def render_live_siem() -> None:
    render_siem_panel(boot_runtime())


def main() -> None:
    inject_splash()
    inject_theme()
    engine = boot_runtime()

    # v7 production hardening: optional login gate for every panel.
    # Default off (zero-setup demo UX); enable via Settings for production.
    from modules.app_config import get_setting
    if get_setting("require_login", "0") == "1" and not st.session_state.get("rbac_user"):
        st.markdown(
            '<div class="cp-banner cp-critical"><b>RESTRICTED</b> — sign in to '
            "access Pak-CyberPulse (require_login is enabled).</div>",
            unsafe_allow_html=True,
        )
        render_login_panel()
        st.stop()

    priv = detect_privilege()

    st.markdown(
        """
<div class="cp-mast">
  <div class="cp-kicker">National CERT aligned  ·  PISF 2026  ·  Academic prototype</div>
  <p class="cp-title">Pak-CyberPulse</p>
  <p class="cp-sub">Locally deployable SIEM / SOAR and GRC automation platform — sliding-window detection, privilege-honest containment, cryptographic evidence.</p>
  <p class="cp-sub" style="opacity:0.75">v7.0 · production-hardening release</p>
</div>
<div class="cp-classbar">Academic prototype // demonstration telemetry only // mock CNIC vectors labelled DEMO // not an operational PKCERT instrument</div>
""",
        unsafe_allow_html=True,
    )

    render_kpi_header()

    with st.sidebar:
        st.markdown("**Analyst sign-in (RBAC)**")
        render_login_panel()
        st.divider()
        st.markdown("**Runtime**")
        st.caption("Privilege probe")
        st.code(
            f"privileged = {priv['privileged']}\n"
            f"uid        = {priv['uid']}\n"
            f"method     = {priv['method']}\n"
            f"platform   = {priv['platform']}\n"
            f"fw_binary  = {priv.get('firewall_binary') or 'absent'}",
            language="text",
        )
        mode = planned_mode(priv)
        if mode == "NETWORK FIREWALL BLOCK":
            st.markdown(
                '<div class="cp-banner cp-hardened">SOAR maps to NETWORK FIREWALL BLOCK</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="cp-banner cp-action">SOAR maps to APPLICATION-LAYER ACCESS CONTROL BLOCK</div>',
                unsafe_allow_html=True,
            )
        st.caption(
            "Worker is a daemon thread started via st.cache_resource. "
            "It tails database/live_siem_stream.log — the Streamlit script thread does not loop."
        )
        st.caption(f"Root  {ROOT.name}/")

    tab_grc, tab_siem, tab_anomaly, tab_tech, tab_ti, tab_cases, tab_forensics, tab_compliance = st.tabs(
        (
            "Executive GRC & Policy Ledger",
            "SIEM Real-Time Monitoring Center",
            "Anomaly Detection",
            "Technical Safeguards / SOAR Gate",
            "Threat Intel",
            "Cases",
            "Forensics",
            "Compliance",
        )
    )
    with tab_grc:
        render_governance_panel()
    with tab_siem:
        render_live_siem()
    with tab_anomaly:
        # Share the live detector with the SIEM engine so the dashboard
        # shows exactly what the stream is scoring.
        if engine.ml_anomaly is None:
            engine.ml_anomaly = AnomalyDetector()
        render_anomaly_panel(engine.ml_anomaly)
    with tab_tech:
        (soar_tab, tech_tab, alert_tab, ingest_tab, conn_tab,
         wsite_tab, settings_tab) = st.tabs(
            [
                "SOAR containment gate (PISF-07 / PISF-12)",
                "Technical safeguards (PISF-06 / 10 / 11)",
                "Alerting",
                "Log Ingest",
                "Connectors",
                "Website Monitor",
                "Settings",
            ]
        )
        with soar_tab:
            render_soar_panel(engine)
        with tech_tab:
            render_tech_panel()
        with alert_tab:
            render_alerting_panel()
        with ingest_tab:
            render_ingest_panel()
        with conn_tab:
            render_connectors_panel()
        with wsite_tab:
            render_website_monitor(engine)
        with settings_tab:
            render_settings_panel()
    with tab_ti:
        render_ti_panel()
    with tab_cases:
        render_cases_panel()
    with tab_forensics:
        render_forensics_panel()
    with tab_compliance:
        render_compliance_panel()


if __name__ == "__main__":
    main()
