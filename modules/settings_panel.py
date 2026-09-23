"""
Pak-CyberPulse Settings — centralized configuration UI.

Backed by modules/app_config.py (DB settings + environment overrides).
Secrets are never rendered back: the UI only shows "configured ✓" / "not set".
"""

from __future__ import annotations

import html

import streamlit as st

from modules.app_config import (
    KNOWN_SETTINGS,
    api_token_status,
    get_setting,
    otx_key_source,
    set_setting,
    warn_if_demo_credentials,
)


def render_settings_panel() -> None:
    st.subheader("Settings")

    warnings = warn_if_demo_credentials()
    for w in warnings:
        st.markdown(
            f'<div class="cp-banner cp-action">⚠ {html.escape(w)}</div>',
            unsafe_allow_html=True,
        )

    st.markdown("### Threat intel")
    src = otx_key_source()
    if src == "none":
        st.caption("No OTX API key configured — threat intel uses SIMULATED feeds "
                   "(honestly labeled) until you add one.")
    else:
        st.caption(f"✓ OTX API key configured via **{src}** (value never shown).")
    c1, c2 = st.columns((3, 1))
    with c1:
        new_key = st.text_input(
            "AlienVault OTX API key",
            type="password",
            key="set-otx-key",
            placeholder="paste key, then Save",
            help="Free at otx.alienvault.com. Stored in the local SQLite DB. "
                 "Env OTX_API_KEY overrides this.",
        )
    with c2:
        st.write("")
        st.write("")
        if st.button("Save key", key="set-otx-save", use_container_width=True):
            set_setting("otx_api_key", (new_key or "").strip())
            st.success("OTX key saved." if new_key else "OTX key cleared.")
            st.rerun()
    if src == "settings" and st.button("Clear saved OTX key", key="set-otx-clear"):
        set_setting("otx_api_key", "")
        st.success("Saved OTX key cleared.")
        st.rerun()

    auto = get_setting("abusech_auto_refresh", "1") == "1"
    new_auto = st.checkbox(
        "Auto-refresh Abuse.ch live feeds every 6h (background)",
        value=auto, key="set-abusech-auto",
    )
    if new_auto != auto:
        set_setting("abusech_auto_refresh", "1" if new_auto else "0")
        st.rerun()

    st.markdown("### REST API security")
    tstat = api_token_status()
    st.markdown(
        f'<div class="cp-banner {"cp-hardened" if tstat["mode"] == "custom" else "cp-action"}>'
        f"{html.escape(tstat['note'])}</div>",
        unsafe_allow_html=True,
    )
    t1, t2 = st.columns((3, 1))
    with t1:
        new_tok = st.text_input(
            "Custom API token",
            type="password",
            key="set-api-tok",
            placeholder="leave blank to keep current",
            help="Stored in the local DB. Env PAKCYBER_API_TOKEN overrides this.",
        )
    with t2:
        st.write("")
        st.write("")
        if st.button("Save token", key="set-api-save", use_container_width=True):
            if (new_tok or "").strip():
                set_setting("api_token", new_tok.strip())
                st.success("API token saved — restart the API to apply.")
                st.rerun()
            else:
                st.info("No change.")

    st.markdown("### Access control")
    req = get_setting("require_login", "0") == "1"
    new_req = st.checkbox(
        "Require login for all panels (production)",
        value=req, key="set-require-login",
        help="When ON, the app shows only the login screen until an analyst "
             "signs in. OFF preserves the zero-setup demo UX (flagged above).",
    )
    if new_req != req:
        set_setting("require_login", "1" if new_req else "0")
        st.success("Login requirement " + ("ENABLED." if new_req else "disabled."))
        st.rerun()

    st.markdown("### Demo credentials")
    st.caption("Seeded demo accounts use public passwords — flagged "
               "**⚠ CHANGE ME** until changed. Change them in the RBAC panel "
               "(Governance tab) after signing in.")
    try:
        from modules.rbac import RBACManager
        users = RBACManager().list_users()
        st.dataframe(
            [
                {
                    "username": u["username"],
                    "role": u["role"],
                    "status": ("⚠ CHANGE ME (demo password)"
                               if u.get("must_change") else "✓ custom"),
                }
                for u in users
            ],
            use_container_width=True, hide_index=True,
        )
    except Exception as exc:  # noqa: BLE001
        st.caption(f"User list unavailable: {exc}")

    with st.expander("All settings (raw key/value)"):
        rows = []
        for k in KNOWN_SETTINGS:
            v = get_setting(k, KNOWN_SETTINGS[k])
            shown = "***configured***" if ("key" in k or "token" in k) and v else v
            rows.append({"key": k, "value": shown})
        st.dataframe(rows, use_container_width=True, hide_index=True)
