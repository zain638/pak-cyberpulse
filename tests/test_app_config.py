"""Central config/secrets tests (modules/app_config)."""

import os

from modules.app_config import (
    KNOWN_SETTINGS,
    api_token_status,
    get_api_token,
    get_setting,
    otx_key_source,
    set_setting,
    warn_if_demo_credentials,
)


def test_settings_roundtrip(tmp_db, monkeypatch):
    # Route app_config DB access to the isolated tmp DB.
    monkeypatch.setattr("database.db_manager.get_db", lambda: tmp_db)
    set_setting("otx_api_key", "ABC123")
    assert get_setting("otx_api_key") == "ABC123"
    assert get_setting("no.such.key", "dflt") == "dflt"
    set_setting("otx_api_key", "")
    assert get_setting("otx_api_key", "x") == ""  # cleared value round-trips as empty


def test_known_settings_defaults_present():
    for key in ("otx_api_key", "api_token", "abusech_auto_refresh", "require_login"):
        assert key in KNOWN_SETTINGS
    assert KNOWN_SETTINGS["require_login"] == "0"  # demo UX default stays off


def test_api_token_priority_env_over_db(tmp_db, monkeypatch):
    monkeypatch.setattr("database.db_manager.get_db", lambda: tmp_db)
    monkeypatch.delenv("PAKCYBER_API_TOKEN", raising=False)
    set_setting("api_token", "db-token-xyz")
    assert get_api_token() == "db-token-xyz"
    monkeypatch.setenv("PAKCYBER_API_TOKEN", "env-token-abc")
    assert get_api_token() == "env-token-abc"


def test_api_token_status_labels(tmp_db, monkeypatch):
    monkeypatch.setattr("database.db_manager.get_db", lambda: tmp_db)
    monkeypatch.delenv("PAKCYBER_API_TOKEN", raising=False)
    set_setting("api_token", "")
    st0 = api_token_status()
    assert st0["mode"] == "demo"
    assert "change me" in st0["note"].lower()
    set_setting("api_token", "custom-token-1")
    st1 = api_token_status()
    assert st1["mode"] == "custom" and st1["source"] == "settings"
    monkeypatch.setenv("PAKCYBER_API_TOKEN", "env-tok")
    st2 = api_token_status()
    assert st2["mode"] == "custom" and st2["source"] == "environment"


def test_otx_key_source(tmp_db, monkeypatch):
    monkeypatch.setattr("database.db_manager.get_db", lambda: tmp_db)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    set_setting("otx_api_key", "")
    assert otx_key_source() == "none"
    set_setting("otx_api_key", "key-in-db")
    assert otx_key_source() == "settings"
    monkeypatch.setenv("OTX_API_KEY", "key-in-env")
    assert otx_key_source() == "environment"


def test_warn_if_demo_credentials_lists_all(tmp_db, monkeypatch):
    monkeypatch.setattr("database.db_manager.get_db", lambda: tmp_db)
    monkeypatch.delenv("PAKCYBER_API_TOKEN", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    set_setting("api_token", "")
    set_setting("otx_api_key", "")
    warns = warn_if_demo_credentials()
    text = " ".join(warns).lower()
    assert "demo token" in text
    assert "otx" in text
    # login disabled is also surfaced
    set_setting("require_login", "0")
    assert any("login" in w.lower() for w in warns)


def test_secrets_never_rendered_back(tmp_db, monkeypatch):
    """get_setting exposes values to code, but the Settings page must only
    show 'configured' — this test pins the api used by that page."""
    monkeypatch.setattr("database.db_manager.get_db", lambda: tmp_db)
    set_setting("otx_api_key", "super-secret-otx")
    assert "super-secret-otx" not in str(api_token_status())
    # api_token_status never embeds the token value either
    monkeypatch.delenv("PAKCYBER_API_TOKEN", raising=False)
    set_setting("api_token", "super-secret-token")
    assert "super-secret-token" not in str(api_token_status())
    os.environ.pop("PAKCYBER_API_TOKEN", None)
