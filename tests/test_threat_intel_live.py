"""Parser + failure tests for real Abuse.ch fetchers (mocked network)."""

import io

import pytest

from modules import threat_intel as ti


class _FakeResp:
    def __init__(self, text: str):
        self._buf = io.BytesIO(text.encode("utf-8"))

    def read(self):
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_urlopen(monkeypatch, text: str):
    monkeypatch.setattr(
        ti.urllib.request, "urlopen", lambda req, timeout=None: _FakeResp(text)
    )


def test_urlhaus_parser_ip_vs_domain(monkeypatch):
    _patch_urlopen(
        monkeypatch,
        "http://1.2.3.4/mal.exe\nhttp://evil.example.com/payload\n"
        "http://7.7.7.7/\n# comment line\n\ngarbage-no-url\n",
    )
    res = ti.fetch_abusech_feed("urlhaus")
    assert res["ok"] is True
    by_val = {v: t for v, t, _ in res["indicators"]}
    assert by_val["1.2.3.4"] == "ip"          # v7 fix: IP hosts stored as IPs
    assert by_val["7.7.7.7"] == "ip"
    assert by_val["evil.example.com"] == "domain"
    assert len(res["indicators"]) == 3


def test_feodo_parser_ips_only(monkeypatch):
    _patch_urlopen(
        monkeypatch,
        "# Feodo Tracker (IPv4-only blocklist)\n185.1.2.3\n10.0.0.9\n# end\n\nevil.example.com\n",
    )
    res = ti.fetch_abusech_feed("feodo")
    assert res["ok"] is True
    by_val = {v: t for v, t, _ in res["indicators"]}
    assert by_val["185.1.2.3"] == "ip"
    assert by_val["10.0.0.9"] == "ip"
    assert "evil.example.com" not in by_val  # not an IP -> dropped


def test_threatfox_csv_parser(monkeypatch):
    _patch_urlopen(
        monkeypatch,
        '"first_seen","id","ioc","ioc_type","threat_type","malware","a","b","c"\n'
        '"2026-01-01 00:00:00","1","9.9.9.9:4444","ip:port","botnet_cc","TrickBot","","",""\n'
        '"2026-01-01 00:00:00","2","mal.example.net","domain","botnet_cc","Emotet","","",""\n'
        '"2026-01-01 00:00:00","3","http://c2.bad.example/x","url","payload_delivery","X","","",""\n'
        '"2026-01-01 00:00:00","4","zz","md5","payload_delivery","","","",""\n',
    )
    res = ti.fetch_abusech_feed("threatfox")
    assert res["ok"] is True
    by_val = {v: t for v, t, _ in res["indicators"]}
    assert by_val["9.9.9.9"] == "ip"          # ip:port -> bare IP
    assert by_val["mal.example.net"] == "domain"
    assert by_val["c2.bad.example"] == "domain"  # url -> host
    assert "zz" not in by_val                  # md5 type not ingested


def test_unknown_feed_key():
    res = ti.fetch_abusech_feed("nope")
    assert res["ok"] is False and res["indicators"] == []


def test_network_failure_never_raises(monkeypatch):
    def boom(req, timeout=None):
        raise TimeoutError("simulated timeout")

    monkeypatch.setattr(ti.urllib.request, "urlopen", boom)
    for key in ("urlhaus", "feodo", "threatfox"):
        res = ti.fetch_abusech_feed(key)
        assert res["ok"] is False
        assert res["indicators"] == []
        assert "TimeoutError" in res["error"]


def test_otx_uses_settings_key_before_env(monkeypatch, tmp_db):
    """v7: OTX key resolves centrally — env first, then Settings (SQLite)."""
    monkeypatch.setattr("database.db_manager.get_db", lambda: tmp_db)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    tmp_db.set_setting("otx_api_key", "settings-otx-key")
    from modules.app_config import get_otx_api_key

    assert get_otx_api_key() == "settings-otx-key"
    monkeypatch.setenv("OTX_API_KEY", "env-otx-key")
    assert get_otx_api_key() == "env-otx-key"


def test_refresh_feed_routes_live_to_real_fetch(monkeypatch, tmp_db):
    """v7: refresh_feed() on a LIVE feed performs a real fetch (mocked),
    never synthetic rotation."""
    from modules.threat_intel import TIStore

    ti = TIStore(db=tmp_db)
    ti.seed_feeds()
    # Simulate a live-imported Abuse.ch feed
    with tmp_db.lock, tmp_db.connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ti_feeds (feed_name, description, feed_kind,"
            " source_url, update_interval_h, last_updated)"
            " VALUES ('AbuseCH-URLhaus-LIVE', 'x', 'live', 'https://example/', 6, '2026-01-01')"
        )
        conn.commit()
    seen = {}

    def fake_import(key, timeout=20):
        seen["key"] = key
        return {"ok": True, "feed": "URLhaus", "added": 5, "skipped": 1, "total": 6}

    monkeypatch.setattr(ti, "import_abusech", fake_import)
    res = ti.refresh_feed("AbuseCH-URLhaus-LIVE")
    assert res["live"] is True and res["ok"] is True
    assert seen["key"] == "urlhaus"  # real fetcher path taken


def test_refresh_feed_simulated_still_rotates(tmp_db):
    from modules.threat_intel import TIStore

    ti = TIStore(db=tmp_db)
    ti.seed_feeds()
    feeds = ti.list_feeds()
    sim = next(f for f in feeds if f.get("feed_kind") != "live")
    res = ti.refresh_feed(sim["feed_name"])
    assert "rotated_iocs" in res and "live" not in res
