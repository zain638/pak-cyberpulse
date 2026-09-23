"""Tests for v4 threat-intel import: CSV bulk import + OTX live fetch."""

from __future__ import annotations

import json
import urllib.request

import pytest

from modules.threat_intel import TIStore, fetch_otx_pulses


@pytest.fixture
def ti_seeded(tmp_db):
    ti = TIStore(db=tmp_db)
    ti.seed_feeds()
    return ti


def test_csv_import_adds_and_counts(ti_seeded, tmp_path):
    before = ti_seeded.count_iocs()
    p = tmp_path / "iocs.csv"
    p.write_text(
        "ioc,ioc_type,confidence,threat_type,description\n"
        "203.0.113.200,ip,80,scanner,test indicator one\n"
        "import-demo.example.com,domain,70,phishing,test indicator two\n"
    )
    res = ti_seeded.import_indicators_csv(p)
    assert res["added"] == 2
    assert res["skipped"] == 0
    assert res["invalid"] == 0
    assert ti_seeded.count_iocs() == before + 2
    assert ti_seeded.enrich("203.0.113.200")["matches"]


def test_csv_import_dedupes_against_existing(ti_seeded, tmp_path):
    p = tmp_path / "dup.csv"
    p.write_text("ioc,ioc_type\n203.0.113.200,ip\n203.0.113.200,ip\n")
    first = ti_seeded.import_indicators_csv(p)
    second = ti_seeded.import_indicators_csv(p)
    assert first["added"] == 1
    assert second["added"] == 0
    assert second["skipped"] == 2


def test_csv_import_skips_invalid_rows(ti_seeded, tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text(
        "ioc,ioc_type\n"
        ",ip\n"                       # empty ioc
        "10.0.0.1,url\n"              # bad type
        "10.0.0.2,ip\n"               # good
    )
    res = ti_seeded.import_indicators_csv(p)
    assert res["added"] == 1
    assert res["invalid"] == 2


def test_csv_import_rejects_bad_header(ti_seeded, tmp_path):
    p = tmp_path / "nope.csv"
    p.write_text("aaa,bbb\n1,2\n")
    with pytest.raises(ValueError):
        ti_seeded.import_indicators_csv(p)


def test_otx_no_key_graceful():
    res = fetch_otx_pulses("")
    assert res["ok"] is False
    assert "API key" in res["error"]


def test_otx_offline_graceful(monkeypatch):
    def _boom(req, timeout=12):
        raise OSError("simulated: no network")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    res = fetch_otx_pulses("DUMMYKEY")
    assert res["ok"] is False
    assert "OSError" in res["error"] or "no network" in res["error"]
    assert res["indicators"] == []


def test_otx_parses_mock_response(monkeypatch):
    payload = {
        "results": [
            {
                "name": "Test Pulse",
                "indicators": [
                    {"type": "IPv4", "indicator": "203.0.113.250"},
                    {"type": "domain", "indicator": "evil-test.example.com"},
                    {"type": "FileHash-SHA256", "indicator": "a" * 64},
                    {"type": "URL", "indicator": "http://x/"},
                ],
            }
        ]
    }

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(payload).encode()

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=12: _Resp())
    res = fetch_otx_pulses("DUMMYKEY", limit=5)
    assert res["ok"] is True
    assert res["pulses"] == 1
    got = {(v, t) for v, t, _ in res["indicators"]}
    assert ("203.0.113.250", "ip") in got
    assert ("evil-test.example.com", "domain") in got
    assert ("a" * 64, "sha256") in got
    assert not any(t == "url" for _, t in got)  # unmapped types skipped


def test_ti_import_otx_offline_never_raises(ti_seeded, monkeypatch):
    def _boom(req, timeout=12):
        raise OSError("simulated: no network")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    res = ti_seeded.import_otx("DUMMYKEY")
    assert res["ok"] is False
    assert res["added"] == 0
