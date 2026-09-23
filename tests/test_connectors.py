"""Tests for modules/connectors.py (v4 log connectors)."""

from __future__ import annotations

import pytest

from modules.connectors import (
    RegexLogParser,
    import_csv_logs,
    parse_json_log,
    parse_windows_event_xml,
)


# ---------------------------------------------------------------------------
# JSON log parser
# ---------------------------------------------------------------------------

def test_json_log_normalizes_aliases():
    ev = parse_json_log(
        '{"timestamp": "2026-09-22T10:00:00Z", "username": "admin", '
        '"source_ip": "203.0.113.7", "event_type": "AUTH_FAIL", '
        '"message": "Failed password"}'
    )
    assert ev["user"] == "admin"
    assert ev["src_ip"] == "203.0.113.7"
    assert ev["event"] == "AUTH_FAIL"
    assert ev["msg"] == "Failed password"
    assert ev["ts"] == pytest.approx(1790071200.0)
    assert ev["parsed"] == "json_log"


def test_json_log_epoch_ts():
    ev = parse_json_log('{"ts": 1790071200, "user": "x"}')
    assert ev["ts"] == pytest.approx(1790071200.0)


def test_json_log_defaults_for_sparse_object():
    ev = parse_json_log('{"foo": "bar"}')
    assert ev["user"] == "-" and ev["src_ip"] == "0.0.0.0"
    assert ev["event"] == "JSON_LOG"


def test_json_log_rejects_garbage():
    with pytest.raises(ValueError):
        parse_json_log("not json at all")
    with pytest.raises(ValueError):
        parse_json_log("[1, 2, 3]")
    with pytest.raises(ValueError):
        parse_json_log("   ")


# ---------------------------------------------------------------------------
# CSV import
# ---------------------------------------------------------------------------

def test_csv_import_happy_path(tmp_path):
    p = tmp_path / "logs.csv"
    p.write_text(
        "timestamp,username,source_ip,event_type,message\n"
        "2026-09-22T10:00:00Z,admin,203.0.113.7,AUTH_FAIL,Failed password\n"
        "2026-09-22T10:01:00Z,jdoe,198.51.100.9,AUTH_OK,Accepted\n"
    )
    events = import_csv_logs(p)
    assert len(events) == 2
    assert events[0]["user"] == "admin"
    assert events[0]["src_ip"] == "203.0.113.7"
    assert all(e["parsed"] == "csv_import" for e in events)


def test_csv_import_rejects_unknown_header(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("aaa,bbb,ccc\n1,2,3\n")
    with pytest.raises(ValueError):
        import_csv_logs(p)


def test_csv_import_rejects_headerless(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_text("")
    with pytest.raises(ValueError):
        import_csv_logs(p)


# ---------------------------------------------------------------------------
# Windows Event XML
# ---------------------------------------------------------------------------

_WIN_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <Channel>Security</Channel>
    <Computer>DC01.corp.example</Computer>
    <Security/>
    <TimeCreated SystemTime="2026-09-22T10:00:00.000Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="IpAddress">203.0.113.44</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>"""


def test_windows_event_xml_parses():
    ev = parse_windows_event_xml(_WIN_XML)
    assert ev["event_id"] == "4625"
    assert ev["host"] == "DC01.corp.example"
    assert ev["user"] == "administrator"
    assert ev["src_ip"] == "203.0.113.44"
    assert ev["channel"] == "Security"
    assert ev["parsed"] == "windows_event_xml"
    assert ev["event_data"]["LogonType"] == "3"


def test_windows_event_xml_rejects_bad_input():
    with pytest.raises(ValueError):
        parse_windows_event_xml("<nope/>")
    with pytest.raises(ValueError):
        parse_windows_event_xml("not xml")
    with pytest.raises(ValueError):
        parse_windows_event_xml("")


# ---------------------------------------------------------------------------
# Regex parser
# ---------------------------------------------------------------------------

def test_regex_parser_happy_path():
    parser = RegexLogParser(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>\S+) "(?P<msg>[^"]+)"')
    ev = parser.parse_line('203.0.113.9 - jdoe "Failed password attempt"')
    assert ev is not None
    assert ev["src_ip"] == "203.0.113.9"
    assert ev["user"] == "jdoe"
    assert ev["msg"] == "Failed password attempt"
    assert ev["parsed"] == "regex"


def test_regex_parser_no_match_returns_none():
    parser = RegexLogParser(r"IP=(?P<ip>\S+)")
    assert parser.parse_line("nothing to see here") is None


def test_regex_parser_rejects_bad_pattern():
    with pytest.raises(ValueError):
        RegexLogParser("(unclosed")
    with pytest.raises(ValueError):
        RegexLogParser("   ")


def test_regex_parser_extra_groups_preserved():
    parser = RegexLogParser(r"user=(?P<user>\w+) port=(?P<port>\d+)")
    ev = parser.parse_line("user=root port=51234")
    assert ev["regex_fields"]["port"] == "51234"
    assert ev["user"] == "root"


def test_regex_parser_parse_lines_skips_nonmatching():
    parser = RegexLogParser(r"ERR (?P<msg>.+)")
    out = parser.parse_lines(["ERR disk full", "INFO all good", "ERR timeout"])
    assert len(out) == 2
