"""Parser tests for modules/log_ingest.py parse_syslog_line (pure function)."""

from modules.log_ingest import parse_syslog_line


def _has_stamp(ev):
    assert isinstance(ev["ts"], float)
    assert isinstance(ev["iso"], str) and ev["iso"]


def test_parse_json_line():
    ev = parse_syslog_line('{"event": "AUTH_FAIL", "user": "bob", "src_ip": "1.2.3.4"}')
    assert ev["event"] == "AUTH_FAIL"
    assert ev["user"] == "bob"
    assert ev["parsed"] == "json"
    _has_stamp(ev)


def test_parse_cef_line():
    ev = parse_syslog_line(
        "CEF:0|Vendor|Product|1.0|100|Login failed|5|src=1.2.3.4 dst=5.6.7.8"
    )
    assert ev["event"] == "CEF"
    assert ev["parsed"] == "cef"
    fields = ev["cef_fields"]
    assert fields["vendor"] == "Vendor"
    assert fields["name"] == "Login failed"
    assert fields["severity"] == "5"
    assert fields["extensions"]["src"] == "1.2.3.4"
    _has_stamp(ev)


def test_parse_bsd_syslog_line():
    ev = parse_syslog_line("<34>Oct 11 22:14:15 myhost sshd[123]: Failed password for bob")
    assert ev["event"] == "SYSLOG"
    assert ev["parsed"] == "bsd_syslog"
    assert ev["pri"] == 34
    assert ev["facility"] == 4       # 34 >> 3
    assert ev["severity"] == 2       # 34 & 7
    assert ev["month"] == "Oct" and ev["day"] == "11" and ev["time"] == "22:14:15"
    assert ev["host"] == "myhost"
    assert ev["app"] == "sshd" and ev["pid"] == "123"
    assert "Failed password" in ev["msg"]
    _has_stamp(ev)


def test_parse_raw_line_falls_through():
    ev = parse_syslog_line("some random unstructured line")
    assert ev["event"] == "RAW"
    assert ev["msg"] == "some random unstructured line"
    _has_stamp(ev)


def test_parse_empty_line():
    ev = parse_syslog_line("")
    assert ev["event"] == "EMPTY"
    _has_stamp(ev)


def test_json_scalar_and_json_with_existing_ts():
    ev = parse_syslog_line('"just a string"')
    assert ev["event"] == "RAW" and ev["parsed"] == "json_scalar"
    ev2 = parse_syslog_line('{"event": "X", "ts": 123.0}')
    assert ev2["ts"] == 123.0  # parser must not overwrite an existing ts
    _has_stamp(ev2)
