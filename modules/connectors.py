"""
Pak-CyberPulse log connectors (v4).

Beyond the built-in syslog listener: parse logs that arrive in other common
shapes and normalize them into the same event-dict format the SIEM engine
consumes (keys: ts, iso, event, user, src_ip, host, msg, ...).

  * parse_json_log()      — strict one-line JSON log parser
  * import_csv_logs()     — CSV log import (header-aware)
  * parse_windows_event_xml() — Windows Event Log XML (wevtutil / Winlogbeat shape)
  * RegexLogParser        — user-defined named-group regex parser + tester

All parsers are pure functions (no sockets, no files except the CSV import
path argument) so they are trivially unit-testable. Streamlit is imported
lazily inside render_connectors_panel() only.
"""

from __future__ import annotations

import csv
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET


def _stamp(event: Dict[str, Any]) -> Dict[str, Any]:
    event.setdefault("ts", time.time())
    event.setdefault("iso", datetime.now(timezone.utc).isoformat())
    return event


def _coerce_ts(value: Any) -> Optional[float]:
    """Best-effort: epoch number, or ISO-8601 string, -> unix float."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        s = value.strip()
        try:
            return float(s)
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# 1) JSON log parser
# ---------------------------------------------------------------------------

_JSON_FIELD_ALIASES = {
    "user": ("user", "username", "user_name", "account"),
    "src_ip": ("src_ip", "source_ip", "src", "client_ip", "ip"),
    "host": ("host", "hostname", "computer", "device"),
    "msg": ("msg", "message", "log", "description", "event_data"),
    "event": ("event", "event_type", "type", "action"),
}


def parse_json_log(line: str) -> Dict[str, Any]:
    """
    Parse one JSON log line into a normalized event dict.

    Raises ValueError on invalid JSON or a non-object payload. Common field
    names are normalized (username -> user, message -> msg, ...); the full
    original object is preserved under "_raw".
    """
    text = (line or "").strip()
    if not text:
        raise ValueError("empty line")
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("JSON log must be an object, got " + type(obj).__name__)

    event: Dict[str, Any] = {"parsed": "json_log", "_raw": obj}
    lower = {str(k).lower(): v for k, v in obj.items()}
    for canonical, aliases in _JSON_FIELD_ALIASES.items():
        for a in aliases:
            if a in lower and lower[a] not in (None, ""):
                event[canonical] = lower[a]
                break
    for ts_key in ("ts", "timestamp", "@timestamp", "time", "event_time"):
        if ts_key in lower:
            coerced = _coerce_ts(lower[ts_key])
            if coerced is not None:
                event["ts"] = coerced
                event["iso"] = datetime.fromtimestamp(
                    coerced, tz=timezone.utc
                ).isoformat()
                break
    event.setdefault("event", "JSON_LOG")
    event.setdefault("user", "-")
    event.setdefault("src_ip", "0.0.0.0")
    event.setdefault("host", "-")
    event.setdefault("msg", text[:400])
    return _stamp(event)


# ---------------------------------------------------------------------------
# 2) CSV log import
# ---------------------------------------------------------------------------

def import_csv_logs(
    path: str | Path, *, delimiter: str = ",", max_rows: int = 100_000
) -> List[Dict[str, Any]]:
    """
    Import a CSV log file (with header row) into normalized event dicts.

    Column names are matched case-insensitively against the same aliases as
    parse_json_log(). Raises ValueError when the file has no usable header.
    """
    path = Path(path)
    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh, delimiter=delimiter)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row")
        norm_fields = {f.strip().lower() for f in reader.fieldnames if f}
        known = {a for aliases in _JSON_FIELD_ALIASES.values() for a in aliases}
        known |= {"ts", "timestamp", "@timestamp", "time", "event_time"}
        if not (norm_fields & known):
            raise ValueError(
                "CSV header has no recognizable log columns "
                f"(saw: {sorted(norm_fields)[:8]})"
            )
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            clean = {
                (k.strip() if k else ""): (v.strip() if isinstance(v, str) else v)
                for k, v in row.items()
                if k
            }
            try:
                events.append(parse_json_log(json.dumps(clean)))
            except ValueError:
                continue
    for e in events:
        e["parsed"] = "csv_import"
    return events


# ---------------------------------------------------------------------------
# 3) Windows Event Log XML parser
# ---------------------------------------------------------------------------

_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event",
}


def _ev_text(root: ET.Element, path: str) -> str:
    el = root.find(path, _NS)
    return (el.text or "").strip() if el is not None and el.text else ""


def parse_windows_event_xml(xml_text: str) -> Dict[str, Any]:
    """
    Parse one Windows Event Log <Event> XML record (the shape produced by
    `wevtutil qe /f:xml` or Winlogbeat) into a normalized event dict.

    Raises ValueError on malformed XML or a non-<Event> root.
    """
    text = (xml_text or "").strip()
    if not text:
        raise ValueError("empty XML")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid XML: {exc}") from exc
    tag = root.tag.split("}")[-1]
    if tag != "Event":
        raise ValueError(f"expected <Event> root, got <{tag}>")

    event_id = _ev_text(root, "e:System/e:EventID")
    computer = _ev_text(root, "e:System/e:Computer")
    channel = _ev_text(root, "e:System/e:Channel")
    level = _ev_text(root, "e:System/e:Level")
    time_el = root.find("e:System/e:TimeCreated", _NS)
    sys_time = time_el.get("SystemTime", "") if time_el is not None else ""

    data: Dict[str, str] = {}
    for d in root.findall("e:EventData/e:Data", _NS):
        name = d.get("Name") or f"Data{len(data)}"
        data[name] = (d.text or "").strip()

    # Common Windows auth fields -> normalized user / src_ip.
    user = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or _ev_text(root, "e:System/e:Security")
        or "-"
    )
    src_ip = data.get("IpAddress") or data.get("SourceIP") or "0.0.0.0"
    if src_ip in {"-", ""}:
        src_ip = "0.0.0.0"

    event: Dict[str, Any] = {
        "parsed": "windows_event_xml",
        "event": "WIN_EVENT",
        "event_id": event_id,
        "channel": channel,
        "level": level,
        "computer": computer,
        "host": computer or "-",
        "user": user,
        "src_ip": src_ip,
        "event_data": data,
        "msg": f"Windows Event {event_id} on {computer or '?'} "
               f"({channel or '?'}) " + "; ".join(
                   f"{k}={v}" for k, v in list(data.items())[:6]
               ),
    }
    coerced = _coerce_ts(sys_time)
    if coerced is not None:
        event["ts"] = coerced
        event["iso"] = datetime.fromtimestamp(coerced, tz=timezone.utc).isoformat()
    return _stamp(event)


# ---------------------------------------------------------------------------
# 4) User-defined regex parser
# ---------------------------------------------------------------------------

class RegexLogParser:
    """
    Parse log lines with a user-supplied regex using Python named groups,
    e.g.  r'(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+) - (?P<user>\\S+) "(?P<msg>[^"]+)"'.

    Named groups map onto event fields: recognized names (user, src_ip/ip,
    host, msg/message, event, ts/timestamp) are normalized; anything else is
    kept under "regex_fields".
    """

    _ALIASES = {
        "ip": "src_ip", "src": "src_ip", "source_ip": "src_ip", "client_ip": "src_ip",
        "username": "user", "account": "user",
        "hostname": "host", "computer": "host",
        "message": "msg", "log": "msg",
        "event_type": "event", "type": "event", "action": "event",
        "time": "ts", "timestamp": "ts", "@timestamp": "ts",
    }

    def __init__(self, pattern: str, *, flags: int = 0) -> None:
        if not pattern or not pattern.strip():
            raise ValueError("regex pattern must not be empty")
        try:
            self._rx = re.compile(pattern, flags)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
        self.pattern = pattern

    @property
    def group_names(self) -> List[str]:
        return list(self._rx.groupindex.keys())

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Return a normalized event dict, or None when the line doesn't match."""
        m = self._rx.search(line or "")
        if not m:
            return None
        groups = {k: v for k, v in m.groupdict().items() if v is not None}
        event: Dict[str, Any] = {"parsed": "regex", "regex_fields": dict(groups)}
        for name, value in groups.items():
            canon = self._ALIASES.get(name.lower(), name.lower())
            if canon == "ts":
                coerced = _coerce_ts(value)
                if coerced is not None:
                    event["ts"] = coerced
                    event["iso"] = datetime.fromtimestamp(
                        coerced, tz=timezone.utc
                    ).isoformat()
            elif canon not in event:
                event[canon] = value
        event.setdefault("event", "REGEX_LOG")
        event.setdefault("user", "-")
        event.setdefault("src_ip", "0.0.0.0")
        event.setdefault("host", "-")
        event.setdefault("msg", (line or "").strip()[:400])
        return _stamp(event)

    def parse_lines(self, lines: List[str]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for line in lines:
            ev = self.parse_line(line)
            if ev is not None:
                out.append(ev)
        return out


# ---------------------------------------------------------------------------
# Streamlit panel (lazy import — module stays headless-importable)
# ---------------------------------------------------------------------------

def render_connectors_panel() -> None:
    import streamlit as st

    st.subheader("Log connectors — import logs in more formats")
    st.caption(
        "Everything imported here is normalized into the same event format "
        "the SIEM engine consumes, so imported logs flow through detection."
    )

    tab_json, tab_csv, tab_win, tab_regex = st.tabs(
        ["JSON logs", "CSV import", "Windows Event XML", "Custom regex"]
    )

    with tab_json:
        st.markdown("**Parse a JSON log line**")
        sample = st.text_area(
            "JSON line",
            '{"timestamp": "2026-09-22T10:00:00Z", "username": "admin", '
            '"source_ip": "203.0.113.7", "event_type": "AUTH_FAIL", '
            '"message": "Failed password for admin"}',
            key="conn-json",
        )
        if st.button("Parse", key="conn-json-go"):
            try:
                st.json(parse_json_log(sample))
            except ValueError as exc:
                st.error(str(exc))

    with tab_csv:
        st.markdown("**Import a CSV log file**")
        up = st.file_uploader("CSV file (header row required)", type=["csv"],
                              key="conn-csv")
        if up is not None:
            tmp = Path("/tmp") / f"cp_csv_{int(time.time())}.csv"
            tmp.write_bytes(up.getvalue())
            try:
                events = import_csv_logs(tmp)
                st.success(f"Imported {len(events)} events from CSV.")
                if events:
                    st.dataframe(events[:20], use_container_width=True)
            except ValueError as exc:
                st.error(str(exc))
            finally:
                tmp.unlink(missing_ok=True)

    with tab_win:
        st.markdown("**Parse a Windows Event Log XML record**")
        st.caption("Export with: wevtutil qe Security /f:xml /c:1")
        xml_in = st.text_area("Event XML", "", key="conn-xml", height=150)
        if st.button("Parse", key="conn-xml-go"):
            try:
                st.json(parse_windows_event_xml(xml_in))
            except ValueError as exc:
                st.error(str(exc))

    with tab_regex:
        st.markdown("**User-defined regex parser (named groups)**")
        pattern = st.text_input(
            "Regex with named groups",
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>\S+) "(?P<msg>[^"]+)"',
            key="conn-rx-pat",
        )
        test_line = st.text_input(
            "Test line",
            '203.0.113.9 - jdoe "Failed password attempt"',
            key="conn-rx-line",
        )
        if st.button("Test parse", key="conn-rx-go"):
            try:
                parser = RegexLogParser(pattern)
                ev = parser.parse_line(test_line)
                if ev is None:
                    st.warning("Pattern compiled, but the line did not match.")
                else:
                    st.json(ev)
            except ValueError as exc:
                st.error(str(exc))
