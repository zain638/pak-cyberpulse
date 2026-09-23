"""
Pak-CyberPulse log ingest — syslog listener + file tailer.

Parses raw lines (JSON, CEF, BSD syslog, raw) and forwards event dicts to a
callable sink. The listener's default sink appends JSONL to the same
live_siem_stream.log file the SIEM engine tails.
"""

from __future__ import annotations

import json
import queue
import re
import shutil
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import streamlit as st

from database.db_manager import LOG_PATH


_SINK = Callable[[Dict[str, Any]], None]

_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>[^:\s\[]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)


def _stamp(event: Dict[str, Any]) -> Dict[str, Any]:
    event.setdefault("ts", time.time())
    event.setdefault("iso", datetime.now(timezone.utc).isoformat())
    return event


def _parse_cef(line: str) -> Optional[Dict[str, Any]]:
    # CEF:0|vendor|product|version|signature|name|severity|extension k=v ...
    if not line.startswith("CEF:"):
        return None
    parts = line.split("|", 7)
    if len(parts) < 7:
        return None
    # CEF header: CEF:0|vendor|product|version|signature|name|severity|ext k=v
    _, vendor, product, ver, signature, name, severity = parts[:7]
    ext_raw = parts[7] if len(parts) > 7 else ""
    extensions: Dict[str, str] = {}
    for token in ext_raw.split():
        if "=" in token:
            k, v = token.split("=", 1)
            extensions[k] = v
    return _stamp(
        {
            "event": "CEF",
            "parsed": "cef",
            "cef_version": ver,
            "cef_fields": {
                "vendor": vendor,
                "product": product,
                "product_version": ver,
                "signature": signature,
                "name": name,
                "severity": severity,
                "extensions": extensions,
            },
        }
    )


def parse_syslog_line(line: str) -> Dict[str, Any]:
    """
    Pure parser: raw line -> event dict. No sockets, no files, no side effects.

    Tries JSON first, then CEF, then BSD syslog ("<PRI>MMM DD HH:MM:SS host
    app: msg"), else wraps the line as a RAW event. Always includes "ts"
    (time.time()) and "iso" (UTC ISO-8601).
    """
    line = (line or "").rstrip("\r\n")
    if not line:
        return _stamp({"event": "EMPTY", "msg": ""})

    # 1) JSON
    try:
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            parsed.setdefault("parsed", "json")
            return _stamp(parsed)
        return _stamp({"event": "RAW", "parsed": "json_scalar", "msg": line})
    except (json.JSONDecodeError, ValueError):
        pass

    # 2) CEF
    cef = _parse_cef(line)
    if cef is not None:
        return cef

    # 3) BSD syslog
    m = _SYSLOG_RE.match(line)
    if m:
        pri = int(m.group("pri"))
        return _stamp(
            {
                "event": "SYSLOG",
                "parsed": "bsd_syslog",
                "pri": pri,
                "facility": pri >> 3,
                "severity": pri & 7,
                "month": m.group("month"),
                "day": m.group("day"),
                "time": m.group("time"),
                "host": m.group("host"),
                "app": m.group("app"),
                "pid": m.group("pid"),
                "msg": m.group("msg"),
            }
        )

    # 4) fallback
    return _stamp({"event": "RAW", "parsed": "none", "msg": line})


def _jsonl_sink(path: Path) -> _SINK:
    lock = threading.Lock()

    def _sink(event: Dict[str, Any]) -> None:
        line = json.dumps(event, default=str)
        with lock:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    return _sink


class SyslogListener:
    """TCP + UDP syslog listener. Every datagram/line is parsed and sent to sink."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        tcp_port: int = 1514,
        udp_port: int = 1514,
        sink: Optional[_SINK] = None,
    ) -> None:
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.sink: _SINK = sink or _jsonl_sink(LOG_PATH)
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._sockets: List[socket.socket] = []
        self.received = 0
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return any(t.is_alive() for t in self._threads)

    def _handle_line(self, raw: bytes) -> None:
        try:
            text = raw.decode("utf-8", "replace").strip()
        except Exception:
            return
        if not text:
            return
        try:
            self.sink(parse_syslog_line(text))
        except Exception:
            return
        with self._lock:
            self.received += 1

    def _udp_loop(self, sock: socket.socket) -> None:
        sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            for chunk in data.split(b"\n"):
                if chunk.strip():
                    self._handle_line(chunk)

    def _tcp_loop(self, sock: socket.socket) -> None:
        sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(0.5)
                buf = b""
                while not self._stop.is_set():
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self._handle_line(line)
                if buf.strip():
                    self._handle_line(buf)

    def start(self) -> None:
        """Bind TCP and UDP sockets and spawn daemon receiver threads."""
        if self.running:
            return
        self._stop.clear()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind((self.host, self.udp_port))
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((self.host, self.tcp_port))
        tcp.listen(8)
        self._sockets = [udp, tcp]
        for target, sock in (("udp", udp), ("tcp", tcp)):
            t = threading.Thread(
                target=self._udp_loop if target == "udp" else self._tcp_loop,
                args=(sock,),
                name=f"syslog-{target}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads = []
        self._sockets = []


class FileTailer:
    """Tails a file from its end, forwarding newly appended lines (parsed) to sink."""

    def __init__(self, path: str | Path, sink: _SINK, poll_interval: float = 0.5) -> None:
        self.path = Path(path)
        self.sink = sink
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.lines_forwarded = 0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        try:
            fh = open(self.path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return
        with fh:
            fh.seek(0, 2)  # start at end — only NEW lines are forwarded
            while not self._stop.is_set():
                line = fh.readline()
                if not line:
                    time.sleep(self.poll_interval)
                    continue
                text = line.rstrip("\r\n")
                if text:
                    try:
                        self.sink(parse_syslog_line(text))
                    except Exception:
                        pass
                    self.lines_forwarded += 1

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="file-tailer", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None


# ---------------------------------------------------------------------------
# Batch ingestion (v4) — large log bursts without blocking the caller
# ---------------------------------------------------------------------------

class BatchIngester:
    """
    Queue + background flusher: submit() never blocks on I/O. The worker
    thread drains the queue and forwards parsed events to the sink in
    batches (every `batch_size` events or `flush_interval_s`, whichever
    comes first). Call flush() for a deterministic drain (tests, shutdown)
    and stop() to terminate the worker.
    """

    def __init__(
        self,
        sink: Optional[_SINK] = None,
        batch_size: int = 200,
        flush_interval_s: float = 0.5,
    ) -> None:
        self.sink: _SINK = sink or _jsonl_sink(LOG_PATH)
        self.batch_size = max(1, batch_size)
        self.flush_interval_s = flush_interval_s
        self._queue: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.submitted = 0
        self.flushed = 0
        self.batches = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="batch-ingester", daemon=True
        )
        self._thread.start()

    def submit(self, line: str) -> None:
        """Non-blocking enqueue of one raw log line."""
        self._queue.put(line)
        with self._lock:
            self.submitted += 1

    def submit_many(self, lines: List[str]) -> int:
        for line in lines:
            self.submit(line)
        return len(lines)

    def _drain(self) -> List[str]:
        batch: List[str] = []
        while len(batch) < self.batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _flush_batch(self, batch: List[str]) -> None:
        for line in batch:
            text = (line or "").strip()
            if not text:
                continue
            try:
                self.sink(parse_syslog_line(text))
            except Exception:
                continue
        with self._lock:
            self.flushed += len(batch)
            self.batches += 1

    def _loop(self) -> None:
        while not self._stop.is_set():
            batch = self._drain()
            if batch:
                self._flush_batch(batch)
            else:
                time.sleep(self.flush_interval_s / 2)

    def flush(self, timeout_s: float = 10.0) -> int:
        """Block until every submitted line has been flushed.

        The background worker may hold an in-flight batch when the queue
        looks empty, so this waits for flushed >= submitted (not just an
        empty queue) before returning. Returns events flushed.
        """
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            with self._lock:
                done = self.flushed >= self.submitted and self._queue.empty()
                if done:
                    return self.flushed
            # Help drain while waiting for the worker's in-flight batch.
            batch = self._drain()
            if batch:
                self._flush_batch(batch)
            else:
                time.sleep(0.01)
        with self._lock:
            return self.flushed

    def stop(self) -> None:
        self.flush()
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "submitted": self.submitted,
                "flushed": self.flushed,
                "batches": self.batches,
                "queued": self._queue.qsize(),
                "worker_alive": bool(self._thread and self._thread.is_alive()),
            }


# ---------------------------------------------------------------------------
# Native OS system-log attachment (v7) — zero-config direct log ingestion
# ---------------------------------------------------------------------------
#
# Windows: live Windows Event Log subscription (Security + System channels)
#          via win32evtlog, guarded import (pywin32 is Windows-only, so the
#          Linux build imports this module fine).
# Linux:   `journalctl --follow -o short-precise` via subprocess, falling
#          back to /var/log/syslog and /var/log/auth.log file tailing.
# Every record is normalized to the same event-dict shape parse_syslog_line()
# produces and forwarded to the same sink, so the SIEM engine correlates
# native OS logs exactly like syslog input. Unavailable sources record a
# reason and are skipped — the app never crashes.

_win32evtlog = None
_win32_import_error = ""
try:
    import win32evtlog as _win32evtlog  # type: ignore[import-not-found]
except ImportError as _exc:  # pywin32 is Windows-only; expected on Linux
    _win32_import_error = str(_exc)


def _normalize_system_event(**fields: Any) -> Dict[str, Any]:
    """Normalized event dict — same shape as parse_syslog_line() output."""
    base: Dict[str, Any] = {"event": "SYSTEM_LOG", "parsed": "system_log"}
    base.update(fields)
    return _stamp(base)


class WindowsEventLogTailer:
    """Live Windows Event Log subscription. Windows-only.

    Subscribes to future events on the Security and System channels with
    EvtSubscribe, renders each record as XML, extracts the key fields and
    forwards a normalized event dict to the sink. All failures are captured
    as a human-readable reason — start() returns False instead of raising.
    """

    CHANNELS = ("Security", "System")

    def __init__(
        self,
        sink: Optional[_SINK] = None,
        channels: tuple = CHANNELS,
        poll_timeout_ms: int = 1000,
    ) -> None:
        self.sink: _SINK = sink or _jsonl_sink(LOG_PATH)
        self.channels = tuple(channels)
        self.poll_timeout_ms = poll_timeout_ms
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.received = 0
        self.reason = ""
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def source_name(self) -> str:
        return "Windows Event Log"

    def _extract(self, xml: str, channel: str) -> Dict[str, Any]:
        # Best-effort XML field extraction (regex, no extra deps).
        def _tag(name: str) -> str:
            m = re.search(rf"<{name}[^>]*>([^<]*)</{name}>", xml)
            return m.group(1).strip() if m else ""

        event_id = _tag("EventID")
        level = _tag("Level")
        provider = ""
        m = re.search(r'<Provider[^>]*Name="([^"]+)"', xml)
        if m:
            provider = m.group(1)
        computer = _tag("Computer")
        time_created = ""
        m = re.search(r'<TimeCreated[^>]*SystemTime="([^"]+)"', xml)
        if m:
            time_created = m.group(1)
        data_items = re.findall(r"<Data(?:[^>]*)>([^<]*)</Data>", xml)
        detail = "; ".join(d.strip() for d in data_items if d.strip())[:300]
        msg = f"[{channel}] EventID {event_id or '?'} {provider}: {detail or 'no event data'}"
        return _normalize_system_event(
            channel=channel,
            event_id=event_id,
            level=level,
            provider=provider,
            computer=computer,
            host=computer or "-",
            user="-",
            src_ip="-",
            event_time=time_created,
            msg=msg,
            vector="SYSTEM_LOG",
        )

    def _poll_channel(self, channel: str) -> None:
        evt = _win32evtlog
        try:
            sub = evt.EvtSubscribe(channel, evt.EvtSubscribeToFutureEvents)
        except Exception as exc:  # noqa: BLE001 — e.g. access denied on Security
            with self._lock:
                self.reason = f"{channel}: {type(exc).__name__}: {exc}"
            return
        try:
            while not self._stop.is_set():
                try:
                    handles = evt.EvtNext(sub, self.poll_timeout_ms)
                except Exception:
                    continue  # timeout or transient — keep polling
                for h in handles or []:
                    try:
                        xml = evt.EvtRender(h, evt.EvtRenderEventXml)
                    except Exception:
                        continue
                    try:
                        self.sink(self._extract(xml, channel))
                    except Exception:
                        pass
                    with self._lock:
                        self.received += 1
        finally:
            try:
                evt.EvtClose(sub)
            except Exception:
                pass

    def _run(self) -> None:
        workers = []
        for ch in self.channels:
            t = threading.Thread(
                target=self._poll_channel, args=(ch,),
                name=f"winevt-{ch}", daemon=True,
            )
            t.start()
            workers.append(t)
        for t in workers:
            t.join()

    def start(self) -> bool:
        if self.running:
            return True
        if _win32evtlog is None:
            self.reason = (
                "pywin32 not available "
                f"({_win32_import_error or 'win32evtlog missing'})"
            )
            return False
        if sys.platform != "win32":
            self.reason = "Windows Event Log requires Windows (win32)"
            return False
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="winevt-tailer", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "source": self.source_name,
                "channels": list(self.channels),
                "received": self.received,
                "running": self.running,
                "reason": self.reason,
            }


class JournaldTailer:
    """Tails `journalctl --follow -o short-precise` in a subprocess thread.

    Falls back gracefully: if journalctl is missing, exits immediately, or
    the platform is not Linux, start() returns False with a reason.
    """

    def __init__(self, sink: Optional[_SINK] = None) -> None:
        self.sink: _SINK = sink or _jsonl_sink(LOG_PATH)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proc = None
        self.received = 0
        self.reason = ""
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def source_name(self) -> str:
        return "journald"

    def _parse_line(self, line: str) -> Dict[str, Any]:
        # short-precise: "Sep 22 17:33:01.123456 hostname app[pid]: message"
        m = re.match(
            r"^\w{3}\s+\d{1,2}\s+(\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
            r"(\S+)\s+([^:]+):\s*(.*)$",
            line,
        )
        if m:
            _clock, host, app, msg = m.groups()
            app = app.strip()
            return _normalize_system_event(
                channel="journald",
                host=host,
                user="-",
                src_ip="-",
                app=app,
                msg=f"[{app}] {msg.strip()}"[:500],
                vector="SYSTEM_LOG",
            )
        return _normalize_system_event(
            channel="journald", host="-", user="-", src_ip="-",
            msg=line[:500], vector="SYSTEM_LOG",
        )

    def _reader(self) -> None:
        try:
            proc = self._proc
            if proc is None or proc.stdout is None:
                return
            for line in proc.stdout:
                if self._stop.is_set():
                    break
                text = line.strip()
                if not text or text.startswith("--"):
                    continue
                try:
                    self.sink(self._parse_line(text))
                except Exception:
                    pass
                with self._lock:
                    self.received += 1
        except Exception:
            pass

    def start(self) -> bool:
        if self.running:
            return True
        if sys.platform != "linux":
            self.reason = "journald requires Linux"
            return False
        if shutil.which("journalctl") is None:
            self.reason = "journalctl binary not found"
            return False
        try:
            import subprocess

            self._proc = subprocess.Popen(
                ["journalctl", "--follow", "-n", "0",
                 "-o", "short-precise", "--no-pager"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except Exception as exc:  # noqa: BLE001
            self.reason = f"could not launch journalctl: {exc}"
            return False
        time.sleep(0.4)
        if self._proc.poll() is not None:
            self.reason = (
                f"journalctl exited immediately (rc={self._proc.poll()}) — "
                "journal may be unavailable"
            )
            self._proc = None
            return False
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._reader, name="journald-tailer", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._proc is not None:
            try:
                self._proc.terminate()
            except Exception:
                pass
            self._proc = None
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "source": self.source_name,
                "received": self.received,
                "running": self.running,
                "reason": self.reason,
            }


_LINUX_FALLBACK_LOGS = (
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/messages",
    "/var/log/secure",
)


class SystemLogSource:
    """Zero-config native OS log source with automatic platform selection.

    Windows -> WindowsEventLogTailer (Security + System channels).
    Linux   -> JournaldTailer, else FileTailer over /var/log/syslog etc.
    Anything else -> unavailable (reason recorded, app continues normally).
    """

    def __init__(self, sink: Optional[_SINK] = None) -> None:
        self.sink: _SINK = sink or _jsonl_sink(LOG_PATH)
        self.backend: Optional[Any] = None
        self.source_name = "none"
        self.reason = ""
        self._fallbacks: List[FileTailer] = []

    @property
    def running(self) -> bool:
        if self.backend is not None:
            return bool(self.backend.running)
        return any(f.running for f in self._fallbacks)

    @property
    def received(self) -> int:
        n = 0
        if self.backend is not None:
            n += int(getattr(self.backend, "received", 0) or 0)
        for f in self._fallbacks:
            n += int(getattr(f, "lines_forwarded", 0) or 0)
        return n

    def start(self) -> bool:
        if self.running:
            return True
        try:
            if sys.platform == "win32":
                return self._start_windows()
            if sys.platform == "linux":
                return self._start_linux()
            self.reason = f"unsupported platform: {sys.platform}"
            return False
        except Exception as exc:  # noqa: BLE001 — never let auto-start crash the app
            self.reason = f"{type(exc).__name__}: {exc}"
            return False

    def _start_windows(self) -> bool:
        tailer = WindowsEventLogTailer(sink=self.sink)
        if tailer.start():
            self.backend = tailer
            self.source_name = tailer.source_name
            return True
        self.reason = tailer.reason or "Windows Event Log unavailable"
        return False

    def _start_linux(self) -> bool:
        jd = JournaldTailer(sink=self.sink)
        if jd.start():
            self.backend = jd
            self.source_name = "journald"
            return True
        tried: List[str] = []
        for path in _LINUX_FALLBACK_LOGS:
            p = Path(path)
            if not p.is_file():
                tried.append(f"{path} (absent)")
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="replace"):
                    pass
            except OSError:
                tried.append(f"{path} (permission denied)")
                continue
            ft = FileTailer(p, sink=self.sink)
            ft.start()
            if ft.running:
                self._fallbacks.append(ft)
                tried.append(f"{path} (live)")
            else:
                tried.append(f"{path} (failed)")
        if self._fallbacks:
            self.source_name = "syslog files: " + ", ".join(
                Path(f.path).name for f in self._fallbacks
            )
            self.reason = f"journald unavailable ({jd.reason}); using file fallback"
            return True
        self.reason = f"journald unavailable ({jd.reason}); fallbacks: {'; '.join(tried)}"
        return False

    def stop(self) -> None:
        for f in self._fallbacks:
            try:
                f.stop()
            except Exception:
                pass
        self._fallbacks = []
        if self.backend is not None:
            try:
                self.backend.stop()
            except Exception:
                pass

    def describe_short(self) -> str:
        """Compact source name for the LIVE badge (e.g. 'journald')."""
        if sys.platform == "win32":
            return "Windows Event Log"
        return self.source_name

    def describe(self) -> str:
        if self.running:
            n = self.received
            if sys.platform == "win32":
                return (
                    "SYSTEM: Windows Event Log — LIVE "
                    f"(Security + System, {n} events)"
                )
            return f"SYSTEM: {self.source_name} — LIVE ({n} lines)"
        return f"SYSTEM: unavailable — {self.reason or 'no native source'}"


# ---------------------------------------------------------------------------
# Streamlit panel
# ---------------------------------------------------------------------------
_listener: Optional[SyslogListener] = None


def ensure_listener_running(host: str = "127.0.0.1", tcp_port: int = 1514,
                            udp_port: int = 1514) -> bool:
    """Auto-start the syslog listener (zero-config first run).

    Idempotent: returns True immediately if a listener is already running.
    Returns False (never raises) when the ports are unavailable — e.g. a
    second copy of the app is already listening — so boot is never blocked.
    """
    global _listener
    if _listener is not None and _listener.running:
        return True
    try:
        _listener = SyslogListener(host=host, tcp_port=tcp_port, udp_port=udp_port)
        _listener.start()
        return True
    except OSError:
        _listener = None
        return False


_system_source: Optional[SystemLogSource] = None


def is_listener_running() -> bool:
    """True when the syslog listener is currently live."""
    return _listener is not None and _listener.running


def ensure_system_log_running() -> bool:
    """Auto-start the native OS log source (zero-config first run).

    Idempotent: returns True immediately if a source is already live.
    Returns False (never raises) when no native source is available — e.g.
    missing permissions or no journal — so boot is never blocked.
    """
    global _system_source
    try:
        if _system_source is not None and _system_source.running:
            return True
        _system_source = SystemLogSource()
        return _system_source.start()
    except Exception:
        return False


def get_system_log_source() -> Optional[SystemLogSource]:
    """The current native-OS log source (or None if never started)."""
    return _system_source


def render_ingest_panel() -> None:
    """Listener controls + recent parsed-line preview."""
    global _listener
    st.subheader("Log ingest — syslog listener")

    if _listener is not None and _listener.running:
        st.markdown(
            f'<div class="cp-banner cp-hardened"><span class="cp-live-dot"></span>LIVE — LISTENING — { _listener.host } '
            f"TCP/{_listener.tcp_port} + UDP/{_listener.udp_port} "
            f"({_listener.received} lines received)"
            '<div class="cp-streambar"><div class="cp-streambar-fill"></div></div></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="cp-banner cp-action">IDLE — listener is not running.</div>',
            unsafe_allow_html=True,
        )

    col1, col2, col3 = st.columns(3)
    with col1:
        host = st.text_input("Bind host", "127.0.0.1", key="ingest_host")
    with col2:
        tcp_port = st.number_input("TCP port", 1, 65535, 1514, key="ingest_tcp")
    with col3:
        udp_port = st.number_input("UDP port", 1, 65535, 1514, key="ingest_udp")

    b1, b2 = st.columns(2)
    with b1:
        if st.button("Start listener", key="ingest_start"):
            _listener = SyslogListener(host=host, tcp_port=int(tcp_port),
                                       udp_port=int(udp_port))
            _listener.start()
            st.rerun()
    with b2:
        if st.button("Stop listener", key="ingest_stop"):
            if _listener:
                _listener.stop()
            st.rerun()

    st.caption(f"Default sink appends JSONL to: {LOG_PATH}")
    st.caption(
        "The listener auto-starts with the app on 127.0.0.1:1514 "
        "(zero-config). The buttons below are a manual override."
    )

    st.markdown("**Native OS system logs — direct attachment (zero-config)**")
    src = get_system_log_source()
    if src is not None and src.running:
        st.markdown(
            f'<div class="cp-banner cp-hardened"><span class="cp-live-dot"></span>'
            f"{src.describe()}"
            '<div class="cp-streambar"><div class="cp-streambar-fill"></div></div></div>',
            unsafe_allow_html=True,
        )
    else:
        reason = (src.reason if src else "not started")
        st.markdown(
            f'<div class="cp-banner cp-action">SYSTEM log source idle — {reason}. '
            "The syslog listener above still feeds the SIEM stream.</div>",
            unsafe_allow_html=True,
        )
    s1, s2 = st.columns(2)
    with s1:
        if st.button("Start system log source", key="syslog_src_start", use_container_width=True):
            ensure_system_log_running()
            st.rerun()
    with s2:
        if st.button("Stop system log source", key="syslog_src_stop", use_container_width=True):
            if src:
                src.stop()
            st.rerun()
    st.caption(
        "Windows: live Security + System channel subscription (win32evtlog). "
        "Linux: journalctl --follow, falling back to /var/log/syslog + /var/log/auth.log. "
        "Unavailable sources are skipped with a warning — the app never crashes."
    )

    st.markdown("**Recent parsed lines (from the live SIEM stream file)**")
    try:
        lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        preview = [parse_syslog_line(l) for l in lines[-10:]]
        if preview:
            st.dataframe(preview, use_container_width=True)
        else:
            st.caption("Stream file is empty.")
    except FileNotFoundError:
        st.caption("Stream file does not exist yet.")
