"""
Pak-CyberPulse Website Monitor — per-website traffic analysis + auto-blocking.

- Register websites (name + web-server access-log path) persisted in SQLite.
- A background tailer per site parses Combined Log Format lines and forwards
  normalized HTTP_REQ events into the SIEM engine stream, so the EXISTING
  attack_patterns registry (SQLi, XSS, CMDI, LFI, SSRF, BAC, …) and the
  behavioral correlators (brute-force sliding window, password spray) fire
  unchanged. 401/403 on login-like URLs are additionally emitted as
  AUTH_FAIL so the PISF-05.2 IAM window sees credential attacks.
- A watcher thread polls engine.snapshot() for pattern/injection hits
  tagged with the site, keeps a per-(site, IP) 5-minute sliding window, and
  at >= 3 attack hits auto-blocks via the EXISTING SOAR contain_source_ip().
- Blocked IPs are persisted in the DB with unblock support. Firewall
  blocking honestly requires admin/root; without privileges the UI shows
  "block unavailable — run as admin" instead of silently failing.

No new detection engine: everything reuses modules/attack_patterns.py and
modules/soar_engine.py.
"""

from __future__ import annotations

import html
import os
import re
import sqlite3
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import streamlit as st

from database.db_manager import get_db, utc_now

# Auto-block policy: N attack-pattern hits from one IP inside the window.
BLOCK_THRESHOLD = 3
BLOCK_WINDOW_S = 300

# Combined Log Format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "ref" "ua"
ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+(?P<proto>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

_LOGIN_URL_RE = re.compile(
    r"(?i)(login|signin|sign-in|sign_in|auth|wp-login|wp_admin|account|password)"
)


def parse_access_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one Combined-Log-Format line. Returns None when unparseable."""
    m = ACCESS_LOG_RE.match((line or "").strip())
    if not m:
        return None
    d = m.groupdict()
    ts = time.time()
    try:
        ts = datetime.strptime(d["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except (ValueError, TypeError):
        pass
    try:
        status = int(d["status"])
    except (TypeError, ValueError):
        status = 0
    return {
        "ip": d["ip"],
        "user": d["user"] if d["user"] != "-" else "-",
        "method": d["method"],
        "url": d["url"],
        "proto": (d["proto"] or "").strip(),
        "status": status,
        "bytes": d["bytes"],
        "ua": (d["ua"] or "")[:160],
        "ts": ts,
    }


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def access_events(site_name: str, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize one parsed access-log line into SIEM event dicts.

    Always emits HTTP_REQ (feeds the signature registry). Additionally
    emits AUTH_FAIL for 401/403 on login-like URLs so the brute-force
    sliding window and spray correlators see credential attacks.
    """
    ts = float(parsed["ts"])
    base_msg = (
        f'{parsed["method"]} {parsed["url"]} {parsed["proto"]} '
        f'{parsed["status"]} {parsed["bytes"]}'.strip()
    )
    events = [
        {
            "ts": ts,
            "iso": _iso(ts),
            "event": "HTTP_REQ",
            "user": parsed["user"],
            "src_ip": parsed["ip"],
            "host": site_name,
            "asset_class": "Standard",
            "msg": base_msg,
            "site": site_name,
            "url": parsed["url"],
            "http_status": parsed["status"],
            "user_agent": parsed["ua"],
            "vector": "WEBSITE_MONITOR",
        }
    ]
    if parsed["status"] in (401, 403) and _LOGIN_URL_RE.search(parsed["url"]):
        events.append(
            {
                "ts": ts,
                "iso": _iso(ts),
                "event": "AUTH_FAIL",
                "user": parsed["user"],
                "src_ip": parsed["ip"],
                "host": site_name,
                "asset_class": "Standard",
                "msg": f'WEB AUTH_FAIL {parsed["method"]} {parsed["url"]} -> {parsed["status"]}',
                "site": site_name,
                "url": parsed["url"],
                "vector": "WEBSITE_MONITOR",
            }
        )
    return events


class _SiteTailer:
    """Tails one website access log from its end, forwarding parsed events
    into the SIEM engine stream (engine.append_event)."""

    def __init__(
        self,
        site_id: int,
        site_name: str,
        log_path: str,
        engine,
        stats_sink: Callable[[int, Dict[str, Any]], None],
    ) -> None:
        self.site_id = site_id
        self.site_name = site_name
        self.log_path = Path(log_path)
        self.engine = engine
        self.stats_sink = stats_sink
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.lines_parsed = 0
        self.lines_skipped = 0
        self.last_error = ""

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        try:
            fh = open(self.log_path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return
        with fh:
            try:
                fh.seek(0, os.SEEK_END)
            except OSError:
                pass
            last_size = self.log_path.stat().st_size
            while not self._stop.is_set():
                try:
                    # Log rotation: file shrank -> re-seek to end.
                    try:
                        size = self.log_path.stat().st_size
                        if size < last_size:
                            fh.seek(0, os.SEEK_END)
                        last_size = size
                    except OSError:
                        pass
                    line = fh.readline()
                    if not line:
                        time.sleep(0.25)
                        continue
                    parsed = parse_access_log_line(line)
                    if parsed is None:
                        self.lines_skipped += 1
                        continue
                    try:
                        for ev in access_events(self.site_name, parsed):
                            self.engine.append_event(ev)
                        self.stats_sink(self.site_id, parsed)
                    except Exception:
                        pass
                    self.lines_parsed += 1
                except Exception as exc:  # never let the tailer die silently
                    self.last_error = f"tailer loop: {type(exc).__name__}: {exc}"
                    try:
                        from modules.app_config import log_to_desktop
                        log_to_desktop(
                            f"website-tailer site={self.site_id} error: {exc}")
                    except Exception:
                        pass
                    time.sleep(2.0)

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name=f"website-tailer-{self.site_id}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None


class WebsiteMonitor:
    """Singleton manager: site tailers, per-site stats, auto-block watcher."""

    def __init__(self, db, engine) -> None:
        self.db = db
        self.engine = engine
        self.lock = threading.RLock()
        self._tailers: Dict[int, _SiteTailer] = {}
        self.site_stats: Dict[int, Dict[str, Deque]] = {}
        self._hit_windows: Dict[Tuple[int, str], Deque[float]] = defaultdict(deque)
        self._seen_hit_keys: set = set()
        self._blocked_keys: set = set()  # (site_id, ip) already auto-blocked
        self.last_blocks: Deque[Dict[str, Any]] = deque(maxlen=10)
        self._watch_stop = threading.Event()
        self._watch_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Start tailers for all enabled sites + the auto-block watcher."""
        with self.lock:
            for site in self.db.list_websites():
                if site["enabled"]:
                    self._ensure_tailer(site)
            if self._watch_thread is None or not self._watch_thread.is_alive():
                self._watch_stop.clear()
                self._watch_thread = threading.Thread(
                    target=self._watch_loop, name="website-monitor-watcher", daemon=True
                )
                self._watch_thread.start()

    def _ensure_tailer(self, site: Dict[str, Any]) -> Optional[_SiteTailer]:
        sid = int(site["site_id"])
        tailer = self._tailers.get(sid)
        if tailer is not None and tailer.running:
            return tailer
        if sid not in self.site_stats:
            self.site_stats[sid] = {
                "events": deque(maxlen=5000),  # (ts, ip, url, status)
                "hits": deque(maxlen=1000),    # (ts, kind, pattern/id, ip)
            }
        tailer = _SiteTailer(
            sid, site["name"], site["log_path"], self.engine, self._record_event
        )
        tailer.start()
        self._tailers[sid] = tailer
        return tailer

    def _record_event(self, site_id: int, parsed: Dict[str, Any]) -> None:
        buf = self.site_stats.get(site_id)
        if buf is not None:
            buf["events"].append(
                (parsed["ts"], parsed["ip"], parsed["url"], parsed["status"])
            )

    # -------------------------------------------------- http ingest (v7)
    def ingest_lines(self, site_ref: str, lines: List[str]) -> Dict[str, Any]:
        """Feed access-log lines for a registered site via the HTTP endpoint.

        Same parse -> SIEM-event -> stats pipeline as the file tailer, so
        detection, thresholds and auto-block behave identically. Returns
        counts; never raises."""
        try:
            site = self.db.find_website(site_ref)
            if site is None:
                return {"ok": False, "error": f"unknown website {site_ref!r}"}
            sid = int(site["site_id"])
            if sid not in self.site_stats:
                self.site_stats[sid] = {
                    "events": deque(maxlen=5000),
                    "hits": deque(maxlen=1000),
                }
            parsed_n = skipped = events_n = 0
            for raw in (lines or [])[:5000]:
                if not isinstance(raw, str) or not raw.strip():
                    skipped += 1
                    continue
                parsed = parse_access_log_line(raw)
                if parsed is None:
                    skipped += 1
                    continue
                parsed_n += 1
                try:
                    for ev in access_events(site["name"], parsed):
                        self.engine.append_event(ev)
                        events_n += 1
                    self._record_event(sid, parsed)
                except Exception:
                    pass
            self.db.mark_website_http_source(sid)
            return {"ok": True, "site": site["name"], "parsed": parsed_n,
                    "skipped": skipped, "events": events_n}
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    # ------------------------------------------------------------ registry
    def register_site(self, name: str, log_path: str, note: str = "") -> int:
        name = (name or "").strip()
        log_path = (log_path or "").strip()
        if not name:
            raise ValueError("Website name is required.")
        if len(name) > 80:
            raise ValueError("Website name is too long (max 80 chars).")
        # Canonicalize the path (resolves "..", symlinks) BEFORE any check —
        # the tailer must open exactly this file, never a traversal surprise.
        try:
            p = Path(log_path).expanduser().resolve()
        except Exception as exc:
            raise ValueError(f"Bad access-log path: {exc}")
        if not p.is_file():
            raise ValueError(f"Access log not found: {log_path}")
        try:
            with open(p, "r", encoding="utf-8", errors="replace"):
                pass
        except OSError as exc:
            raise ValueError(f"Access log not readable: {exc}")
        try:
            site_id = self.db.register_website(name, str(p), note)
        except sqlite3.IntegrityError:
            raise ValueError(f'A website named "{name}" is already registered.')
        site = next(
            (s for s in self.db.list_websites() if int(s["site_id"]) == site_id), None
        )
        if site:
            self._ensure_tailer(site)
        return site_id

    def remove_site(self, site_id: int) -> None:
        with self.lock:
            tailer = self._tailers.pop(int(site_id), None)
            if tailer:
                tailer.stop()
            self.site_stats.pop(int(site_id), None)
        self.db.remove_website(int(site_id))

    def set_enabled(self, site_id: int, enabled: bool) -> None:
        self.db.set_website_enabled(int(site_id), enabled)
        with self.lock:
            if enabled:
                site = next(
                    (s for s in self.db.list_websites()
                     if int(s["site_id"]) == int(site_id)),
                    None,
                )
                if site:
                    self._ensure_tailer(site)
            else:
                tailer = self._tailers.pop(int(site_id), None)
                if tailer:
                    tailer.stop()

    def tailer_status(self, site_id: int) -> Dict[str, Any]:
        t = self._tailers.get(int(site_id))
        if t is None:
            return {"running": False, "lines_parsed": 0, "last_error": "not started"}
        return {
            "running": t.running,
            "lines_parsed": t.lines_parsed,
            "lines_skipped": t.lines_skipped,
            "last_error": t.last_error,
        }

    # ------------------------------------------------------------ watcher
    def _site_id_by_name(self) -> Dict[str, int]:
        return {s["name"]: int(s["site_id"]) for s in self.db.list_websites()}

    def _hit_key(self, kind: str, h: Dict[str, Any]) -> tuple:
        if kind == "pattern":
            return ("p", h.get("pattern_id"), h.get("src_ip"),
                    str(h.get("matched", ""))[:60], h.get("ts"))
        return ("i", h.get("src_ip"), str(h.get("msg", ""))[:60], h.get("ts"))

    def _watch_once(self) -> None:
        """Single watcher pass — also used by tests for determinism."""
        try:
            snap = self.engine.snapshot()
        except Exception:
            return
        name_to_id = self._site_id_by_name()
        if not name_to_id:
            return
        candidates: List[Tuple[str, Dict[str, Any]]] = []
        for h in snap.get("patterns") or []:
            # Pattern hits carry host=<site name> (no arbitrary fields copied).
            sid = name_to_id.get(str(h.get("host", "")))
            if sid is not None:
                candidates.append(("pattern", h, sid))
        for h in snap.get("injections") or []:
            # Injection findings spread the full event incl. "site".
            sid = name_to_id.get(str(h.get("site", h.get("host", ""))))
            if sid is not None:
                candidates.append(("injection", h, sid))
        now = time.time()
        for kind, h, sid in candidates:
            key = self._hit_key(kind, h)
            with self.lock:
                if key in self._seen_hit_keys:
                    continue
                self._seen_hit_keys.add(key)
                if len(self._seen_hit_keys) > 5000:
                    self._seen_hit_keys = set(list(self._seen_hit_keys)[-2500:])
            ip = str(h.get("src_ip", "") or "").strip()
            if not ip or ip in {"0.0.0.0", "-", "unknown"}:
                continue
            buf = self.site_stats.get(sid)
            if buf is not None:
                label = h.get("pattern_id") or ",".join(h.get("signatures", []))
                buf["hits"].append((now, kind, str(label), ip))
            win = self._hit_windows[(sid, ip)]
            win.append(now)
            while win and now - win[0] > BLOCK_WINDOW_S:
                win.popleft()
            if len(win) >= BLOCK_THRESHOLD and (sid, ip) not in self._blocked_keys:
                self._auto_block(sid, ip, len(win))

    def _auto_block(self, site_id: int, ip: str, hits: int) -> None:
        # NOTE: ACL_PATH is read from modules.soar_engine (not db_manager)
        # because containment writes through that module's binding, which
        # tests redirect to a tmp file.
        from modules.soar_engine import ACL_PATH, contain_source_ip

        site_name = next(
            (s["name"] for s in self.db.list_websites()
             if int(s["site_id"]) == site_id),
            f"site-{site_id}",
        )
        reason = (
            f"{hits} attack-pattern hits from {ip} inside "
            f"{BLOCK_WINDOW_S}s (auto-block threshold {BLOCK_THRESHOLD})"
        )
        # The SIEM engine already contains block_ip-action patterns on the
        # FIRST live hit (see siem_panel._mitigate_pattern). Do not double
        # block: if an ACL marker for this IP exists, the engine got there
        # first — record it honestly instead of calling contain_source_ip
        # again. Only IPs the engine left alone (alert-action patterns) are
        # blocked here under the 3-in-5-min website policy.
        already = False
        try:
            if ACL_PATH.exists():
                txt = ACL_PATH.read_text(encoding="utf-8")
                already = any(
                    ln.startswith(f"DENY {ip} ") or ln.startswith(f"BAN {ip} ")
                    for ln in txt.splitlines()
                )
        except OSError:
            pass
        try:
            if already:
                mode = "ENGINE AUTO-CONTAINMENT"
                detail = (
                    "IP was already contained by the SIEM engine on the first "
                    f"live signature hit (block_ip playbook). Website-monitor "
                    f"threshold met ({hits} hits / {BLOCK_WINDOW_S}s) — recorded "
                    "here for visibility; no duplicate firewall/ACL call made."
                )
            else:
                result = contain_source_ip(ip)
                mode, detail = result.mode, result.detail
        except Exception as exc:  # noqa: BLE001 — block must never kill the watcher
            mode, detail = "ERROR", f"{type(exc).__name__}: {exc}"
        try:
            block_id = self.db.record_website_block(
                site_id, site_name, ip, reason, mode, detail[:400]
            )
        except Exception:
            block_id = -1
        # Incident-ledger trail for the GRC record.
        try:
            self.db.record_incident(
                source_ip=ip,
                target_host=site_name,
                classification="WEBSITE_AUTO_BLOCK",
                detection_rule=reason,
                mitigating_action=f"{mode}: {detail[:200]}",
                privilege_state="website-monitor",
                raw_record=f"website_monitor auto-block site={site_name} ip={ip} hits={hits}",
                sha256="",
            )
        except Exception:
            pass
        with self.lock:
            self._blocked_keys.add((site_id, ip))
            self.last_blocks.append(
                {
                    "block_id": block_id,
                    "site_id": site_id,
                    "site_name": site_name,
                    "ip": ip,
                    "mode": mode,
                    "detail": detail,
                    "ts": time.time(),
                }
            )

    def _watch_loop(self) -> None:
        while not self._watch_stop.is_set():
            try:
                self._watch_once()
            except Exception as exc:  # never let the watcher die silently
                try:
                    from modules.app_config import log_to_desktop
                    log_to_desktop(f"website-monitor watcher error: {exc}")
                except Exception:
                    pass
            time.sleep(2.0)

    # ------------------------------------------------------------ unblock
    def unblock_ip(self, block_id: int) -> Dict[str, Any]:
        """Best-effort unblock: remove DENY/BAN ACL lines for the IP and mark
        the block unblocked in the DB. OS firewall rules installed as
        NETWORK FIREWALL BLOCK need the same privileges to remove — the UI
        states this honestly."""
        # Same binding note as _auto_block: read through soar_engine.
        from modules.soar_engine import ACL_PATH

        blocks = self.db.list_website_blocks(include_unblocked=True)
        blk = next((b for b in blocks if int(b["block_id"]) == int(block_id)), None)
        if blk is None:
            return {"ok": False, "note": "Block record not found."}
        ip = str(blk["source_ip"])
        removed = 0
        try:
            if ACL_PATH.exists():
                lines = ACL_PATH.read_text(encoding="utf-8").splitlines()
                kept = []
                for ln in lines:
                    if ln.startswith(f"DENY {ip} ") or ln.startswith(f"BAN {ip} "):
                        removed += 1
                    else:
                        kept.append(ln)
                if removed:
                    ACL_PATH.write_text("\n".join(kept) + ("\n" if kept else ""),
                                        encoding="utf-8")
        except OSError as exc:
            return {"ok": False, "note": f"ACL file not writable: {exc}"}
        self.db.mark_block_unblocked(int(block_id))
        with self.lock:
            self._blocked_keys.discard((int(blk["site_id"] or -1), ip))
        note = f"Removed {removed} ACL line(s) for {ip}."
        if blk["mode"] == "NETWORK FIREWALL BLOCK":
            note += (" OS firewall rule needs the same admin/root privileges to remove — "
                     "delete it in your firewall console or re-run the app as admin/root.")
        return {"ok": True, "note": note}


_MONITOR: Optional[WebsiteMonitor] = None
_MONITOR_LOCK = threading.Lock()


def get_website_monitor() -> Optional[WebsiteMonitor]:
    return _MONITOR


def ensure_website_monitor_running(db=None, engine=None) -> Optional[WebsiteMonitor]:
    """Start the website monitor singleton (zero-config). Never raises."""
    global _MONITOR
    try:
        with _MONITOR_LOCK:
            if _MONITOR is not None:
                return _MONITOR
            from modules.siem_panel import get_siem_engine

            _MONITOR = WebsiteMonitor(db or get_db(), engine or get_siem_engine())
            _MONITOR.start()
            return _MONITOR
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------
def _per_minute(events: List[Tuple[float, ...]], minutes: int = 30) -> Dict[str, int]:
    now = time.time()
    buckets: Dict[str, int] = {}
    for i in range(minutes - 1, -1, -1):
        key = datetime.fromtimestamp(now - i * 60, tz=timezone.utc).strftime("%H:%M")
        buckets[key] = 0
    for (ts, *_rest) in events:
        age_min = int((now - ts) // 60)
        if 0 <= age_min < minutes:
            key = datetime.fromtimestamp(now - age_min * 60, tz=timezone.utc).strftime("%H:%M")
            buckets[key] = buckets.get(key, 0) + 1
    return buckets


def render_website_monitor(engine) -> None:
    db = get_db()
    mon = ensure_website_monitor_running(db, engine)

    from modules.soar_engine import detect_privilege

    priv = detect_privilege()
    fw_ok = bool(priv.get("privileged") and priv.get("firewall_binary"))
    if fw_ok:
        st.markdown(
            '<div class="cp-banner cp-hardened"><span class="cp-live-dot"></span>'
            "FIREWALL BLOCK ARMED — privileged process with firewall binary: "
            "auto-blocks install OS firewall rules.</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="cp-banner cp-action">FIREWALL BLOCK UNAVAILABLE — '
            "run as administrator (Windows) or root (Linux) for NETWORK FIREWALL BLOCK. "
            "Detection still fires; containment falls back to the application-layer ACL "
            "(mock_acl_rules.txt), never silently skipped.</div>",
            unsafe_allow_html=True,
        )

    st.subheader("Register a website")
    c1, c2 = st.columns((1, 2))
    with c1:
        wname = st.text_input("Website name", placeholder="e.g. myshop", key="wsite_name")
    with c2:
        wpath = st.text_input(
            "Access-log file path",
            placeholder="/var/log/nginx/access.log",
            key="wsite_path",
        )
    wnote = st.text_input("Note (optional)", key="wsite_note",
                          placeholder="e.g. production nginx")
    if st.button("➕ Add website", key="wsite_add", use_container_width=True):
        if mon is None:
            st.error("Website monitor failed to start — check the desktop log.")
        else:
            try:
                sid = mon.register_site(wname, wpath, wnote)
                st.success(f"Registered “{wname}” (id {sid}) — tailing live.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    st.caption(
        "Tip: your web server can also ship access logs via syslog to the existing "
        "listener (127.0.0.1:1514, Log Ingest tab) — the SIEM engine correlates "
        "those automatically; per-site dashboards use the tailed file above."
    )

    sites = db.list_websites()
    if not sites:
        st.info("No websites registered yet — add one above to start live traffic analysis.")
        return

    # ---- site picker + live status
    names = [s["name"] for s in sites]
    sel = st.selectbox("Website", names, key="wsite_sel")
    site = next(s for s in sites if s["name"] == sel)
    sid = int(site["site_id"])
    status = mon.tailer_status(sid) if mon else {"running": False}

    if status.get("running"):
        st.markdown(
            f'<div class="cp-livebar"><span class="cp-live-dot"></span>'
            f"LIVE — {html.escape(str(site['name']))} · tailing "
            f"{html.escape(str(site['log_path']))} "
            f"({status.get('lines_parsed', 0)} lines parsed)</div>",
            unsafe_allow_html=True,
        )
    elif site["enabled"]:
        st.markdown(
            f'<div class="cp-livebar off">⚠ TAILER NOT RUNNING — '
            f"{html.escape(str(site['name']))}: "
            f"{html.escape(str(status.get('last_error', 'unknown')))}. "
            f"No fake data is shown.</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div class="cp-livebar off">⏸ PAUSED — '
            f"{html.escape(str(site['name']))} (monitoring disabled).</div>",
            unsafe_allow_html=True,
        )

    st.caption(
        f"Ingest sources: **{site.get('ingest_sources', 'file')}** · "
        "remote servers can also ship lines via the authenticated REST endpoint "
        "`POST /websites/ingest` {\"site\": name, \"lines\": [...]}."
    )

    b1, b2, b3 = st.columns(3)
    with b1:
        _en = st.checkbox("Monitoring enabled", value=bool(site["enabled"]),
                          key=f"wsite_en_{sid}")
        if _en != bool(site["enabled"]) and mon:
            mon.set_enabled(sid, _en)
            st.rerun()
    with b2:
        if st.button("⏸ Pause / ▶ Resume tailer", key=f"wsite_t_{sid}",
                     use_container_width=True) and mon:
            mon.set_enabled(sid, not site["enabled"])
            st.rerun()
    with b3:
        if st.button("🗑 Remove website", key=f"wsite_rm_{sid}",
                     use_container_width=True) and mon:
            mon.remove_site(sid)
            st.success(f"Removed “{site['name']}”.")
            st.rerun()

    # ---- recent auto-blocks with the red->green BLOCKED animation
    if mon:
        now = time.time()
        for blk in list(mon.last_blocks):
            if blk["site_id"] == sid and now - blk["ts"] < 120:
                st.markdown(
                    f'<div class="cp-blocked">'
                    f'<svg class="cp-check" viewBox="0 0 52 52">'
                    f'<circle class="cp-check-circle" cx="26" cy="26" r="24"/>'
                    f'<path class="cp-check-mark" d="M14 27l8 8 16-17"/></svg>'
                    f'<div class="cp-blocked-title">⛔ AUTO-BLOCKED — '
                    f'{html.escape(str(blk["ip"]))}</div>'
                    f'<div class="cp-blocked-sub">'
                    f'{html.escape(str(blk["site_name"]))} · '
                    f'{html.escape(str(blk["mode"]))} · '
                    f'threshold {BLOCK_THRESHOLD} hits / {BLOCK_WINDOW_S}s</div>'
                    f"</div>",
                    unsafe_allow_html=True,
                )

    # ---- traffic dashboard
    st.subheader(f"Traffic analysis — {site['name']}")
    st.markdown(
        '<div class="cp-scanline"><span class="cp-scanring"></span>ANALYZING LIVE TRAFFIC</div>',
        unsafe_allow_html=True,
    )
    buf = mon.site_stats.get(sid, {"events": deque(), "hits": deque()}) if mon else {}
    events: List[Tuple] = list(buf.get("events", []))
    hits: List[Tuple] = list(buf.get("hits", []))

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Requests (buffered)", f"{len(events)}")
    uniq_ips = len({e[1] for e in events})
    m2.metric("Unique source IPs", f"{uniq_ips}")
    m3.metric("Attack-pattern hits", f"{len(hits)}")
    n_blocks = len(db.list_website_blocks(site_id=sid))
    m4.metric("IPs auto-blocked", f"{n_blocks}")

    if events:
        rpm = _per_minute(events)
        st.markdown("**Requests per minute (live)**")
        st.line_chart(rpm, color="#00e676")

        ips = Counter(e[1] for e in events)
        urls = Counter(e[2] for e in events)
        codes = Counter(str(e[3]) for e in events)
        d1, d2 = st.columns(2)
        with d1:
            st.markdown("**Top source IPs**")
            st.dataframe(
                [{"source_ip": ip, "requests": n}
                 for ip, n in ips.most_common(10)],
                use_container_width=True, hide_index=True,
            )
        with d2:
            st.markdown("**Top requested URLs**")
            st.dataframe(
                [{"url": (u[:70] + "…") if len(u) > 70 else u, "requests": n}
                 for u, n in urls.most_common(10)],
                use_container_width=True, hide_index=True,
            )
        st.markdown("**Status-code breakdown**")
        st.bar_chart(dict(codes), color="#ff2b2b")
    else:
        st.caption("No requests buffered yet — tailer is live; traffic appears as it arrives.")

    if hits:
        st.markdown("**Attack-pattern hits over time**")
        st.line_chart(_per_minute([(h[0],) for h in hits]), color="#ff2b2b")
        st.dataframe(
            [{"time": _iso(h[0])[11:19], "kind": h[1], "pattern": h[2], "src_ip": h[3]}
             for h in reversed(hits[-20:])],
             use_container_width=True, hide_index=True,
        )

    # ---- blocked IPs with unblock
    st.subheader("Blocked IPs")
    blocks = db.list_website_blocks(site_id=sid)
    if not blocks:
        st.caption("No IPs blocked for this site yet.")
    else:
        for b in blocks:
            bc1, bc2 = st.columns((4, 1))
            with bc1:
                st.markdown(
                    f'<div class="cp-banner cp-hardened">⛔ '
                    f'<b>{html.escape(str(b["source_ip"]))}</b> — '
                    f'{html.escape(str(b["mode"]))} · '
                    f'{html.escape(str(b["blocked_at"])[:19])}<br>'
                    f'<span style="font-size:0.82rem;color:var(--fg-muted);">'
                    f'{html.escape(str(b["reason"]))}</span></div>',
                    unsafe_allow_html=True,
                )
            with bc2:
                if st.button("Unblock", key=f"wsite_unblock_{b['block_id']}",
                             use_container_width=True):
                    res = mon.unblock_ip(int(b["block_id"])) if mon else {"ok": False}
                    if res.get("ok"):
                        st.success(res["note"])
                    else:
                        st.error(res.get("note", "Unblock failed."))
                    st.rerun()
