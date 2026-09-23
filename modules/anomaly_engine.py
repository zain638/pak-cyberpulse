"""
Pak-CyberPulse anomaly detection engine (v4).

Numpy-based statistical machine learning for security telemetry — deliberately
kept explainable so a student can defend every number in a viva:

  * z-score outlier detection (classic, mean/std based)
  * modified z-score (MAD based — robust when the data itself has outliers)
  * EWMA spike detection on a live stream (event-rate / failure-rate bursts)
  * Shannon entropy scoring (flags DGA-like random domains / strings)
  * UEBA-lite: per-user behavioral baselines (usual login hours, usual source
    IPs, failed-login ratio) with a 0-100 per-user risk score and a
    plain-English explanation for every contributing factor.

Nothing here is a black box: every anomaly carries its detector name, its
score, and the human-readable reason it fired. High/Critical anomalies are
wired into the existing alert/incident pipeline by the SIEM engine
(see siem_panel._correlate_ml_anomaly).

This module has NO streamlit import at top level so the REST API and the
pytest suite can use it headlessly; the dashboard panel imports streamlit
lazily inside render_anomaly_panel().
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

import numpy as np


# ---------------------------------------------------------------------------
# Pure statistical primitives (no state — trivially unit-testable)
# ---------------------------------------------------------------------------

def zscore_outliers(
    values: Sequence[float], threshold: float = 3.0
) -> List[Tuple[int, float, float]]:
    """
    Classic z-score outlier detection.

    Returns [(index, value, z), ...] for every value with |z| >= threshold,
    where z = (x - mean) / std. Needs >= 3 samples and a non-zero std;
    returns [] otherwise (honest: no variance, no outliers).
    """
    arr = np.asarray(list(values), dtype=float)
    if arr.size < 3:
        return []
    mean = float(np.mean(arr))
    std = float(np.std(arr))
    if std == 0.0:
        return []
    out: List[Tuple[int, float, float]] = []
    for i, x in enumerate(arr):
        z = (float(x) - mean) / std
        if abs(z) >= threshold:
            out.append((i, float(x), z))
    return out


def modified_zscore_outliers(
    values: Sequence[float], threshold: float = 3.5
) -> List[Tuple[int, float, float]]:
    """
    Modified z-score using the Median Absolute Deviation (MAD).

    Mi = 0.6745 * (xi - median) / MAD. Robust: a few huge outliers cannot
    inflate the median/MAD the way they inflate mean/std, so this catches
    outliers the classic z-score misses. Returns [] when MAD == 0.
    """
    arr = np.asarray(list(values), dtype=float)
    if arr.size < 3:
        return []
    median = float(np.median(arr))
    mad = float(np.median(np.abs(arr - median)))
    if mad == 0.0:
        return []
    out: List[Tuple[int, float, float]] = []
    for i, x in enumerate(arr):
        mz = 0.6745 * (float(x) - median) / mad
        if abs(mz) >= threshold:
            out.append((i, float(x), mz))
    return out


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string in bits per character (0 for empty)."""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_outliers(
    strings: Sequence[str], threshold_bits: float = 4.0
) -> List[Tuple[int, str, float]]:
    """
    Flag strings whose per-character entropy >= threshold_bits.

    Normal English-ish hostnames/domains sit around 2.5-3.5 bits/char;
    random/DGA-like strings push past 4.0. Threshold is explicit and tunable.
    """
    out: List[Tuple[int, str, float]] = []
    for i, s in enumerate(strings):
        e = shannon_entropy(s or "")
        if e >= threshold_bits:
            out.append((i, s, e))
    return out


# ---------------------------------------------------------------------------
# Streaming EWMA spike detector
# ---------------------------------------------------------------------------

class EWMAAnomalyDetector:
    """
    Exponentially Weighted Moving Average spike detector for a live numeric
    stream (e.g. events/second, failed logins/minute).

    Keeps an EWMA mean and EWMA variance; a sample is anomalous when it lies
    more than `threshold` EWMA-stddevs above the running mean (one-sided:
    we care about spikes, not dips). A short warmup period learns the
    baseline before any firing.
    """

    def __init__(self, alpha: float = 0.3, threshold: float = 3.0,
                 warmup: int = 10) -> None:
        self.alpha = alpha
        self.threshold = threshold
        self.warmup = warmup
        self._mean: Optional[float] = None
        self._var: float = 0.0
        self._n = 0
        self._lock = threading.Lock()

    def update(self, x: float) -> Tuple[bool, float]:
        """
        Feed one sample. Returns (is_spike, z) where z is the one-sided
        prediction-error distance: (x - previous EWMA mean) / previous
        EWMA stddev. The stddev has a floor (5% of the baseline mean) so a
        perfectly flat baseline does not divide by zero or flag every
        wiggle as infinitely anomalous.
        """
        with self._lock:
            self._n += 1
            fx = float(x)
            if self._mean is None:
                self._mean = fx
                return False, 0.0
            prev_mean = self._mean
            raw_std = math.sqrt(self._var) if self._var > 0 else 0.0
            floor = 0.05 * abs(prev_mean) if prev_mean != 0 else 1e-6
            std = max(raw_std, floor)
            z = (fx - prev_mean) / std
            spike = self._n > self.warmup and z >= self.threshold
            # Update state AFTER scoring (prediction-error formulation).
            self._mean = self.alpha * fx + (1.0 - self.alpha) * prev_mean
            dev = fx - prev_mean
            self._var = self.alpha * dev * dev + (1.0 - self.alpha) * self._var
            return spike, z

    @property
    def samples_seen(self) -> int:
        with self._lock:
            return self._n

    @property
    def baseline_mean(self) -> Optional[float]:
        with self._lock:
            return self._mean


# ---------------------------------------------------------------------------
# UEBA-lite: per-user behavioral baseline + risk score
# ---------------------------------------------------------------------------

# Risk-score weights — each factor's maximum contribution (sum caps at 100).
_W_NEW_IP = 35.0
_W_OFF_HOURS = 25.0
_W_FAIL_RATIO = 20.0
_W_VOLUME_BURST = 15.0
_W_NEW_HOST = 5.0

_BASELINE_MIN_LOGINS = 5      # learn quietly until this many logins seen
_OFFHOUR_SHARE = 0.10         # hour holding <10% of logins is "off-hours"


class UserBehaviorBaseline:
    """
    Learns what "normal" looks like per user from AUTH_OK / AUTH_FAIL events:

      * usual source IPs (set)
      * usual login hours of day, UTC (24-bin histogram)
      * failed-login ratio over a sliding window of recent auth attempts
      * usual hosts seen

    risk_score(user, event) -> (score 0-100, [plain-English explanations]).
    observe(event) trains the baseline; scoring never trains (no feedback
    loops where an attack poisons its own baseline mid-score).
    """

    def __init__(self, fail_window: int = 50) -> None:
        self._lock = threading.RLock()
        self._ips: Dict[str, set] = defaultdict(set)
        self._hours: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._hosts: Dict[str, set] = defaultdict(set)
        self._logins: Dict[str, int] = defaultdict(int)
        self._attempts: Dict[str, Deque[bool]] = defaultdict(
            lambda: deque(maxlen=fail_window)
        )  # True == failed attempt
        self._event_counts: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=500)
        )  # event ts per user, for volume bursts

    # -- training ---------------------------------------------------------
    def observe(self, event: Dict[str, Any]) -> None:
        etype = str(event.get("event", "")).upper()
        user = str(event.get("user", "") or "").strip()
        if not user or user in {"-", "unknown"}:
            return
        ip = str(event.get("src_ip", "0.0.0.0"))
        host = str(event.get("host", "-"))
        try:
            ts = float(event.get("ts") or time.time())
        except (TypeError, ValueError):
            ts = time.time()
        with self._lock:
            self._event_counts[user].append(ts)
            if etype == "AUTH_OK":
                hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
                self._ips[user].add(ip)
                self._hours[user][hour] += 1
                self._hosts[user].add(host)
                self._logins[user] += 1
                self._attempts[user].append(False)
            elif etype == "AUTH_FAIL":
                self._attempts[user].append(True)

    # -- scoring ----------------------------------------------------------
    def risk_score(
        self, user: str, event: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        Score one event for one user. Returns (0-100, explanations).
        Below the baseline minimum the user is "still learning" -> (0.0, []).
        """
        user = (user or "").strip()
        if not user or user in {"-", "unknown"}:
            return 0.0, []
        with self._lock:
            total = self._logins.get(user, 0)
            if total < _BASELINE_MIN_LOGINS:
                return 0.0, []
            ips = set(self._ips[user])
            hours = dict(self._hours[user])
            hosts = set(self._hosts[user])
            attempts = list(self._attempts[user])
            ev_ts = list(self._event_counts[user])

        score = 0.0
        explanations: List[str] = []

        ip = str(event.get("src_ip", "0.0.0.0"))
        if ip not in ips and ip != "0.0.0.0":
            score += _W_NEW_IP
            explanations.append(
                f"New source IP {ip} — never seen in {total} prior logins"
            )

        try:
            ts = float(event.get("ts") or time.time())
        except (TypeError, ValueError):
            ts = time.time()
        hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
        share = hours.get(hour, 0) / max(1, total)
        if share < _OFFHOUR_SHARE:
            score += _W_OFF_HOURS
            explanations.append(
                f"Off-hours login at {hour:02d}:00 UTC "
                f"(only {share:.0%} of this user's logins happen then)"
            )

        if len(attempts) >= 5:
            fail_ratio = sum(1 for a in attempts if a) / len(attempts)
            if fail_ratio >= 0.5:
                contrib = _W_FAIL_RATIO * min(1.0, fail_ratio)
                score += contrib
                explanations.append(
                    f"High recent failure ratio: {fail_ratio:.0%} of last "
                    f"{len(attempts)} auth attempts failed"
                )

        # Volume burst: >5x the user's median events/minute over last 10 min.
        if len(ev_ts) >= 10:
            cutoff = ts - 600
            recent = [t for t in ev_ts if t >= cutoff]
            if len(recent) >= 10:
                per_min = len(recent) / 10.0
                # crude personal "usual" rate from the whole observed history
                span_min = max(1.0, (ev_ts[-1] - ev_ts[0]) / 60.0)
                usual = len(ev_ts) / span_min
                if usual > 0 and per_min > 5 * usual:
                    score += _W_VOLUME_BURST
                    explanations.append(
                        f"Volume burst: {per_min:.1f} events/min vs usual "
                        f"{usual:.1f} events/min for this user"
                    )

        host = str(event.get("host", "-"))
        if host != "-" and host not in hosts:
            score += _W_NEW_HOST
            explanations.append(f"First time this user seen on host {host}")

        return min(100.0, round(score, 1)), explanations

    def user_risk_table(self) -> List[Dict[str, Any]]:
        """One row per known user: current baseline risk posture."""
        with self._lock:
            users = list(self._logins.keys())
        rows: List[Dict[str, Any]] = []
        for user in users:
            with self._lock:
                total = self._logins[user]
                attempts = list(self._attempts[user])
            fail_ratio = (
                sum(1 for a in attempts if a) / len(attempts) if attempts else 0.0
            )
            # Baseline posture score (not event-triggered): new-IP/off-hour
            # history can't be scored without an event, so posture reflects
            # failure ratio + baseline maturity.
            posture = round(min(100.0, fail_ratio * 60.0), 1)
            rows.append(
                {
                    "user": user,
                    "logins_observed": total,
                    "known_ips": len(self._ips[user]),
                    "known_hosts": len(self._hosts[user]),
                    "recent_fail_ratio": round(fail_ratio, 3),
                    "posture_score": posture,
                    "baseline_trusted": total >= _BASELINE_MIN_LOGINS,
                }
            )
        rows.sort(key=lambda r: r["posture_score"], reverse=True)
        return rows


# ---------------------------------------------------------------------------
# Orchestrator: one entry point the SIEM engine calls per event
# ---------------------------------------------------------------------------

def _severity_for(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _iso(ts: Optional[float] = None) -> str:
    return datetime.fromtimestamp(
        ts if ts is not None else time.time(), tz=timezone.utc
    ).isoformat()


class AnomalyDetector:
    """
    Stateful orchestrator. Call process_event(event) for every SIEM event;
    returns a list of anomaly dicts (usually empty). Keeps the most recent
    anomalies in a bounded deque for the dashboard and API.

    Layers:
      1. EWMA spike on global event rate (events/sec sampled per event).
      2. UEBA-lite per-user risk score on AUTH_OK / AUTH_FAIL events.
      3. Entropy screen on domain-ish fields (host / msg-embedded domains).
    """

    def __init__(self, min_score_to_record: float = 40.0) -> None:
        self.ewma = EWMAAnomalyDetector(alpha=0.3, threshold=3.0, warmup=15)
        self.ueba = UserBehaviorBaseline()
        self.min_score_to_record = min_score_to_record
        self.recent: Deque[Dict[str, Any]] = deque(maxlen=100)
        self._fired: set = set()  # dedupe keys
        self._lock = threading.RLock()
        self._last_ts: Optional[float] = None
        self._rate_samples: Deque[float] = deque(maxlen=60)

    # -- helpers ----------------------------------------------------------
    def _note(self, anomaly: Dict[str, Any]) -> None:
        key_src = (
            anomaly.get("detector"), anomaly.get("user"),
            anomaly.get("src_ip"), anomaly.get("detail", "")[:80],
        )
        key = hashlib.sha256(repr(key_src).encode()).hexdigest()
        with self._lock:
            if key in self._fired:
                return
            self._fired.add(key)
            self.recent.append(anomaly)

    def _mk(
        self, detector: str, score: float, explanation: str,
        event: Dict[str, Any], detail: str = "",
    ) -> Dict[str, Any]:
        try:
            ts = float(event.get("ts") or time.time())
        except (TypeError, ValueError):
            ts = time.time()
        return {
            "ts": ts,
            "iso": _iso(ts),
            "detector": detector,
            "score": round(float(score), 1),
            "severity": _severity_for(score),
            "explanation": explanation,
            "detail": detail[:200],
            "user": str(event.get("user", "-")),
            "src_ip": str(event.get("src_ip", "0.0.0.0")),
            "host": str(event.get("host", "-")),
            "event": str(event.get("event", "")),
        }

    # -- main entry -------------------------------------------------------
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run every detection layer; return anomalies worth recording."""
        if not isinstance(event, dict):
            return []
        found: List[Dict[str, Any]] = []
        try:
            ts = float(event.get("ts") or time.time())
        except (TypeError, ValueError):
            ts = time.time()
        etype = str(event.get("event", "")).upper()
        user = str(event.get("user", "") or "")

        # Layer 1 — global event-rate spike (EWMA on inter-arrival rate).
        with self._lock:
            if self._last_ts is not None and ts > self._last_ts:
                dt = ts - self._last_ts
                if dt > 0:
                    self._rate_samples.append(1.0 / dt)
            self._last_ts = ts
        if len(self._rate_samples) >= 5:
            import numpy as _np

            rate = float(_np.mean(list(self._rate_samples)[-5:]))
            spike, z = self.ewma.update(rate)
            if spike:
                score = min(100.0, 55.0 + min(45.0, z * 5.0))
                found.append(
                    self._mk(
                        "EWMA event-rate spike",
                        score,
                        f"Event rate spiked to {rate:.1f}/s "
                        f"({z:.1f} EWMA-stddevs above baseline)",
                        event,
                    )
                )

        # Layer 2 — UEBA-lite per-user risk (AUTH events only).
        if etype in {"AUTH_OK", "AUTH_FAIL"} and user not in {"", "-", "unknown"}:
            # Train first, then score the CURRENT event against the baseline
            # built from PRIOR events (score-before-observe would poison).
            score, explanations = self.ueba.risk_score(user, event)
            self.ueba.observe(event)
            if score >= self.min_score_to_record and explanations:
                found.append(
                    self._mk(
                        "UEBA user-risk",
                        score,
                        "; ".join(explanations),
                        event,
                    )
                )
        elif etype:
            # Non-auth events still feed volume baselines.
            self.ueba.observe(event)

        # Layer 3 — entropy screen on host/domain-ish strings.
        host = str(event.get("host", "") or "")
        if host and host != "-" and "." in host:
            e = shannon_entropy(host.lower())
            if e >= 4.2 and len(host) >= 12:
                score = min(100.0, 45.0 + (e - 4.2) * 30.0)
                if score >= self.min_score_to_record:
                    found.append(
                        self._mk(
                            "Entropy (DGA-like host)",
                            score,
                            f"Host '{host}' has {e:.2f} bits/char entropy "
                            f"(>= 4.2 suggests randomly generated)",
                            event,
                        )
                    )

        for a in found:
            self._note(a)
        return found

    # -- read API ---------------------------------------------------------
    def recent_anomalies(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.recent)[-limit:]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_sev: Dict[str, int] = defaultdict(int)
            by_det: Dict[str, int] = defaultdict(int)
            for a in self.recent:
                by_sev[a["severity"]] += 1
                by_det[a["detector"]] += 1
            return {
                "total_recorded": len(self.recent),
                "by_severity": dict(by_sev),
                "by_detector": dict(by_det),
                "ewma_samples": self.ewma.samples_seen,
                "ewma_baseline": self.ewma.baseline_mean,
            }


# ---------------------------------------------------------------------------
# Demo vector (for the dashboard + live classroom demo)
# ---------------------------------------------------------------------------

def fire_anomaly_demo(detector: AnomalyDetector) -> Dict[str, Any]:
    """
    Train a small baseline for demo.user (10 normal 09:00 UTC logins from the
    office IP), then fire one 03:00 UTC login from a fresh IP. Returns the
    anomaly dict produced (or {} if scoring did not trigger).
    """
    user = "demo.user"
    office_ip = "10.10.8.44"
    base = time.time()
    day_ago = base - 86400
    for i in range(10):
        ts = day_ago + i * 600
        detector.process_event(
            {
                "ts": ts, "iso": _iso(ts), "event": "AUTH_OK",
                "user": user, "src_ip": office_ip, "host": "DEMO-WS-01",
            }
        )
    evil = {
        "ts": base, "iso": _iso(base), "event": "AUTH_OK",
        "user": user, "src_ip": "185.220.101.97", "host": "DEMO-WS-01",
    }
    # Force the 03:00 UTC hour for a deterministic off-hours finding.
    dt = datetime.fromtimestamp(base, tz=timezone.utc).replace(
        hour=3, minute=12, second=0, microsecond=0
    )
    evil["ts"] = dt.timestamp()
    evil["iso"] = dt.isoformat()
    out = detector.process_event(evil)
    return out[0] if out else {}


# ---------------------------------------------------------------------------
# Streamlit dashboard panel (lazy import — module stays headless-importable)
# ---------------------------------------------------------------------------

def render_anomaly_panel(detector: Optional[AnomalyDetector] = None) -> None:
    import streamlit as st

    det = detector or AnomalyDetector()
    st.subheader("Anomaly detection — statistical ML (explainable)")

    st.markdown(
        '<div class="cp-banner cp-action">'
        "<b>How it works (viva-ready):</b> z-score / modified z-score flag "
        "numeric outliers · EWMA tracks the live event rate and fires on "
        "spikes · Shannon entropy flags DGA-like random hostnames · UEBA-lite "
        "learns each user's usual hours, IPs and failure ratio and scores "
        "every login 0-100. Every finding carries its reason — no black box."
        "</div>",
        unsafe_allow_html=True,
    )

    stats = det.stats()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Anomalies recorded", stats["total_recorded"])
    c2.metric("Critical", stats["by_severity"].get("Critical", 0))
    c3.metric("High", stats["by_severity"].get("High", 0))
    c4.metric("EWMA samples", stats["ewma_samples"])
    if stats["by_detector"]:
        st.caption(
            "By detector: "
            + ", ".join(f"{k}: {v}" for k, v in stats["by_detector"].items())
        )

    if st.button("Run anomaly demo vector", key="anomaly-demo"):
        res = fire_anomaly_demo(det)
        if res:
            st.success(
                f"Demo anomaly recorded — score {res['score']} "
                f"({res['severity']}): {res['explanation']}"
            )
        else:
            st.info("Demo ran but scored below the recording threshold.")
        st.rerun()

    st.markdown("**Recent anomalies (score + explanation)**")
    rows = det.recent_anomalies(limit=50)
    if rows:
        st.dataframe(
            [
                {
                    "Time": r["iso"][:19],
                    "Detector": r["detector"],
                    "Score": r["score"],
                    "Severity": r["severity"],
                    "User": r["user"],
                    "Src IP": r["src_ip"],
                    "Explanation": r["explanation"],
                }
                for r in rows
            ],
            use_container_width=True,
        )
    else:
        st.caption(
            "No anomalies recorded yet — run the demo vector or generate "
            "logins that break a user's baseline."
        )

    st.markdown("**User risk table (UEBA-lite baselines)**")
    table = det.ueba.user_risk_table()
    if table:
        st.dataframe(
            [
                {
                    "User": r["user"],
                    "Logins observed": r["logins_observed"],
                    "Known IPs": r["known_ips"],
                    "Known hosts": r["known_hosts"],
                    "Recent fail ratio": r["recent_fail_ratio"],
                    "Posture score": r["posture_score"],
                    "Baseline trusted": "yes" if r["baseline_trusted"] else "learning…",
                }
                for r in table
            ],
            use_container_width=True,
        )
    else:
        st.caption("No user baselines yet — AUTH_OK events train them automatically.")
