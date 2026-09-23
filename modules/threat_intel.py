"""
Pak-CyberPulse threat-intelligence feed engine (SIMULATED).

All feeds in this module are synthetic: they behave like real threat-intel
feeds (staleness, enrichment, refresh) but every IOC is fabricated from
documentation ranges (TEST-NET-1/2/3 per RFC 5737) and RFC 2606-style
example domains, so nothing here can ever touch a real reputation system.
The UI labels them SIMULATED at every surface.

SQLite persistence follows the db_manager.py convention:
  - tables created idempotently via TIStore.ensure_schema()
  - seeding is a migration: feeds/IOCs are only inserted when missing
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import re
import sqlite3
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import streamlit as st

from database.db_manager import DatabaseManager, get_db, utc_now

IOC_TYPES = {"ip", "domain", "sha256"}

# ---------------------------------------------------------------------------
# REAL Abuse.ch feeds (free, no API key). Fetched over HTTPS with a timeout;
# any failure degrades gracefully to the honestly-labeled simulated feeds.
# ---------------------------------------------------------------------------
ABUSECH_FEEDS: dict[str, dict[str, Any]] = {
    "urlhaus": {
        "feed_name": "AbuseCH-URLhaus-LIVE",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "description": (
            "LIVE FEED — Abuse.ch URLhaus: domains extracted from currently "
            "reported malware-distribution URLs (refreshed from abuse.ch)."
        ),
        "update_interval_h": 6,
        "parser": "urlhaus",
        "threat_type": "malware-distribution",
    },
    "feodo": {
        "feed_name": "AbuseCH-Feodo-LIVE",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "description": (
            "LIVE FEED — Abuse.ch Feodo Tracker: botnet C2 IPs (refreshed "
            "from abuse.ch)."
        ),
        "update_interval_h": 6,
        "parser": "iplist",
        "threat_type": "botnet-c2",
    },
    "threatfox": {
        "feed_name": "AbuseCH-ThreatFox-LIVE",
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "description": (
            "LIVE FEED — Abuse.ch ThreatFox: recent IOCs (IPs, domains, URLs, "
            "hashes) with malware family labels (refreshed from abuse.ch)."
        ),
        "update_interval_h": 6,
        "parser": "threatfox",
        "threat_type": "threatfox-ioc",
    },
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def fetch_abusech_feed(feed_key: str, timeout: int = 20) -> dict[str, Any]:
    """
    Download one Abuse.ch blocklist and normalize it to IOC tuples.

    Returns {"ok": True, "indicators": [(value, type, desc), ...]} or
    {"ok": False, "error": "...", "indicators": []}. Never raises —
    no network, DNS failure, HTTP errors and timeouts all land in "error".
    """
    spec = ABUSECH_FEEDS.get(feed_key)
    if spec is None:
        return {"ok": False, "error": f"unknown Abuse.ch feed {feed_key!r}",
                "indicators": []}
    req = urllib.request.Request(
        spec["url"],
        headers={"User-Agent": "Pak-CyberPulse/7.0 (FYP research; contact: admin)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 — offline/timeout/HTTP all land here
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                "indicators": []}
    indicators: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    from urllib.parse import urlsplit

    def _host_type(host: str) -> Optional[str]:
        if _IP_RE.match(host):
            return "ip"
        if "." in host:
            return "domain"
        return None

    if spec["parser"] == "threatfox":
        # CSV: "first_seen","id","ioc","ioc_type","threat_type","malware",...
        reader = csv.reader(text.splitlines())
        for row in reader:
            if len(row) < 6 or row[0].strip().startswith("#"):
                continue
            raw_ioc = row[2].strip().strip('"')
            raw_type = row[3].strip().strip('"').lower()
            threat = row[4].strip().strip('"') or spec["threat_type"]
            malware = row[5].strip().strip('"')
            val: Optional[str] = None
            typ: Optional[str] = None
            if raw_type == "ip:port":
                cand = raw_ioc.split(":")[0].strip()
                if _IP_RE.match(cand):
                    val, typ = cand, "ip"
            elif raw_type == "domain":
                if _host_type(raw_ioc) == "domain":
                    val, typ = raw_ioc.lower(), "domain"
            elif raw_type == "url":
                try:
                    host = (urlsplit(raw_ioc).hostname or "").strip().lower()
                except Exception:
                    host = ""
                t = _host_type(host)
                if t:
                    val, typ = host, t
            elif raw_type == "sha256_hash" and len(raw_ioc) == 64:
                val, typ = raw_ioc.lower(), "sha256"
            if not val or not typ or val in seen:
                continue
            seen.add(val)
            label = f"{spec['feed_name']}: {threat}" + (f" ({malware})" if malware else "")
            indicators.append((val, typ, label[:400]))
    else:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if spec["parser"] == "iplist":
                # Feodo: first token is the IP (lines may carry extra cols).
                val = line.split()[0].strip().rstrip(",")
                if not _IP_RE.match(val):
                    continue
                typ = "ip"
            else:  # urlhaus: extract the host from each malware URL
                try:
                    host = (urlsplit(line).hostname or "").strip().lower()
                except Exception:
                    continue
                typ = _host_type(host)
                if not typ:
                    continue
                val = host
            if val in seen:
                continue
            seen.add(val)
            indicators.append(
                (val, typ, f"{spec['feed_name']}: {spec['threat_type']}")
            )
    if not indicators:
        return {"ok": False, "error": "feed downloaded but yielded 0 IOCs",
                "indicators": []}
    return {"ok": True, "indicators": indicators}


# AlienVault OTX (free tier) — optional live enrichment. Any failure
# (no internet, no/invalid key) returns a graceful error dict; the app
# never depends on it.
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
_OTX_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "FileHash-SHA256": "sha256",
    "FileHash-SHA1": None,   # not tracked by our schema — skipped honestly
    "FileHash-MD5": None,
    "URL": None,
    "email": None,
    "CIDR": None,
    "other": None,
}

# Documentation / reserved ranges only — never real infrastructure.
TESTNET_V4 = ["203.0.113", "198.51.100", "192.0.2"]
EXAMPLE_DOMAINS = [
    "evil-example.com",
    "phish-sim-example.com",
    "c2-drop-example.net",
    "malware-stage-example.org",
    "bulletproof-sim-example.net",
    "exploit-kit-example.com",
    "credential-harvest-example.org",
    "fake-invoice-example.com",
    "update-trojan-example.net",
    "darkforum-sim-example.onion",
    "ransom-note-example.com",
    "rat-panel-example.org",
]

FEED_DEFS: list[dict[str, Any]] = [
    {
        "feed_name": "PakCERT-Advisory-Sim",
        "description": (
            "SIMULATED National CERT Pakistan advisory feed — synthetic phishing "
            "and malware IOCs themed on public-sector targeting."
        ),
        "update_interval_h": 24,
        "source_url": "https://sim.pkcert.internal/feeds/advisories",
        "ioc_count": (15, 25),
        "ioc_mix": [("ip", 7), ("domain", 8), ("sha256", 6)],
        "threat_types": ["phishing", "malware-dropper", "c2", "credential-harvesting"],
        "desc_tpl": "PakCERT advisory SIM-{n}: {t} infrastructure observed in simulated advisories.",
    },
    {
        "feed_name": "AbuseCH-Sim",
        "description": (
            "SIMULATED Abuse.ch-style blocklist feed — synthetic C2 IPs, "
            "malware hashes and bulletproof-hosting domains."
        ),
        "update_interval_h": 6,
        "source_url": "https://sim.abusech.internal/feeds",
        "ioc_count": (15, 25),
        "ioc_mix": [("ip", 10), ("domain", 6), ("sha256", 7)],
        "threat_types": ["c2", "malware", "botnet", "ransomware"],
        "desc_tpl": "AbuseCH SIM-{n}: {t} infrastructure reported by simulated community reporters.",
    },
    {
        "feed_name": "OTX-Community-Sim",
        "description": (
            "SIMULATED OTX-style community pulse feed — synthetic scanning, "
            "exploit-kit and opportunistic-attack infrastructure."
        ),
        "update_interval_h": 12,
        "source_url": "https://sim.otx.internal/pulses",
        "ioc_count": (15, 25),
        "ioc_mix": [("ip", 8), ("domain", 9), ("sha256", 5)],
        "threat_types": ["scanner", "exploit-kit", "phishing", "bruteforcer"],
        "desc_tpl": "OTX SIM-{n}: {t} infrastructure shared in a simulated community pulse.",
    },
]


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _parse_utc(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)


def _fake_sha256(seed: str) -> str:
    """Deterministic fake hash — looks like a hash, is not a real sample."""
    return hashlib.sha256(("pak-cyberpulse-ti-sim:" + seed).encode()).hexdigest()


def fetch_otx_pulses(api_key: str, limit: int = 20) -> dict[str, Any]:
    """
    Fetch subscribed AlienVault OTX pulses (free tier, no cost).

    Returns {"ok": True, "pulses": n, "indicators": [(value, type, desc), ...]}
    on success, or {"ok": False, "error": "...", "indicators": []} on ANY
    failure (no network, bad key, bad JSON). Never raises — the caller
    decides how to surface the failure.
    """
    if not (api_key or "").strip():
        return {"ok": False, "error": "no API key provided", "indicators": []}
    url = f"{OTX_PULSES_URL}?limit={max(1, min(int(limit), 50))}"
    req = urllib.request.Request(
        url,
        headers={
            "X-OTX-API-KEY": api_key.strip(),
            "User-Agent": "Pak-CyberPulse/4.0 (FYP research)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001 — offline/bad key/timeout all land here
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                "indicators": []}
    indicators: list[tuple[str, str, str]] = []
    pulses = 0
    try:
        results = payload.get("results", []) if isinstance(payload, dict) else []
        for pulse in results:
            pulses += 1
            pname = str(pulse.get("name", "otx-pulse"))[:120]
            for ind in pulse.get("indicators", []) or []:
                otype = str(ind.get("type", ""))
                mapped = _OTX_TYPE_MAP.get(otype)
                val = str(ind.get("indicator", "")).strip()
                if mapped and val:
                    indicators.append((val, mapped, f"OTX pulse: {pname}"))
    except Exception as exc:  # noqa: BLE001 — malformed payload shape
        return {"ok": False, "error": f"unparseable OTX response: {exc}",
                "indicators": []}
    return {"ok": True, "pulses": pulses, "indicators": indicators}


class TIStore:
    """SQLite-backed simulated threat-intel feed store."""

    def __init__(self, db: Optional[DatabaseManager] = None) -> None:
        self.db: DatabaseManager = db if db is not None else get_db()
        self._lock = threading.RLock()
        self.ensure_schema()

    # ------------------------------------------------------------------
    # Schema / seeding
    # ------------------------------------------------------------------
    def ensure_schema(self) -> None:
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS ti_feeds (
                        feed_name         TEXT PRIMARY KEY,
                        description       TEXT NOT NULL,
                        last_updated      TEXT NOT NULL,
                        update_interval_h INTEGER NOT NULL,
                        source_url        TEXT NOT NULL DEFAULT ''
                    );

                    CREATE TABLE IF NOT EXISTS ti_iocs (
                        ioc          TEXT PRIMARY KEY,
                        ioc_type     TEXT NOT NULL,
                        feed_name    TEXT NOT NULL,
                        first_seen   TEXT NOT NULL,
                        last_seen    TEXT NOT NULL,
                        confidence   INTEGER NOT NULL,
                        threat_type  TEXT NOT NULL DEFAULT '',
                        description  TEXT NOT NULL DEFAULT '',
                        FOREIGN KEY (feed_name) REFERENCES ti_feeds (feed_name)
                    );
                    """
                )
                conn.commit()
                # v7 migration: feed_kind distinguishes LIVE feeds from
                # SIMULATED ones in the UI. Safe to re-run (ignored if present).
                try:
                    conn.execute(
                        "ALTER TABLE ti_feeds ADD COLUMN feed_kind "
                        "TEXT NOT NULL DEFAULT 'simulated'"
                    )
                except sqlite3.Error:
                    pass
                conn.execute(
                    "UPDATE ti_feeds SET feed_kind = 'live' "
                    "WHERE feed_name LIKE '%-LIVE'"
                )
                conn.commit()

    def _build_seed_iocs(
        self, feed: dict[str, Any], rng: random.Random, used: set[str]
    ) -> list[tuple]:
        """Fabricate 15-25 deterministic IOCs for one feed (simulated only).

        ``used`` is shared across feeds inside one seed run so the same
        value can never be generated twice (INSERT OR IGNORE would silently
        drop it and break the per-feed 15-25 guarantee). Because feeds are
        always processed in FEED_DEFS order with deterministic per-feed
        RNGs, reseeds regenerate the identical sequence.
        """
        now = datetime.now(timezone.utc)
        iocs: list[tuple] = []
        target = rng.randint(*feed["ioc_count"])
        dom_pool = EXAMPLE_DOMAINS[:]
        rng.shuffle(dom_pool)
        dom_i = 0
        idx = 0
        while len(iocs) < target:
            for ioc_type, share in feed["ioc_mix"]:
                if len(iocs) >= target:
                    break
                if ioc_type == "ip":
                    val = f"{rng.choice(TESTNET_V4)}.{rng.randint(2, 250)}"
                elif ioc_type == "domain":
                    if dom_i >= len(dom_pool):
                        val = f"sim-{feed['feed_name'].lower()}-{idx}.example.com"
                    else:
                        val = dom_pool[dom_i]
                        dom_i += 1
                else:  # sha256
                    val = _fake_sha256(f"{feed['feed_name']}:{idx}")
                idx += 1
                if val in used:
                    continue
                used.add(val)
                threat_type = rng.choice(feed["threat_types"])
                first_seen = now - timedelta(days=rng.randint(1, 30), hours=rng.randint(0, 23))
                last_seen = first_seen + timedelta(hours=rng.randint(1, 72))
                if last_seen > now:
                    last_seen = now - timedelta(hours=rng.randint(0, 12))
                iocs.append(
                    (
                        val,
                        ioc_type,
                        feed["feed_name"],
                        _utc(first_seen),
                        _utc(last_seen),
                        rng.randint(55, 98),
                        threat_type,
                        feed["desc_tpl"].format(n=1000 + idx, t=threat_type),
                    )
                )
        return iocs

    def seed_feeds(self) -> dict[str, int]:
        """
        Idempotent seed (migration pattern): inserts only feeds/IOCs that are
        missing. Returns {feed_name: iocs_added}.
        """
        rng = random.Random(20260922)  # deterministic seed data
        now = datetime.now(timezone.utc)
        added: dict[str, int] = {}
        # Shared across feeds: rebuilt identically on every seed run, so
        # reseeds regenerate the exact same IOC sequence (idempotent).
        used: set[str] = set()
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                for feed in FEED_DEFS:
                    # Independent per-feed RNG: IOC output must not depend on
                    # draws made for feed metadata, so reseeds are stable.
                    feed_rng = random.Random(f"pak-cyberpulse-ti:{feed['feed_name']}")
                    row = conn.execute(
                        "SELECT feed_name FROM ti_feeds WHERE feed_name = ?",
                        (feed["feed_name"],),
                    ).fetchone()
                    if row is None:
                        conn.execute(
                            """
                            INSERT INTO ti_feeds (
                                feed_name, description, last_updated,
                                update_interval_h, source_url, feed_kind
                            ) VALUES (?, ?, ?, ?, ?, 'simulated')
                            """,
                            (
                                feed["feed_name"],
                                feed["description"],
                                _utc(now - timedelta(hours=rng.randint(1, 30))),
                                feed["update_interval_h"],
                                feed["source_url"],
                            ),
                        )
                    n = 0
                    for ioc in self._build_seed_iocs(feed, feed_rng, used):
                        cur = conn.execute(
                            """
                            INSERT OR IGNORE INTO ti_iocs (
                                ioc, ioc_type, feed_name, first_seen, last_seen,
                                confidence, threat_type, description
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            ioc,
                        )
                        n += cur.rowcount
                    added[feed["feed_name"]] = n
                conn.commit()
        return added

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def list_feeds(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.db._rows("SELECT * FROM ti_feeds ORDER BY feed_name")
        for r in rows:
            r["ioc_count"] = self.count_iocs(r["feed_name"])
            r["stale"] = self.feed_is_stale(r["feed_name"])
        return rows

    def count_iocs(self, feed_name: Optional[str] = None) -> int:
        with self._lock:
            with self.db.connect() as conn:
                if feed_name:
                    row = conn.execute(
                        "SELECT COUNT(*) AS n FROM ti_iocs WHERE feed_name = ?",
                        (feed_name,),
                    ).fetchone()
                else:
                    row = conn.execute("SELECT COUNT(*) AS n FROM ti_iocs").fetchone()
                return int(row["n"])

    def list_iocs(self, feed_name: Optional[str] = None, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            if feed_name:
                return self.db._rows(
                    "SELECT * FROM ti_iocs WHERE feed_name = ? ORDER BY confidence DESC LIMIT ?",
                    (feed_name, limit),
                )
            return self.db._rows(
                "SELECT * FROM ti_iocs ORDER BY confidence DESC LIMIT ?", (limit,)
            )

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize(value: str) -> str:
        return value.strip().lower()

    def enrich(self, value: str) -> dict[str, Any]:
        """
        Look up an indicator by exact match (case-insensitive for domains).
        Returns {"matches": [...], "stale_feeds": [...]}.
        """
        norm = self._normalize(value)
        with self._lock:
            rows = self.db._rows(
                """
                SELECT ioc, ioc_type, feed_name, first_seen, last_seen,
                       confidence, threat_type, description
                FROM ti_iocs
                WHERE ioc = ? OR LOWER(ioc) = ?
                ORDER BY confidence DESC
                """,
                (value.strip(), norm),
            )
        return {"matches": rows, "stale_feeds": self.list_stale_feeds()}

    # ------------------------------------------------------------------
    # CSV bulk import (v4)
    # ------------------------------------------------------------------
    def _ensure_import_feed(
        self, conn, feed_name: str, description: str, feed_kind: str = "simulated",
        source_url: str = "", update_interval_h: int = 24,
    ) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO ti_feeds (
                feed_name, description, last_updated, update_interval_h,
                source_url, feed_kind
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (feed_name, description, utc_now(), update_interval_h, source_url,
             feed_kind),
        )

    def import_indicators_csv(self, path: str | Path) -> dict[str, Any]:
        """
        Bulk-import indicators from a CSV file.

        Expected header (case-insensitive): ioc, ioc_type[, confidence,
        threat_type, description]. ioc_type must be one of ip/domain/sha256.
        Duplicates against the existing store are skipped (INSERT OR IGNORE).
        Returns {"feed": ..., "added": n, "skipped": m, "invalid": k}.
        """
        path = Path(path)
        added = skipped = invalid = 0
        feed_name = "CSV-Import"
        now_s = utc_now()
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                self._ensure_import_feed(
                    conn, feed_name,
                    "User-imported indicators from a CSV file (v4 bulk import).",
                )
                with open(path, "r", encoding="utf-8-sig", newline="") as fh:
                    reader = csv.DictReader(fh)
                    if not reader.fieldnames:
                        raise ValueError("CSV has no header row")
                    cols = {c.strip().lower(): c for c in reader.fieldnames if c}
                    if "ioc" not in cols or "ioc_type" not in cols:
                        raise ValueError(
                            "CSV must have 'ioc' and 'ioc_type' columns "
                            f"(saw: {sorted(cols)})"
                        )
                    for row in reader:
                        val = (row.get(cols["ioc"]) or "").strip()
                        typ = (row.get(cols["ioc_type"]) or "").strip().lower()
                        if not val or typ not in IOC_TYPES:
                            invalid += 1
                            continue
                        try:
                            conf = int((row.get(cols.get("confidence", "")) or "60").strip() or "60")
                        except (ValueError, AttributeError):
                            conf = 60
                        conf = max(1, min(100, conf))
                        threat = (row.get(cols.get("threat_type", "")) or "").strip()[:80]
                        desc = (row.get(cols.get("description", "")) or "").strip()[:400]
                        cur = conn.execute(
                            """
                            INSERT OR IGNORE INTO ti_iocs (
                                ioc, ioc_type, feed_name, first_seen, last_seen,
                                confidence, threat_type, description
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (val, typ, feed_name, now_s, now_s, conf, threat, desc),
                        )
                        if cur.rowcount:
                            added += 1
                        else:
                            skipped += 1
                conn.commit()
        return {"feed": feed_name, "added": added, "skipped": skipped,
                "invalid": invalid}

    # ------------------------------------------------------------------
    # AlienVault OTX live fetch (v4, optional — graceful offline fallback)
    # ------------------------------------------------------------------
    def import_otx(self, api_key: str, limit: int = 20) -> dict[str, Any]:
        """
        Fetch the subscribed OTX pulses (free tier) and import their
        indicators as the "OTX-Live" feed. Never raises on network trouble:
        returns {"ok": False, "error": ...} and leaves the store untouched.
        """
        fetched = fetch_otx_pulses(api_key, limit=limit)
        if not fetched["ok"]:
            return {"ok": False, "error": fetched["error"], "added": 0}
        feed_name = "OTX-Live"
        now_s = utc_now()
        added = skipped = 0
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                self._ensure_import_feed(
                    conn, feed_name,
                    "LIVE AlienVault OTX subscribed pulses (free tier, v4).",
                    feed_kind="live",
                    source_url=OTX_PULSES_URL,
                    update_interval_h=12,
                )
                conn.execute(
                    "UPDATE ti_feeds SET last_updated = ? WHERE feed_name = ?",
                    (now_s, feed_name),
                )
                for ind, typ, desc in fetched["indicators"]:
                    cur = conn.execute(
                        """
                        INSERT OR IGNORE INTO ti_iocs (
                            ioc, ioc_type, feed_name, first_seen, last_seen,
                            confidence, threat_type, description
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (ind, typ, feed_name, now_s, now_s, 70,
                         "otx-pulse", desc[:400]),
                    )
                    if cur.rowcount:
                        added += 1
                    else:
                        skipped += 1
                conn.commit()
        return {"ok": True, "feed": feed_name, "added": added,
                "skipped": skipped, "pulses": fetched["pulses"]}

    # ------------------------------------------------------------------
    # Abuse.ch live feeds (v7 — real, free, no key)
    # ------------------------------------------------------------------
    def import_abusech(self, feed_key: str, timeout: int = 20) -> dict[str, Any]:
        """
        Fetch one Abuse.ch blocklist and import it as a LIVE feed.
        Never raises on network trouble: returns {"ok": False, "error": ...}
        and leaves the store untouched.
        """
        spec = ABUSECH_FEEDS.get(feed_key)
        if spec is None:
            return {"ok": False, "error": f"unknown feed {feed_key!r}",
                    "added": 0}
        fetched = fetch_abusech_feed(feed_key, timeout=timeout)
        if not fetched["ok"]:
            return {"ok": False, "error": fetched["error"], "added": 0}
        feed_name = spec["feed_name"]
        now_s = utc_now()
        added = skipped = 0
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                self._ensure_import_feed(
                    conn, feed_name, spec["description"],
                    feed_kind="live", source_url=spec["url"],
                    update_interval_h=spec["update_interval_h"],
                )
                conn.execute(
                    "UPDATE ti_feeds SET last_updated = ?, feed_kind = 'live' "
                    "WHERE feed_name = ?",
                    (now_s, feed_name),
                )
                for ind, typ, desc in fetched["indicators"]:
                    cur = conn.execute(
                        """
                        INSERT OR IGNORE INTO ti_iocs (
                            ioc, ioc_type, feed_name, first_seen, last_seen,
                            confidence, threat_type, description
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (ind, typ, feed_name, now_s, now_s, 85,
                         spec["threat_type"], desc[:400]),
                    )
                    if cur.rowcount:
                        added += 1
                    else:
                        skipped += 1
                conn.commit()
        return {"ok": True, "feed": feed_name, "added": added,
                "skipped": skipped, "total": len(fetched["indicators"])}

    # ------------------------------------------------------------------
    # Staleness / refresh
    # ------------------------------------------------------------------
    def feed_is_stale(self, feed_name: str) -> bool:
        with self._lock:
            rows = self.db._rows(
                "SELECT last_updated, update_interval_h FROM ti_feeds WHERE feed_name = ?",
                (feed_name,),
            )
        if not rows:
            return True
        last = _parse_utc(rows[0]["last_updated"])
        interval = timedelta(hours=int(rows[0]["update_interval_h"]))
        return datetime.now(timezone.utc) > last + interval

    def list_stale_feeds(self) -> list[str]:
        with self._lock:
            rows = self.db._rows("SELECT feed_name FROM ti_feeds")
        return [r["feed_name"] for r in rows if self.feed_is_stale(r["feed_name"])]

    def refresh_feed(self, feed_name: str) -> dict[str, Any]:
        """Refresh one feed, honestly per its kind.

        LIVE feeds (Abuse.ch): performs a REAL network fetch via
        import_abusech() — never synthetic rotation. Network failure
        returns {"ok": False, "error": ...} and leaves data untouched.
        SIMULATED feeds: stamps last_updated and rotates 2-3 IOCs
        (real mutation of local synthetic data; no network contacted).
        """
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                row = conn.execute(
                    "SELECT feed_kind FROM ti_feeds WHERE feed_name = ?",
                    (feed_name,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Unknown feed {feed_name!r}")
                kind = row["feed_kind"] if "feed_kind" in row.keys() else "simulated"
        if kind == "live":
            key_by_feed = {s["feed_name"]: k for k, s in ABUSECH_FEEDS.items()}
            akey = key_by_feed.get(feed_name)
            if akey:
                res = self.import_abusech(akey)
                return {"feed_name": feed_name, "live": True, **res}
            return {"feed_name": feed_name, "live": True, "ok": False,
                    "error": "live feed has no Abuse.ch fetcher — left untouched"}
        with self._lock, self.db.lock:
            with self.db.connect() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM ti_feeds WHERE feed_name = ?", (feed_name,)
                ).fetchone()
                if not exists:
                    raise ValueError(f"Unknown feed {feed_name!r}")
                now_s = utc_now()
                conn.execute(
                    "UPDATE ti_feeds SET last_updated = ? WHERE feed_name = ?",
                    (now_s, feed_name),
                )
                iocs = conn.execute(
                    "SELECT ioc, confidence FROM ti_iocs WHERE feed_name = ?",
                    (feed_name,),
                ).fetchall()
                rotated: list[str] = []
                if iocs:
                    for row in random.sample(list(iocs), k=min(len(iocs), 3)):
                        delta = random.randint(-8, 8)
                        new_conf = max(1, min(100, int(row["confidence"]) + delta))
                        conn.execute(
                            "UPDATE ti_iocs SET last_seen = ?, confidence = ? WHERE ioc = ?",
                            (now_s, new_conf, row["ioc"]),
                        )
                        rotated.append(row["ioc"])
                conn.commit()
        return {"feed_name": feed_name, "last_updated": now_s, "rotated_iocs": rotated}


# ---------------------------------------------------------------------------
# Scheduled live-feed refresh (v7)
# ---------------------------------------------------------------------------
_TI_REFRESH_THREAD: Optional[threading.Thread] = None
_TI_REFRESH_STOP = threading.Event()
_ABUSECH_REFRESH_S = 6 * 3600
_OTX_REFRESH_S = 12 * 3600


def _ti_refresh_loop() -> None:
    """Background loop: refresh live feeds on a schedule. Never raises."""
    from modules.app_config import get_setting, get_otx_api_key, log_to_desktop

    def _last_updated(feed_names: list[str]) -> float:
        try:
            ti = TIStore()
            rows = ti.db._rows(
                "SELECT feed_name, last_updated FROM ti_feeds "
                "WHERE feed_name IN (%s)" % ",".join("?" * len(feed_names)),
                feed_names,
            )
            best = 0.0
            for r in rows:
                try:
                    ts = _parse_utc(r["last_updated"]).timestamp()
                    best = max(best, ts)
                except Exception:
                    pass
            return best
        except Exception:
            return 0.0

    live_names = [s["feed_name"] for s in ABUSECH_FEEDS.values()]
    last_abusech = _last_updated(live_names)
    last_otx = _last_updated(["OTX-Live"])
    while not _TI_REFRESH_STOP.is_set():
        try:
            now = time.time()
            ti = TIStore()  # uses the process-global DB
            if (get_setting("abusech_auto_refresh", "1") == "1"
                    and now - last_abusech >= _ABUSECH_REFRESH_S):
                last_abusech = now
                for key in ABUSECH_FEEDS:
                    try:
                        res = ti.import_abusech(key)
                        if res["ok"]:
                            log_to_desktop(
                                f"ti-refresh: {res['feed']} ok "
                                f"(+{res['added']} new, {res['skipped']} dup)"
                            )
                        else:
                            log_to_desktop(
                                f"ti-refresh: {key} skipped: {res['error']}"
                            )
                    except Exception as exc:  # noqa: BLE001
                        log_to_desktop(f"ti-refresh: {key} error: {exc}")
            otx_key = get_otx_api_key()
            if otx_key and now - last_otx >= _OTX_REFRESH_S:
                last_otx = now
                try:
                    res = ti.import_otx(otx_key)
                    log_to_desktop(
                        f"ti-refresh: OTX {'ok (+%d new)' % res['added'] if res['ok'] else 'skipped: ' + res['error']}"
                    )
                except Exception as exc:  # noqa: BLE001
                    log_to_desktop(f"ti-refresh: OTX error: {exc}")
        except Exception as exc:  # noqa: BLE001 — the loop itself never dies
            try:
                from modules.app_config import log_to_desktop as _log
                _log(f"ti-refresh: loop error: {exc}")
            except Exception:
                pass
        _TI_REFRESH_STOP.wait(300)  # re-check every 5 min


def ensure_ti_refresh_running() -> bool:
    """Start the scheduled live-feed refresh thread (idempotent). Never raises."""
    global _TI_REFRESH_THREAD
    try:
        if _TI_REFRESH_THREAD is not None and _TI_REFRESH_THREAD.is_alive():
            return True
        _TI_REFRESH_STOP.clear()
        _TI_REFRESH_THREAD = threading.Thread(
            target=_ti_refresh_loop, name="ti-refresh", daemon=True
        )
        _TI_REFRESH_THREAD.start()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Streamlit panel
# ---------------------------------------------------------------------------
def render_ti_panel(ti: Optional[TIStore] = None) -> None:
    """Threat-intel panel: feed health, IOC browser, enrichment search, refresh."""
    ti = ti or TIStore()
    ti.seed_feeds()

    st.markdown(
        '<div class="cp-banner cp-action">'
        "<b>Threat Intelligence.</b> Abuse.ch blocklists (URLhaus, Feodo Tracker, "
        "ThreatFox) are fetched LIVE over HTTPS and badged <b>LIVE FEED</b>; "
        "all other feeds are SIMULATED (RFC 5737 TEST-NET ranges, badged "
        "<b>SIMULATED</b>). Note: Abuse.ch <b>SSLBL was deprecated upstream on "
        "2025-01-03</b> — ThreatFox is used in its place."
        "</div>",
        unsafe_allow_html=True,
    )

    feeds = ti.list_feeds()
    stale = ti.list_stale_feeds()
    n_live = sum(1 for f in feeds if f.get("feed_kind") == "live")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total IOCs", ti.count_iocs())
    c2.metric("Feeds", len(feeds))
    c3.metric("LIVE feeds", n_live)
    c4.metric("Stale feeds", len(stale))

    st.subheader("Feed health")
    abusech_key_by_feed = {s["feed_name"]: k for k, s in ABUSECH_FEEDS.items()}
    for f in feeds:
        import html as _html
        tone = "🔴" if f["stale"] else "🟢"
        kind = f.get("feed_kind") or "simulated"
        badge = ('<span class="cp-live-dot"></span> LIVE FEED'
                 if kind == "live"
                 else "🟡 SIMULATED")
        left, right = st.columns([4, 1])
        with left:
            st.markdown(
                f"<b>{badge} · {_html.escape(f['feed_name'])}</b> {tone} "
                f"{'STALE' if f['stale'] else 'fresh'}<br>"
                f"<span style='opacity:.75'>{_html.escape(f['description'])}<br>"
                f"{f['ioc_count']} IOCs · last updated {_html.escape(f['last_updated'])} "
                f"(interval {f['update_interval_h']}h)</span>",
                unsafe_allow_html=True,
            )
        with right:
            akey = abusech_key_by_feed.get(f["feed_name"])
            if akey:
                if st.button("↻ Live fetch", key=f"ti-live-{f['feed_name']}"):
                    with st.spinner("Fetching from abuse.ch…"):
                        res = ti.import_abusech(akey)
                    if res["ok"]:
                        st.success(
                            f"LIVE fetch OK — {res['added']} new IOCs "
                            f"({res['skipped']} duplicates)."
                        )
                        st.rerun()
                    else:
                        st.warning(f"Live fetch failed gracefully: {res['error']}")
            else:
                if st.button("Refresh", key=f"ti-refresh-{f['feed_name']}"):
                    res = ti.refresh_feed(f["feed_name"])
                    st.success(
                        f"Simulated refresh complete — {len(res['rotated_iocs'])} IOCs rotated."
                    )
                    st.rerun()

    st.subheader("Import indicators (v4)")
    st.markdown("**Abuse.ch live feeds (free, no key)**")
    if st.button("↻ Fetch all Abuse.ch feeds now", key="ti-abusech-all"):
        with st.spinner("Fetching URLhaus + Feodo Tracker + ThreatFox from abuse.ch…"):
            results = {k: ti.import_abusech(k) for k in ABUSECH_FEEDS}
        ok = [v for v in results.values() if v["ok"]]
        bad = [f"{k}: {v['error']}" for k, v in results.items() if not v["ok"]]
        if ok:
            st.success(
                "LIVE: " + "; ".join(
                    f"{v['feed']}: +{v['added']} new" for v in ok
                )
            )
        if bad:
            st.warning("Gracefully skipped: " + " | ".join(bad))
        st.rerun()

    imp_csv, imp_otx = st.columns(2)
    with imp_csv:
        st.markdown("**Bulk CSV import**")
        st.caption("Header: ioc, ioc_type (ip/domain/sha256), confidence, threat_type, description")
        up = st.file_uploader("Indicators CSV", type=["csv"], key="ti-csv-up")
        if up is not None and st.button("Import CSV", key="ti-csv-go"):
            tmp = Path(f"/tmp/cp_ti_{int(time.time())}.csv")
            tmp.write_bytes(up.getvalue())
            try:
                res = ti.import_indicators_csv(tmp)
                st.success(
                    f"Imported {res['added']} new indicators "
                    f"({res['skipped']} duplicates skipped, "
                    f"{res['invalid']} invalid rows)."
                )
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
            finally:
                tmp.unlink(missing_ok=True)
    with imp_otx:
        from modules.app_config import get_otx_api_key, otx_key_source
        st.markdown("**AlienVault OTX live fetch (free tier)**")
        st.caption("Needs an OTX API key (free at otx.alienvault.com). Offline = graceful skip.")
        _src = otx_key_source()
        if _src != "none":
            st.caption(f"✓ Key configured via {_src} (see Settings to change).")
            otx_key = get_otx_api_key()
        else:
            otx_key = st.text_input("OTX API key", type="password", key="ti-otx-key")
            st.caption("…or save it permanently in Settings → Threat Intel.")
        otx_limit = st.number_input("Max pulses", 1, 50, 10, key="ti-otx-limit")
        if st.button("Fetch from OTX", key="ti-otx-go"):
            res = ti.import_otx(otx_key, limit=int(otx_limit))
            if res["ok"]:
                st.success(
                    f"OTX: {res['pulses']} pulses → {res['added']} new indicators "
                    f"({res['skipped']} duplicates skipped)."
                )
                st.rerun()
            else:
                st.warning(f"OTX fetch skipped gracefully: {res['error']}")

    st.subheader("Enrich an indicator")
    query = st.text_input(
        "IP, domain or sha256",
        placeholder="e.g. 203.0.113.45 or evil-example.com",
        key="ti-enrich-q",
    )
    if st.button("Enrich", key="ti-enrich-go") and query:
        result = ti.enrich(query)
        matches = result["matches"]
        if matches:
            st.markdown(
                f'<div class="cp-banner cp-critical">'
                f"<b>{len(matches)} match(es)</b> in the simulated feeds — "
                "treat the indicator as hostile in this demo context."
                "</div>",
                unsafe_allow_html=True,
            )
            st.dataframe(
                [
                    {
                        "IOC": m["ioc"],
                        "Type": m["ioc_type"],
                        "Feed": m["feed_name"],
                        "Confidence": m["confidence"],
                        "Threat": m["threat_type"],
                        "Last seen": m["last_seen"],
                    }
                    for m in matches
                ],
                use_container_width=True,
            )
        else:
            st.markdown(
                '<div class="cp-banner cp-hardened">No match in the simulated '
                "feeds — indicator is unknown, not clean.</div>",
                unsafe_allow_html=True,
            )
        if result["stale_feeds"]:
            st.warning(
                "Staleness warning — these feeds are stale, matches may be "
                f"outdated: {', '.join(result['stale_feeds'])}"
            )

    st.subheader("IOC browser")
    feed_filter = st.selectbox(
        "Feed", ["All"] + [f["feed_name"] for f in feeds], key="ti-feed-filter"
    )
    rows = ti.list_iocs(None if feed_filter == "All" else feed_filter, limit=200)
    st.dataframe(
        [
            {
                "IOC": r["ioc"],
                "Type": r["ioc_type"],
                "Feed": r["feed_name"],
                "Confidence": r["confidence"],
                "Threat": r["threat_type"],
                "First seen": r["first_seen"],
                "Last seen": r["last_seen"],
            }
            for r in rows
        ],
        use_container_width=True,
    )
