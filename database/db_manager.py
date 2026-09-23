"""
Pak-CyberPulse — thread-safe SQLite persistence.

Authoritative control catalogue is grounded in the thirteen PISF documents
published by National CERT (PKCERT / nCERT) under CERT Rules 2023:

  01 Essential Governance Controls
  02 Essential Asset and Risk Management Controls
  03 Essential Security Training Controls
  04 Essential System and Communication Protection Controls
  05 Essential Identity and Access Management Controls
  06 Essential Data Protection and Privacy Controls
  07 Essential Incident Response Controls
  08 Essential Physical Security Controls
  09 Essential Data Centre and Web Hosting Services Controls
  10 Essential Secure Software Development Life Cycle Controls
  11 Essential Supply Chain Management Controls
  12 Essential Audit Controls
  13 Essential CII Protection Controls

Each domain is seeded with at least two discrete sub-controls so the GRC
matrix demonstrates multi-control depth rather than a one-row-per-domain stub.
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


def _is_frozen() -> bool:
    """True when running inside a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False))


def _bundle_root() -> Path:
    """Read-only directory holding bundled assets (PyInstaller: sys._MEIPASS)."""
    if _is_frozen():
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


def _data_root() -> Path:
    """Writable per-user data directory.

    Frozen desktop builds must never write next to the executable: every
    writable path lives under ~/.pak-cyberpulse/. Non-frozen runs keep the
    historical in-tree layout so the dev/test behaviour is byte-identical.
    """
    if _is_frozen():
        return Path.home() / ".pak-cyberpulse"
    return Path(__file__).resolve().parent.parent


BUNDLE_ROOT = _bundle_root()
ROOT = _data_root()
DB_DIR = ROOT / "database"
DB_PATH = DB_DIR / "cyberpulse.db"
LOG_PATH = DB_DIR / "live_siem_stream.log"
ACL_PATH = ROOT / "mock_acl_rules.txt"
REPORTS_DIR = ROOT / "reports"


def ensure_user_data() -> Path:
    """Create the user data dir and seed bundled demo assets on first run.

    Only does work when frozen. Copies the bundled demo SIEM log and the
    mock ACL file into ~/.pak-cyberpulse/ when they are missing, so a fresh
    install starts with the same demo telemetry as the source tree.
    Idempotent and safe to call repeatedly.
    """
    if not _is_frozen():
        return ROOT
    DB_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    seeds = (
        (BUNDLE_ROOT / "database" / "live_siem_stream.log", LOG_PATH),
        (BUNDLE_ROOT / "mock_acl_rules.txt", ACL_PATH),
    )
    for src, dest in seeds:
        try:
            if not dest.exists() and src.exists():
                shutil.copy2(src, dest)
        except OSError:
            pass  # never crash startup over a seed copy
    return ROOT


# Run the seed eagerly at import so every consumer of these paths
# (soar_engine, siem_panel, log_ingest, ...) sees a ready directory.
ensure_user_data()

# Allowed status vocabulary — keep this closed set so UI banners stay honest.
STATUS_COMPLIANT = "Compliant"
STATUS_NON_COMPLIANT = "Non-Compliant"
STATUS_UNDER_ATTACK = "Under Attack"
ALLOWED_STATUS = {STATUS_COMPLIANT, STATUS_NON_COMPLIANT, STATUS_UNDER_ATTACK}

CLASS_CII = "Critical Information Infrastructure"
CLASS_STANDARD = "Standard"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Authoritative PISF catalogue (control_id, domain_id, domain_name,
# description, initial status, risk_weight)
# ---------------------------------------------------------------------------
PISF_CONTROLS: list[tuple[str, str, str, str, str, int]] = [
    # PISF-01 Governance
    (
        "PISF-01.1",
        "PISF-01",
        "Essential Governance Controls",
        "Executive-approved information security policy mapped to National Cyber Security Policy 2021 and CERT Rules 2023, with named nCERT liaison.",
        STATUS_COMPLIANT,
        8,
    ),
    (
        "PISF-01.2",
        "PISF-01",
        "Essential Governance Controls",
        "Documented roles, RACI, and board-level oversight for residual cyber risk across ministries, attached departments, and designated CII operators.",
        STATUS_COMPLIANT,
        7,
    ),
    (
        "PISF-01.3",
        "PISF-01",
        "Essential Governance Controls",
        "Periodic management review of PISF implementation status and exception register submitted to the departmental CISO.",
        STATUS_NON_COMPLIANT,
        5,
    ),
    # PISF-02 Asset & Risk
    (
        "PISF-02.1",
        "PISF-02",
        "Essential Asset and Risk Management Controls",
        "Living asset inventory with owner, IP, and CII/Standard classification for every in-scope information system.",
        STATUS_COMPLIANT,
        9,
    ),
    (
        "PISF-02.2",
        "PISF-02",
        "Essential Asset and Risk Management Controls",
        "Risk assessment methodology producing residual-risk ratings that drive control weighting in the PISF readiness index.",
        STATUS_COMPLIANT,
        8,
    ),
    # PISF-03 Training
    (
        "PISF-03.1",
        "PISF-03",
        "Essential Security Training Controls",
        "Role-based security awareness programme covering phishing, CII handling, and PKCERT reporting duties.",
        STATUS_NON_COMPLIANT,
        6,
    ),
    (
        "PISF-03.2",
        "PISF-03",
        "Essential Security Training Controls",
        "Recorded literacy assessment (five-item PISF quiz) with evidence retained in the GRC ledger.",
        STATUS_NON_COMPLIANT,
        6,
    ),
    # PISF-04 System & Communication Protection
    (
        "PISF-04.1",
        "PISF-04",
        "Essential System and Communication Protection Controls",
        "Boundary monitoring of the append-only SIEM stream with correlation of network and host telemetry.",
        STATUS_COMPLIANT,
        8,
    ),
    (
        "PISF-04.2",
        "PISF-04",
        "Essential System and Communication Protection Controls",
        "Detection of application-layer manipulation (SQLi / XSS signatures) on CII and standard hosting fronts.",
        STATUS_COMPLIANT,
        8,
    ),
    # PISF-05 IAM
    (
        "PISF-05.1",
        "PISF-05",
        "Essential Identity and Access Management Controls",
        "Unique identification of administrative and service accounts on CII nodes; shared-credential prohibition.",
        STATUS_COMPLIANT,
        9,
    ),
    (
        "PISF-05.2",
        "PISF-05",
        "Essential Identity and Access Management Controls",
        "Stateful brute-force detector: 10 failed authentications for one Source IP / User inside a 60-second sliding window.",
        STATUS_COMPLIANT,
        10,
    ),
    (
        "PISF-05.3",
        "PISF-05",
        "Essential Identity and Access Management Controls",
        "Behavioral anomaly detector (UEBA-lite): flags successful logins at unusual hours for the user and logins from never-before-seen source IPs, learned from per-user baselines.",
        STATUS_COMPLIANT,
        10,
    ),
    # PISF-06 Data Protection & Privacy
    (
        "PISF-06.1",
        "PISF-06",
        "Essential Data Protection and Privacy Controls",
        "Protection of personally identifiable information (labelled DEMO Pakistani CNIC vectors) using authenticated encryption.",
        STATUS_NON_COMPLIANT,
        9,
    ),
    (
        "PISF-06.2",
        "PISF-06",
        "Essential Data Protection and Privacy Controls",
        "Fernet key-management hygiene: ephemeral session keys, masked display, no production secrets in source or logs.",
        STATUS_NON_COMPLIANT,
        8,
    ),
    # PISF-07 Incident Response
    (
        "PISF-07.1",
        "PISF-07",
        "Essential Incident Response Controls",
        "Documented SOAR playbook for parallel containment of confirmed IAM / injection incidents.",
        STATUS_COMPLIANT,
        8,
    ),
    (
        "PISF-07.2",
        "PISF-07",
        "Essential Incident Response Controls",
        "Privilege-aware containment: native firewall block when elevated; application-layer ACL otherwise; honest labelling of the mode actually executed.",
        STATUS_COMPLIANT,
        9,
    ),
    # PISF-08 Physical Security
    (
        "PISF-08.1",
        "PISF-08",
        "Essential Physical Security Controls",
        "Data-centre physical access logging correlated against after-hours and failed-badge events.",
        STATUS_COMPLIANT,
        5,
    ),
    (
        "PISF-08.2",
        "PISF-08",
        "Essential Physical Security Controls",
        "Visitor escort and tailgating exception handling with evidence attached to the GRC ledger.",
        STATUS_COMPLIANT,
        4,
    ),
    # PISF-09 Data Centre & Hosting
    (
        "PISF-09.1",
        "PISF-09",
        "Essential Data Centre and Web Hosting Services Controls",
        "Segmentation, WAF/IDS coverage, and environment isolation for hosted public-sector services.",
        STATUS_COMPLIANT,
        7,
    ),
    (
        "PISF-09.2",
        "PISF-09",
        "Essential Data Centre and Web Hosting Services Controls",
        "SOC/SIEM operations for hosting platforms, including CII-priority escalation paths to PKCERT.",
        STATUS_COMPLIANT,
        7,
    ),
    # PISF-10 SSDLC
    (
        "PISF-10.1",
        "PISF-10",
        "Essential Secure Software Development Life Cycle Controls",
        "Secure-coding gate rejecting SQL injection and XSS patterns in application request telemetry.",
        STATUS_COMPLIANT,
        8,
    ),
    (
        "PISF-10.2",
        "PISF-10",
        "Essential Secure Software Development Life Cycle Controls",
        "Static token review that flags plaintext password, API-key, and secret assignments in source artefacts.",
        STATUS_NON_COMPLIANT,
        7,
    ),
    # PISF-11 Supply Chain
    (
        "PISF-11.1",
        "PISF-11",
        "Essential Supply Chain Management Controls",
        "Software composition analysis of package manifests against an explicit vulnerable-version baseline.",
        STATUS_NON_COMPLIANT,
        7,
    ),
    (
        "PISF-11.2",
        "PISF-11",
        "Essential Supply Chain Management Controls",
        "Block / exception workflow for third-party components that fail the internal CVE baseline.",
        STATUS_NON_COMPLIANT,
        6,
    ),
    # PISF-12 Audit
    (
        "PISF-12.1",
        "PISF-12",
        "Essential Audit Controls",
        "Cryptographic evidence ledger: SHA-256 over the canonical incident record, retained with the PKCERT PDF.",
        STATUS_COMPLIANT,
        8,
    ),
    (
        "PISF-12.2",
        "PISF-12",
        "Essential Audit Controls",
        "Structured PKCERT incident report (timestamp, source, target, classification, rule, action, privilege state, hash).",
        STATUS_COMPLIANT,
        8,
    ),
    # PISF-13 CII Protection
    (
        "PISF-13.1",
        "PISF-13",
        "Essential CII Protection Controls",
        "Identification and register of designated Critical Information Infrastructure nodes (NADRA, SBP, NTDC, PKCERT).",
        STATUS_COMPLIANT,
        10,
    ),
    (
        "PISF-13.2",
        "PISF-13",
        "Essential CII Protection Controls",
        "Heightened monitoring and automatic severity elevation when detection rules fire against CII-class assets.",
        STATUS_COMPLIANT,
        10,
    ),
]


ASSETS: list[tuple[str, str, str, int]] = [
    ("NADRA-IDC-ISB", "10.51.1.10", CLASS_CII, 95),
    ("SBP-RTGS-KHI", "10.52.2.8", CLASS_CII, 93),
    ("NTDC-SCADA-LHR", "10.53.3.4", CLASS_CII, 90),
    ("PKCERT-SOC-ISB", "10.54.4.12", CLASS_CII, 72),
    ("MOITT-PORTAL", "172.16.20.30", CLASS_STANDARD, 41),
]


class DatabaseManager:
    """Single-writer SQLite facade. All mutating methods take the module lock."""

    def __init__(self, path: Path = DB_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._initialized = False

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def initialize(self) -> None:
        """Idempotent schema + seed. Safe to call from the Streamlit boot path."""
        with self.lock:
            if self._initialized and self.path.exists():
                return
            with self.connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS pisf_compliance (
                        control_id        TEXT PRIMARY KEY,
                        domain_id         TEXT NOT NULL,
                        domain_name       TEXT NOT NULL,
                        control_description TEXT NOT NULL,
                        status            TEXT NOT NULL,
                        evidence_log      TEXT NOT NULL DEFAULT '',
                        last_assessment   TEXT NOT NULL,
                        risk_weight       INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS asset_inventory (
                        asset_id       INTEGER PRIMARY KEY AUTOINCREMENT,
                        hostname       TEXT NOT NULL,
                        ip_address     TEXT NOT NULL,
                        classification TEXT NOT NULL,
                        risk_score     INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS incident_ledger (
                        incident_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at         TEXT NOT NULL,
                        source_ip          TEXT NOT NULL,
                        target_host        TEXT NOT NULL,
                        classification     TEXT NOT NULL,
                        detection_rule     TEXT NOT NULL,
                        mitigating_action  TEXT NOT NULL,
                        privilege_state    TEXT NOT NULL,
                        raw_record         TEXT NOT NULL,
                        sha256             TEXT NOT NULL,
                        pdf_path           TEXT NOT NULL DEFAULT ''
                    );

                    CREATE TABLE IF NOT EXISTS monitored_websites (
                        site_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                        name       TEXT NOT NULL UNIQUE,
                        log_path   TEXT NOT NULL,
                        note       TEXT NOT NULL DEFAULT '',
                        enabled    INTEGER NOT NULL DEFAULT 1,
                        ingest_sources TEXT NOT NULL DEFAULT 'file',
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS website_blocks (
                        block_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                        site_id      INTEGER,
                        site_name    TEXT NOT NULL,
                        source_ip    TEXT NOT NULL,
                        reason       TEXT NOT NULL,
                        mode         TEXT NOT NULL,
                        detail       TEXT NOT NULL DEFAULT '',
                        blocked_at   TEXT NOT NULL,
                        unblocked    INTEGER NOT NULL DEFAULT 0,
                        unblocked_at TEXT NOT NULL DEFAULT ''
                    );

                    CREATE TABLE IF NOT EXISTS app_settings (
                        key        TEXT PRIMARY KEY,
                        value      TEXT NOT NULL DEFAULT '',
                        updated_at TEXT NOT NULL
                    );
                    """
                )
                existing = conn.execute("SELECT COUNT(*) AS n FROM pisf_compliance").fetchone()["n"]
                if existing == 0:
                    ts = utc_now()
                    conn.executemany(
                        """
                        INSERT INTO pisf_compliance (
                            control_id, domain_id, domain_name, control_description,
                            status, evidence_log, last_assessment, risk_weight
                        ) VALUES (?, ?, ?, ?, ?, '', ?, ?)
                        """,
                        [
                            (cid, did, dname, desc, status, ts, weight)
                            for cid, did, dname, desc, status, weight in PISF_CONTROLS
                        ],
                    )
                # Migration: insert any seed controls added after the DB was
                # first created (e.g. PISF-05.3). Idempotent by control_id.
                ts = utc_now()
                have = {
                    r["control_id"]
                    for r in conn.execute("SELECT control_id FROM pisf_compliance")
                }
                missing = [
                    (cid, did, dname, desc, status, ts, weight)
                    for cid, did, dname, desc, status, weight in PISF_CONTROLS
                    if cid not in have
                ]
                if missing:
                    conn.executemany(
                        """
                        INSERT INTO pisf_compliance (
                            control_id, domain_id, domain_name, control_description,
                            status, evidence_log, last_assessment, risk_weight
                        ) VALUES (?, ?, ?, ?, ?, '', ?, ?)
                        """,
                        missing,
                    )
                assets = conn.execute("SELECT COUNT(*) AS n FROM asset_inventory").fetchone()["n"]
                if assets == 0:
                    conn.executemany(
                        """
                        INSERT INTO asset_inventory (hostname, ip_address, classification, risk_score)
                        VALUES (?, ?, ?, ?)
                        """,
                        ASSETS,
                    )
                # v7 migration: per-site ingest-source metadata for the HTTP
                # endpoint (existing DBs created before the column existed).
                try:
                    conn.execute(
                        "ALTER TABLE monitored_websites ADD COLUMN ingest_sources"
                        " TEXT NOT NULL DEFAULT 'file'"
                    )
                except Exception:
                    pass
                conn.commit()
            self._initialized = True

    def _rows(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self.lock:
            with self.connect() as conn:
                cur = conn.execute(sql, tuple(params))
                return [dict(r) for r in cur.fetchall()]

    def fetch_controls(self, domain_id: Optional[str] = None) -> list[dict[str, Any]]:
        if domain_id:
            return self._rows(
                "SELECT * FROM pisf_compliance WHERE domain_id = ? ORDER BY control_id",
                (domain_id,),
            )
        return self._rows("SELECT * FROM pisf_compliance ORDER BY control_id")

    def fetch_domains(self) -> list[dict[str, Any]]:
        return self._rows(
            """
            SELECT domain_id, domain_name,
                   COUNT(*) AS control_count,
                   SUM(CASE WHEN status = 'Compliant' THEN 1 ELSE 0 END) AS compliant_count,
                   SUM(CASE WHEN status = 'Under Attack' THEN 1 ELSE 0 END) AS attack_count,
                   SUM(CASE WHEN status = 'Non-Compliant' THEN 1 ELSE 0 END) AS gap_count,
                   SUM(risk_weight) AS weight_sum
            FROM pisf_compliance
            GROUP BY domain_id, domain_name
            ORDER BY domain_id
            """
        )

    def fetch_assets(self) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM asset_inventory ORDER BY risk_score DESC")

    def fetch_incidents(self, limit: int = 25) -> list[dict[str, Any]]:
        return self._rows(
            "SELECT * FROM incident_ledger ORDER BY incident_id DESC LIMIT ?",
            (limit,),
        )

    def update_control_status(
        self,
        control_id: str,
        status: str,
        evidence: str,
    ) -> None:
        if status not in ALLOWED_STATUS:
            raise ValueError(f"Invalid status {status!r}")
        with self.lock:
            with self.connect() as conn:
                row = conn.execute(
                    "SELECT evidence_log FROM pisf_compliance WHERE control_id = ?",
                    (control_id,),
                ).fetchone()
                prior = row["evidence_log"] if row else ""
                stamp = f"[{utc_now()}] {evidence}"
                merged = (prior + "\n" + stamp).strip() if prior else stamp
                conn.execute(
                    """
                    UPDATE pisf_compliance
                    SET status = ?, evidence_log = ?, last_assessment = ?
                    WHERE control_id = ?
                    """,
                    (status, merged[-4000:], utc_now(), control_id),
                )
                conn.commit()

    def update_domain_status(self, domain_id: str, status: str, evidence: str) -> None:
        """Apply a status to every sub-control of a domain (used by detection engines)."""
        with self.lock:
            with self.connect() as conn:
                rows = conn.execute(
                    "SELECT control_id, evidence_log FROM pisf_compliance WHERE domain_id = ?",
                    (domain_id,),
                ).fetchall()
                ts = utc_now()
                stamp = f"[{ts}] {evidence}"
                for row in rows:
                    merged = (row["evidence_log"] + "\n" + stamp).strip() if row["evidence_log"] else stamp
                    conn.execute(
                        """
                        UPDATE pisf_compliance
                        SET status = ?, evidence_log = ?, last_assessment = ?
                        WHERE control_id = ?
                        """,
                        (status, merged[-4000:], ts, row["control_id"]),
                    )
                conn.commit()

    def record_incident(
        self,
        source_ip: str,
        target_host: str,
        classification: str,
        detection_rule: str,
        mitigating_action: str,
        privilege_state: str,
        raw_record: str,
        sha256: str,
        pdf_path: str = "",
    ) -> int:
        with self.lock:
            with self.connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO incident_ledger (
                        created_at, source_ip, target_host, classification,
                        detection_rule, mitigating_action, privilege_state,
                        raw_record, sha256, pdf_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        utc_now(),
                        source_ip,
                        target_host,
                        classification,
                        detection_rule,
                        mitigating_action,
                        privilege_state,
                        raw_record,
                        sha256,
                        pdf_path,
                    ),
                )
                conn.commit()
                return int(cur.lastrowid)

    def attach_pdf(self, incident_id: int, pdf_path: str) -> None:
        with self.lock:
            with self.connect() as conn:
                conn.execute(
                    "UPDATE incident_ledger SET pdf_path = ? WHERE incident_id = ?",
                    (pdf_path, incident_id),
                )
                conn.commit()

    # ------------------------------------------------------------------
    # Website Monitor — registrations + blocks (persist across restarts)
    # ------------------------------------------------------------------
    def register_website(self, name: str, log_path: str, note: str = "") -> int:
        with self.lock:
            with self.connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO monitored_websites (name, log_path, note, enabled, created_at)
                    VALUES (?, ?, ?, 1, ?)
                    """,
                    (name.strip(), log_path.strip(), note.strip(), utc_now()),
                )
                conn.commit()
                return int(cur.lastrowid)

    def list_websites(self) -> list[dict[str, Any]]:
        return self._rows(
            "SELECT * FROM monitored_websites ORDER BY created_at"
        )

    def remove_website(self, site_id: int) -> None:
        with self.lock:
            with self.connect() as conn:
                conn.execute(
                    "DELETE FROM monitored_websites WHERE site_id = ?", (site_id,)
                )
                conn.commit()

    def set_website_enabled(self, site_id: int, enabled: bool) -> None:
        with self.lock:
            with self.connect() as conn:
                conn.execute(
                    "UPDATE monitored_websites SET enabled = ? WHERE site_id = ?",
                    (1 if enabled else 0, site_id),
                )
                conn.commit()

    def mark_website_http_source(self, site_id: int) -> None:
        """v7: record that a site also receives lines via the HTTP ingest
        endpoint (ingest_sources is a '+'-joined set like 'file+http')."""
        with self.lock:
            with self.connect() as conn:
                try:
                    conn.execute(
                        "ALTER TABLE monitored_websites ADD COLUMN ingest_sources"
                        " TEXT NOT NULL DEFAULT 'file'"
                    )
                except Exception:
                    pass
                row = conn.execute(
                    "SELECT ingest_sources FROM monitored_websites WHERE site_id = ?",
                    (site_id,),
                ).fetchone()
                cur = (row[0] if row and row[0] else "file")
                parts = [p for p in cur.split("+") if p]
                if "http" not in parts:
                    parts.append("http")
                conn.execute(
                    "UPDATE monitored_websites SET ingest_sources = ?"
                    " WHERE site_id = ?",
                    ("+".join(parts), site_id),
                )
                conn.commit()

    def find_website(self, ref: str) -> Optional[dict[str, Any]]:
        """v7: look up a registered site by numeric id or exact name."""
        ref = (ref or "").strip()
        if not ref:
            return None
        with self.lock:
            with self.connect() as conn:
                row = None
                if ref.isdigit():
                    row = conn.execute(
                        "SELECT * FROM monitored_websites WHERE site_id = ?",
                        (int(ref),),
                    ).fetchone()
                if row is None:
                    row = conn.execute(
                        "SELECT * FROM monitored_websites WHERE name = ?", (ref,)
                    ).fetchone()
                return dict(row) if row else None

    def record_website_block(
        self,
        site_id: int | None,
        site_name: str,
        source_ip: str,
        reason: str,
        mode: str,
        detail: str = "",
    ) -> int:
        with self.lock:
            with self.connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO website_blocks
                        (site_id, site_name, source_ip, reason, mode, detail, blocked_at, unblocked, unblocked_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, '')
                    """,
                    (site_id, site_name, source_ip, reason, mode, detail, utc_now()),
                )
                conn.commit()
                return int(cur.lastrowid)

    def list_website_blocks(
        self, site_id: int | None = None, include_unblocked: bool = False
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM website_blocks"
        params: list[Any] = []
        clauses: list[str] = []
        if site_id is not None:
            clauses.append("site_id = ?")
            params.append(site_id)
        if not include_unblocked:
            clauses.append("unblocked = 0")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY blocked_at DESC"
        return self._rows(sql, params)

    def mark_block_unblocked(self, block_id: int) -> None:
        with self.lock:
            with self.connect() as conn:
                conn.execute(
                    "UPDATE website_blocks SET unblocked = 1, unblocked_at = ? "
                    "WHERE block_id = ?",
                    (utc_now(), block_id),
                )
                conn.commit()

    # ------------------------------------------------------------------
    # Centralized app settings (modules/app_config.py)
    # ------------------------------------------------------------------
    def get_setting(self, key: str) -> Optional[str]:
        with self.lock:
            with self.connect() as conn:
                row = conn.execute(
                    "SELECT value FROM app_settings WHERE key = ?", (key,)
                ).fetchone()
                return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self.lock:
            with self.connect() as conn:
                conn.execute(
                    """
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value, updated_at = excluded.updated_at
                    """,
                    (key, value, utc_now()),
                )
                conn.commit()

    def list_settings(self) -> list[dict[str, Any]]:
        return self._rows("SELECT key, value, updated_at FROM app_settings ORDER BY key")

    def compute_readiness(self) -> dict[str, Any]:
        """
        Global PISF 2026 Readiness Index.

        Weighted share of Compliant controls. Under Attack and Non-Compliant
        contribute zero. A small additional penalty is applied per live attack
        so the header cannot look 'green' while IAM is on fire.
        """
        rows = self.fetch_controls()
        if not rows:
            return {
                "score": 0.0,
                "compliant": 0,
                "non_compliant": 0,
                "under_attack": 0,
                "total": 0,
                "cii_assets": 0,
            }
        total_w = sum(int(r["risk_weight"]) for r in rows) or 1
        earned = sum(int(r["risk_weight"]) for r in rows if r["status"] == STATUS_COMPLIANT)
        under = sum(1 for r in rows if r["status"] == STATUS_UNDER_ATTACK)
        gaps = sum(1 for r in rows if r["status"] == STATUS_NON_COMPLIANT)
        ok = sum(1 for r in rows if r["status"] == STATUS_COMPLIANT)
        raw = 100.0 * earned / total_w
        score = max(0.0, round(raw - (8.0 * under), 1))
        assets = self.fetch_assets()
        return {
            "score": score,
            "compliant": ok,
            "non_compliant": gaps,
            "under_attack": under,
            "total": len(rows),
            "cii_assets": sum(1 for a in assets if a["classification"] == CLASS_CII),
            "asset_count": len(assets),
            "open_incidents": len(self.fetch_incidents(limit=500)),
        }


_DB: Optional[DatabaseManager] = None
_DB_LOCK = threading.Lock()


def get_db() -> DatabaseManager:
    global _DB
    with _DB_LOCK:
        if _DB is None:
            _DB = DatabaseManager()
            _DB.initialize()
        return _DB
