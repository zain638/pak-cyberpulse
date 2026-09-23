# Pak-CyberPulse v4 — Pytest Suite Results

Run from `01_Software_Project/pak-cyberpulse/`:

```
python3 -m pytest tests/ -q
```

**Result: 127 passed, 0 failed, 0 skipped** (2026-09-22)

v4 keeps every v3 test intact (all 12 v3 test files still present; 11 are
byte-identical to the v3 submission, `test_rest_api.py` only gained 2 tests)
and adds 54 new tests for the v4 feature set.

## Per-category counts

| Test file | Category | Tests |
|---|---|---|
| `test_attack_patterns.py` | Attack-pattern registry integrity | 6 |
| `test_siem_engine.py` | SIEMEngine detection (no `start()`) | 9 |
| `test_soar_engine.py` | SOAR containment primitives | 7 |
| `test_session_registry.py` | Zero-trust session store | 3 |
| `test_threat_intel.py` | TIStore feeds / enrichment | 7 |
| `test_mitre_map.py` | MITRE ATT&CK mapping | 6 |
| `test_case_manager.py` | Case lifecycle / SLA / timeline | 7 |
| `test_rbac.py` | Accounts, login, permission matrix | 7 |
| `test_alerting.py` | Dispatch, dedup, honest failures | 5 |
| `test_log_ingest.py` | Syslog/CEF/JSON/RAW parser | 6 |
| `test_compliance_map.py` | Framework map + coverage math | 4 |
| `test_rest_api.py` | FastAPI auth + endpoints (+ `/anomalies`) | 8 |
| `test_anomaly_engine.py` | **v4** z-score / modified z-score / EWMA / entropy / UEBA-lite | 24 |
| `test_connectors.py` | **v4** JSON / CSV / Windows Event XML / custom-regex parsers | 14 |
| `test_ti_import.py` | **v4** TI CSV bulk import + OTX graceful offline | 8 |
| `test_perf.py` | **v4** batch-ingest throughput / non-blocking submit / single-fsync batch | 4 |
| `test_ui_api_compat.py` | **v4** Streamlit API compatibility guards | 2 |
| **Total** | | **127** |

## Coverage summary (pytest-cov, real run)

```
python3 -m pytest tests/ -q --cov=modules --cov=database --cov-report=term-missing
```

| Module | Stmts | Cover | Notes |
|---|---|---|---|
| `modules/attack_patterns.py` | 11 | **100%** | full registry exercised |
| `modules/rest_api.py` | 39 | 95% | all endpoints hit; only the `__main__` uvicorn block missed |
| `modules/session_registry.py` | 58 | 86% | lifecycle + revoke paths covered |
| `modules/threat_intel.py` | 172 | 78% | seed/enrich/stale/refresh covered; UI panel untouched |
| `modules/alerting.py` | 165 | 74% | dispatcher + channels covered; `render_*` untouched |
| `modules/rbac.py` | 130 | 72% | manager + seed covered; `render_login_panel` untouched |
| `modules/mitre_map.py` | 56 | 64% | registry + annotate covered; `render_mitre_panel` untouched |
| `modules/case_manager.py` | 227 | 53% | lifecycle/SLA/timeline covered; Streamlit panel untouched |
| `modules/compliance_map.py` | 41 | 51% | map + coverage math covered; panel untouched |
| `modules/siem_panel.py` | 648 | 45% | every detection correlator covered; tailer thread, demo fire_* vectors and the 400-line `render_siem_panel` untouched (no Streamlit runtime in pytest, by design) |
| `modules/log_ingest.py` | 227 | 30% | `parse_syslog_line` fully covered; listener/tailer/panel untouched (sockets + threads out of scope) |
| `modules/soar_engine.py` | 280 | 25% | containment primitives + canonical record + hashing covered; PDF ledger + 200-line `render_soar_panel` untouched |
| `database/db_manager.py` | 124 | 71% | seed/read/update/incident paths covered |
| `modules/forensics.py`, `modules/governance.py`, `modules/tech_controls.py` | — | 0% | **not in the test contract** — no tests target them |

TOTAL: 45% across `modules/` + `database/`. Every uncovered line is a
deliberate exclusion: `render_*` Streamlit panels (task forbids calling them
without a Streamlit runtime), background threads/sockets, or modules outside
the test contract.

## Per-module: what is exercised

- **attack_patterns**: `PATTERN_BY_ID`/`SIGNATURE_PATTERNS` registry — 19 ids,
  unique; every required key present; all regexes compile; 12 signature /
  7 behavioral split; spot-checks (SQLi/XSS fire, benign line is clean);
  `owasp_coverage()` spans all 19.
- **siem_panel** (`SIEMEngine`, no `start()`): brute-force window fires at
  exactly 10 AUTH_FAIL/60s per (ip,user) and not at 9; per-tuple isolation;
  SQLi+XSS signature hits in `injection_hits` and `pattern_hits`;
  UEBA baseline trains on replay then fires NEW_IP + OFF_HOURS;
  TELEMETRY_GAP fires on real-timestamp ingest collapse (dedup within the
  minute) and stays quiet on steady rate; PASSWORD_SPRAY and
  IMPOSSIBLE_TRAVEL patterns fire.
- **soar_engine**: `canonical_incident_record` determinism + order-locking
  (scrambled dict → identical string; exact expected string; missing key →
  `KeyError`); `sha256_hex("abc")` known vector;
  unprivileged `contain_source_ip` writes `DENY` to the (tmp) ACL;
  `terminate_and_ban_session` refuses `""`/`"0.0.0.0"`/`"-"`/`"unknown"`,
  and on a valid IP writes both `DENY` and the `BAN` marker;
  valid-IP kill revokes the `zt_sessions` row (`status='revoked'`,
  `revoked_at` set, `REVOKED` in result detail).
- **session_registry**: `upsert_active` insert + `last_seen` refresh;
  `revoke` sets `status='revoked'` + `revoked_at`; `revoke` of unknown IP →
  `False`.
- **threat_intel** (`TIStore` on tmp DB): `seed_feeds` inserts exactly 61
  IOCs, reseed adds 0; `enrich` hit returns matches with
  `confidence`/`first_seen`; miss → empty matches; domain lookup
  case-insensitive; `refresh_feed` mutates `last_updated`, rotates 1–3 IOCs,
  clears staleness; unknown feed → `ValueError`.
- **mitre_map**: all 19 pattern ids mapped; every URL starts with
  `https://attack.mitre.org/techniques/`; `annotate_alert` adds the 4
  `mitre_*` keys without mutating the input; unknown id returns the alert
  unchanged; spot-checks (SQLI→T1190, BRUTEFORCE→T1110.001).
- **case_manager** (tmp DB): full `open→…→closed` lifecycle; illegal jump
  and unknown status → `ValueError` (state untouched); `closed→triage`
  reopen allowed; `sla_status` ok/warning/breached/closed via rewritten
  timestamps; SLA due = `SLA_HOURS[severity]`; `add_note` + `case_timeline`
  chronological ordering incl. system status-change notes; create/note
  validation.
- **rbac** (tmp DB): bad role / short password / blank username / duplicate
  rejected; login ok, wrong password → `None`, unknown → `None`;
  inactive user cannot log in (reactivation works); permission matrix
  (Analyst denied `soar.execute`, Admin allowed `user.manage`,
  Senior allowed `soar.kill_session`); `seed_demo_users` idempotent;
  DB file bytes contain no plaintext password; per-user salts differ.
- **alerting** (tmp DB): dry-run dispatch returns `mode: dry_run` with
  SMTP/HTTP entry points monkeypatched to raise (proves no socket use);
  second identical dispatch suppressed as `deduped` and logged;
  live webhook/email to a closed port → `ok: False` with error text and a
  `failed` log row.
- **log_ingest**: `parse_syslog_line` on JSON, CEF (`CEF:0|…`), BSD
  `<34>Oct 11 …` (pri/facility/severity/host/app/pid/msg), RAW, empty, JSON
  scalar, and pre-stamped JSON (ts not overwritten) — every result carries
  `ts` + `iso`.
- **compliance_map** (tmp DB): `CONTROL_FRAMEWORK_MAP` covers exactly the
  28 `PISF_CONTROLS` ids, each with all 4 frameworks; `framework_coverage`
  on seed data = 20/28 compliant = 71.4%; live status change moves the
  numbers (19/28, one Under Attack); unknown framework → `ValueError`.
- **rest_api** (TestClient): `/health` 200 without auth; `/alerts` 401
  without token and 401 on bad token, 200 with `DEMO-TOKEN-CHANGE-ME`;
  `/cases?status=open` 200; `/ti/iocs?q=203.0.113` 200 with
  `matches`/`stale_feeds` keys; **v4** `/anomalies` 401 without token, 200
  with token returning a list, and the route is registered at import time
  (regression: not after the `__main__` uvicorn block).
- **anomaly_engine** (**v4**): z-score flags a clear outlier, stays quiet on
  flat/normal-spread data, needs minimum samples; modified z-score catches a
  masked outlier; Shannon entropy orders random strings above readable ones
  and the entropy-outlier detector flags DGA-like hostnames; EWMA learns a
  baseline without firing, fires on spikes, ignores dips; UEBA-lite scores 0
  below the learning minimum, then flags NEW_IP + OFF_HOURS logins with
  explanations and per-user risk tables.
- **connectors** (**v4**): `parse_json_log` normalizes field aliases, accepts
  epoch timestamps, fills defaults for sparse objects, rejects garbage;
  `import_csv_logs` happy path plus rejection of unknown/headerless headers;
  `parse_windows_event_xml` extracts EventID/Provider/TimeCreated fields and
  rejects malformed XML; `RegexLogParser` happy path, no-match → None,
  invalid pattern → error, extra named groups preserved, `parse_lines`
  skips non-matching lines.
- **ti_import** (**v4**): `import_indicators_csv` adds and counts rows,
  dedupes against existing IOCs, skips invalid rows, rejects bad headers;
  OTX with no key and OTX offline both degrade gracefully (never raise);
  a mocked OTX response parses into typed indicators.
- **perf** (**v4**): `BatchIngester` delivers every submitted line,
  `submit()` never blocks on a slow sink, ingest throughput benchmark,
  `append_events_batch` writes with a single fsync.
- **ui_api_compat** (**v4**): guards against removed/renamed Streamlit
  kwargs so the panels fail loudly in CI instead of at runtime.

## Isolation guarantees (verified)

- Every DB test uses `DatabaseManager(tmp_path/"t.db")` — the real
  `database/cyberpulse.db` is never written by the suite (a `zt_sessions`
  pollution from early runs was removed; only pre-existing demo data remains).
- SIEM/SOAR tests monkeypatch `get_db` → tmp DB, `ACL_PATH` → tmp file,
  `detect_privilege` → forced-unprivileged (the CI user is root; without this
  the suite would attempt a real `iptables` call), and
  `maybe_trigger_airgap_on_attack` → no-op.
- No `render_*` Streamlit function is ever called; no mock of any unit under
  test — only external boundaries (ACL path, privilege probe, DB binding,
  network entry points) are monkeypatched.

## Skips

None — 0 skipped. (The `session_registry` tests were written with
`pytest.importorskip` while the sibling-owned module did not exist yet; the
module has since been created with a compatible API, so all 3 run and pass.)
