# Changelog

## v7.0 — 2026-09-22 — Production-hardening release

### Visual overhaul
- Pure black / red / neon-green SOC theme with high-contrast buttons and
  responsive laptop/mobile layout.
- Full-screen startup splash with staged progress, animated LIVE indicators,
  log-processing scanner animation, threat pulses, red→green containment
  results, animated block/termination checkmarks.

### New: Website Monitor
- Sixth nested tab under **Technical Safeguards / SOAR Gate → Website Monitor**.
- Register sites by name + access-log path (canonicalized, traversal-safe).
- Combined Log Format parser, background tailer with rotation handling.
- Requests become SIEM `HTTP_REQ` events; 401/403 on login-like URLs emit
  `AUTH_FAIL` into the existing brute-force/password-spray correlators.
- Dashboard: req/min, top IPs/URLs, status breakdown, attack hits over time.
- Auto-block: 3 attack hits / IP / 300 s → `contain_source_ip()` (firewall or
  application ACL, privilege-honest). Animated AUTO-BLOCKED card, persistent
  block records, unblock with ACL cleanup.
- **Per-site HTTP ingest:** authenticated `POST /websites/ingest`
  `{site, lines[]}` for remote servers; persistent `ingest_sources`
  metadata (`file`, `file+http`).

### Production hardening
- Central settings (`modules/app_config.py` + Settings UI tab): OTX key
  (env `OTX_API_KEY` → Settings), REST token (env `PAKCYBER_API_TOKEN` →
  Settings → clearly-labeled demo fallback), Abuse.ch auto-refresh toggle,
  `require_login` gate. Secrets are never rendered back to the browser.
- REST API: DB-configured tokens accepted, `/health` stays public and now
  reports `auth_mode` honestly (`custom-env` / `custom-settings` /
  `demo-token-change-me`).
- RBAC: `must_change` flag on demo accounts, CHANGE ME banner, in-app
  password-change form; seeded demo accounts flagged on migration; PBKDF2
  unchanged.
- Real Abuse.ch threat intel: URLhaus, Feodo Tracker, **ThreatFox**
  (SSLBL was deprecated upstream on 2025-01-03 — ThreatFox replaces it).
  LIVE FEED vs SIMULATED badges; per-feed + bulk fetch; OTX via central key;
  background refresh (Abuse.ch 6 h, OTX 12 h) with desktop-log outcomes;
  `refresh_feed()` routes live feeds to real fetch, never synthetic rotation.
- Security self-review: XSS escaping on all user/log-derived values rendered
  as unsafe HTML (Website Monitor, SIEM zero-trust banners, SOAR results);
  path canonicalization for website log registration; background threads
  (website tailer/watcher, TI refresh) log exceptions instead of dying
  silently; startup warnings for demo credentials in `~/.pak-cyberpulse/desktop.log`.
- Native log sources: Windows Event Log subscriber (Security/System),
  Linux journalctl follower with syslog/auth.log fallbacks, TCP/UDP syslog
  listener on 127.0.0.1:1514. Honest "unavailable" states, never silent demo
  telemetry (demo mode is explicit opt-in only, events labeled `DEMO_SYNTH`).

### Docs
- New `README-DEPLOY.md`: requirements, privilege rationale, install,
  first-run checklist, unsigned-binary/SmartScreen warning, FAQ, pilot
  limitations, backup.

### Honest limitations (not fixed in v7)
- Windows `.exe` must be rebuilt and launch-tested natively on Windows.
- Windows Event Log flow not launch-tested (Linux VM only).
- Binaries are unsigned → SmartScreen/AV prompts expected.
- Single-node SQLite, no HA. OTX needs the company's own key.

## v7.0 final verification — 2026-09-22 (this build)

- **Test suite: 160 passed, 0 failed** (`pytest tests/`, 2 FastAPI/Starlette
  TestClient deprecation warnings).
- **Linux binary:** `desktop/dist/Pak-CyberPulse`, 171 MB ELF 64-bit,
  PyInstaller onefile, built clean from this source tree (spec bundles
  `fpdf2` + `cryptography` via `collect_all`).
- **Binary launch test:** serves HTTP 200 on 127.0.0.1:8501; app script
  executes — top-level imports verified (`fpdf`, `cryptography.fernet`,
  `website_monitor`, `app_config`/`settings_panel`, `threat_intel`).
- **Native journald flow:** `logger -t pakcyber-test` line captured by
  `JournaldTailer` as `SYSTEM_LOG` event (channel=journald).
- **Website Monitor end-to-end (frozen binary):** 3× `SECRET_IN_URL`
  hits from 203.0.113.88 in the tailed access log → auto-block fired
  (`NETWORK FIREWALL BLOCK`, threshold 3/300 s) → real iptables DROP rule
  verified present, then removed. UI showed **Attacks: 1**.
- **Screenshots (1366×850):** dashboard, SIEM LIVE (journald+syslog,
  demo mode OFF), Website Monitor, Settings, attack-detected state —
  in `screenshots-v7/`, also shipped in the release ZIP.
