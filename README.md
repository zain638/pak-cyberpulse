# Pak-CyberPulse

**Locally Deployable Prototype SIEM / SOAR and GRC Automation Platform**
Aligned to the **Pakistan Information Security Framework (PISF) 2026**
National CERT (PKCERT / nCERT) — Academic Final Year Project

## What this is

Pak-CyberPulse is an *academic prototype* that demonstrates a working SIEM / SOAR / GRC
platform for a final-year project. v3 adds threat intelligence, MITRE ATT&CK mapping,
incident case management, forensics, RBAC, alerting, syslog ingestion, multi-framework
compliance mapping, and a token-authenticated REST API.

| Capability | Module | PISF mapping |
|---|---|---|
| Real-time log ingestion (background thread) | `modules/siem_panel.py` | PISF-04, PISF-09 |
| Syslog TCP/UDP listener + file tailer (JSON/CEF/syslog parsers) | `modules/log_ingest.py` | PISF-04, PISF-09 |
| Sliding-window brute-force detection (10 fails / 60s) | `siem_panel.py` | PISF-05.2 |
| UEBA-lite behavioral baselining (new-IP, off-hours) | `siem_panel.py` | PISF-05.3 |
| Telemetry-gap pipeline health (real event timestamps) | `siem_panel.py` | PISF-04 |
| 19-pattern registry: 12 signature + 7 behavioral, OWASP Top-10 mapped | `modules/attack_patterns.py` | PISF-04, PISF-10 |
| MITRE ATT&CK technique/tactic per pattern (15 techniques, 12 tactics) | `modules/mitre_map.py` | — |
| Simulated threat-intel feeds (61 IOCs), enrichment, staleness | `modules/threat_intel.py` | PISF-04 |
| Privilege-honest SOAR containment | `modules/soar_engine.py` | PISF-07 |
| Air-gapped SQLite snapshot on attack | `soar_engine.py` | PISF-07 / PISF-12 |
| Zero-Trust session kill & ban with persisted revocation | `session_registry.py` + `soar_engine.py` | PISF-05 / PISF-07 |
| Incident case lifecycle (6 states) + SLA timers + notes | `modules/case_manager.py` | PISF-07 |
| Forensics timeline + attack-chain graph (offline SVG) | `modules/forensics.py` | PISF-07 / PISF-12 |
| RBAC login: 4 roles, PBKDF2 hashes, SOAR permission gating | `modules/rbac.py` | PISF-05 |
| Email/webhook alerting (dry-run default, per-severity routes, dedup) | `modules/alerting.py` | PISF-07 |
| NIST CSF 2.0 / ISO 27001:2022 / PCI-DSS 4.0 / PECA 2016 control mapping | `modules/compliance_map.py` | PISF-01..13 |
| Token-authenticated REST API (`/health`, `/alerts`, `/cases`, `/ti/iocs`) | `modules/rest_api.py` | — |
| Cryptographic PKCERT incident PDF (SHA-256) | `soar_engine.py` | PISF-12 |
| Fernet CNIC encryption (demo vectors only) | `modules/tech_controls.py` | PISF-06 |
| SCA + secret token review | `tech_controls.py` | PISF-10 / PISF-11 |
| 13-domain / 28-control GRC matrix + literacy quiz | `modules/governance.py` | PISF-01..13 |

## Quick start (local demo)

```bash
cd pak-cyberpulse
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Open the URL printed by Streamlit (default `http://localhost:8501`).

### Docker (v3)

```bash
cd Pak-CyberPulse-FYP-Complete
docker compose up --build
# App: http://localhost:8501   API: http://localhost:8000/health
```

### REST API

```bash
cd pak-cyberpulse
uvicorn modules.rest_api:app --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/health
curl -H "Authorization: Bearer DEMO-TOKEN-CHANGE-ME" http://127.0.0.1:8000/alerts
```

Set `PAKCYBER_API_TOKEN` in the environment to replace the demo token.

### Demo logins (RBAC)

Seeded automatically on first boot. **Demo credentials — change or disable for any shared deployment.**

| Username | Password | Role |
|---|---|---|
| admin | Admin123! | Admin |
| soc.manager | Soc12345 | SOC Manager |
| senior.analyst | Senior123 | Senior Analyst |
| analyst | Analyst123 | Analyst |

SOAR execution (`soar.execute`, `soar.kill_session`) requires Senior Analyst or above.
Without a login the app runs in labelled DEMO mode.

### Demo path for examiners (10 minutes)

1. **Executive GRC** — inspect the 13-domain control matrix and Global PISF 2026 Readiness Index.
2. **SIEM** — click *Inject brute-force test vector*; wait for the crimson *Under Attack* banner and audio alert. Note the MITRE technique column (T1110.001).
3. **Zero-Trust Session Manager** — use *Kill Session & Ban Host*; the session row flips to `revoked` and stays revoked after refresh.
4. **SOAR Gate** — log in as `senior.analyst`, then *EXECUTE PARALLEL SOAR MITIGATION PLAYBOOK*; download the PKCERT PDF and note the SHA-256 footer.
5. **Threat Intel** — search an IOC (e.g. `203.0.113.10`), check feed staleness indicators.
6. **Cases** — create a case from the incident, walk it open → triage → contained, watch the SLA timer.
7. **Forensics** — open the incident timeline and attack-chain graph.
8. **Compliance** — compare coverage across NIST CSF 2.0, ISO 27001:2022, PCI-DSS 4.0, PECA 2016.
9. **Technical safeguards** — encrypt a DEMO CNIC, run secret scan and SCA baseline; try the Alerting dry-run.
10. **Website Monitor** (Technical Safeguards / SOAR Gate → Website Monitor) — see "How to test the Website Monitor" below.

### How to test the Website Monitor (live detection → auto-block)

1. Point the monitor at a local access log. Open the app, go to **Technical Safeguards / SOAR Gate → Website Monitor**, and register a site:
   - Website name: `demo-site`
   - Access-log file path: a real file, e.g. `/tmp/demo-access.log`
     (create it first: `touch /tmp/demo-access.log`)
2. Confirm the green **LIVE** banner appears for the site ("tailing … (N lines parsed)").
   If the banner says the tailer is not running, the log path is wrong — no fake
   traffic is ever shown.
3. Simulate an attack against the site by appending malicious requests to the log
   (three different payloads from the same IP, e.g. in a terminal):
   ```bash
   IP=203.0.113.99
   echo "$IP - - [22/Sep/2026:12:00:01 +0500] \"GET /?password=hunter2alpha HTTP/1.1\" 200 10 \"-\" \"x\"" >> /tmp/demo-access.log
   echo "$IP - - [22/Sep/2026:12:00:02 +0500] \"GET /?api_key=ZZZ999secret HTTP/1.1\" 200 10 \"-\" \"x\"" >> /tmp/demo-access.log
   echo "$IP - - [22/Sep/2026:12:00:03 +0500] \"GET /?token=abcdef123456 HTTP/1.1\" 200 10 \"-\" \"x\"" >> /tmp/demo-access.log
   ```
   You can also try a classic SQL injection probe — it fires the SQLi signature:
   ```bash
   echo "$IP - - [22/Sep/2026:12:00:04 +0500] \"GET /?id=1' OR '1'='1 HTTP/1.1\" 200 10 \"-\" \"x\"" >> /tmp/demo-access.log
   ```
4. Watch within a few seconds:
   - the **Attack-pattern hits over time** chart spikes red,
   - the hits table lists `SECRET_IN_URL` / `SQLI` with the source IP,
   - a red-to-green **⛔ AUTO-BLOCKED** animation card appears,
   - the IP shows up under **Blocked IPs** with its block mode.
5. Privilege note: a real **NETWORK FIREWALL BLOCK** (iptables / netsh rule) needs
   admin/root. Without privileges the app shows an honest
   "FIREWALL BLOCK UNAVAILABLE — run as administrator/root" banner and falls back
   to the application-layer ACL (`mock_acl_rules.txt`) — detection still fires,
   nothing is silently skipped. Use **Unblock** to remove the ACL entries again
   (OS firewall rules need the same privileges to remove).
6. **Remote servers:** instead of a local file, a web server can POST raw
   access-log lines to the authenticated REST endpoint (same detection →
   block pipeline; the site's ingest sources become `file+http`):
   ```bash
   curl -X POST http://127.0.0.1:8000/websites/ingest \
     -H "Authorization: Bearer $PAKCYBER_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"site": "demo-site", "lines": ["203.0.113.9 - - [22/Sep/2026:12:00:01 +0500] \"GET /?id=1\x27 OR \x271\x27=\x271 HTTP/1.1\" 200 10 \"-\" \"x\""]}'
   ```
   (The desktop app must be running — the monitor singleton lives in the app
   process; otherwise the endpoint returns an honest 503.)

## Tests

```bash
cd pak-cyberpulse
python3 -m pytest tests/ -q
```

160 tests, 0 failures — see `tests/TEST_RESULTS.md` for the per-category breakdown and coverage summary.

## Project layout

```
pak-cyberpulse/
├── app.py                      # Streamlit entry + CSS + KPI header + 7 tabs
├── requirements.txt
├── mock_acl_rules.txt          # Application-layer DENY list (runtime)
├── database/
│   ├── db_manager.py           # SQLite schema, PISF seed (28 controls), readiness score
│   ├── live_siem_stream.log    # Append-only JSONL SIEM stream
│   └── backups/                # Read-only air-gapped DB snapshots
├── modules/
│   ├── siem_panel.py           # Tailer thread, sliding window, OWASP, Zero-Trust UI
│   ├── attack_patterns.py      # 19-pattern registry (12 signature + 7 behavioral)
│   ├── mitre_map.py            # MITRE ATT&CK mapping for all 19 patterns
│   ├── threat_intel.py         # Simulated TI feeds, IOC enrichment, staleness
│   ├── soar_engine.py          # Privilege probe, ACL/firewall, PDF, air-gap
│   ├── session_registry.py     # Persisted Zero-Trust session revocation
│   ├── case_manager.py         # Incident cases: 6-state lifecycle + SLA
│   ├── forensics.py            # Timeline + attack-chain graph
│   ├── rbac.py                 # Login, 4 roles, PBKDF2, permission gating
│   ├── alerting.py             # Email/webhook dispatcher, dry-run, dedup
│   ├── log_ingest.py           # Syslog TCP/UDP listener + file tailer
│   ├── compliance_map.py       # NIST/ISO/PCI-DSS/PECA control mapping
│   ├── rest_api.py             # FastAPI: /health /alerts /cases /ti/iocs
│   ├── tech_controls.py        # Fernet, SCA, secret review
│   └── governance.py           # GRC matrix, risk rating, literacy quiz
├── tests/                      # 160-test pytest suite + TEST_RESULTS.md
└── reports/                    # Generated PKCERT PDF evidence packs
```

Package layout (this ZIP):

```
Pak-CyberPulse-FYP-Complete/
├── 01_Software_Project/pak-cyberpulse/   # the software (above)
├── 02_Thesis/                            # thesis document (separate file)
├── 03_Presentation/                      # defense slides (separate file)
├── 04_Deployment_Guide/                  # deployment runbook
├── 05_Defense_Prep/                      # defense playbook
├── 05_Diagrams/                          # 8 architecture diagrams
├── Dockerfile / docker-compose.yml
└── CHANGELOG.md
```

Note: the thesis document and defense presentation are separate package files only.
The running application offers no thesis/presentation option anywhere in its UI.

## Academic honesty notes

- **DEMO telemetry only.** Mock Pakistani CNIC vectors are labelled; they are not citizen records.
- **Privilege labels are truthful.** If the process is not root / admin, the UI says so and uses application-layer ACL instead of pretending a firewall rule was installed.
- **Heuristics are labelled.** Impossible-travel detection is a /16-network-change heuristic — no GeoIP is claimed. Threat-intel feeds are simulated and labelled as such.
- **Not an operational PKCERT instrument.** This is a Final Year Project prototype for examination and teaching.

## Licence / use

Academic use for the submitting student’s Final Year Project assessment.
Framework references: National Cyber Security Policy 2021, CERT Rules 2023, PISF 2026 (National CERT).
