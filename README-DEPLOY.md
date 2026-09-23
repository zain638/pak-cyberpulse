# Pak-CyberPulse v7.0 — Deployment Guide

**Target:** pilot / small-company deployment on Windows 10+ and Linux.
**Honest scope:** single-node academic prototype hardened for pilot use — not a
multi-site enterprise SIEM. Read the *Pilot limitations* section before promising
anything to management.

## 1. System requirements

| | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 64-bit / Ubuntu 22.04+ 64-bit | Windows 11 / Ubuntu 24.04 |
| RAM | 4 GB | 8 GB |
| Disk | 1 GB free (app + SQLite + logs) | 5 GB (log growth) |
| CPU | 2 cores | 4 cores |
| Network | outbound HTTPS for Abuse.ch feeds | same |

Python 3.10+ only needed if running from source. The desktop binaries bundle
everything (PyInstaller).

## 2. Why admin / root is needed

Pak-CyberPulse degrades gracefully without privileges, but two features need them:

- **Native log sources:** Windows Security Event Log and Linux journald/system
  logs are readable only by administrators / root (or the `systemd-journal` /
  `adm` groups on Linux).
- **NETWORK FIREWALL BLOCK:** SOAR containment installs real OS firewall rules
  (Windows `netsh advfirewall`, Linux `iptables`). Without privileges the
  platform still *detects* everything and falls back to the
  **application-layer ACL** (`mock_acl_rules.txt`) — the UI always says which
  mode fired. Nothing is silently skipped.

Run the binary "as Administrator" (Windows) or with `sudo` (Linux) for the
full experience.

## 3. Install

### Windows (native build required)

1. On a **Windows 10+ machine**, copy the project folder, install Python 3.10+
   and run `build-windows-FIXEDv3.bat` (or the equivalent PyInstaller command in
   `desktop/`).
2. Run `dist\Pak-CyberPulse\Pak-CyberPulse.exe` **as Administrator**.
3. The app opens in the browser at `http://127.0.0.1:8501`.

> The Linux binary in this release was built on Linux; the Windows `.exe`
> **must be rebuilt and tested on real Windows hardware** — it was not
> launch-tested as part of this release.

### Linux

1. Unzip the release, `chmod +x Pak-CyberPulse`, run with `sudo ./Pak-CyberPulse`
   for firewall + journald access.
2. Browser opens at `http://127.0.0.1:8501`.

### From source (either OS)

```bash
pip install -r requirements.txt
python -m streamlit run app.py --server.headless=true
```

## 4. First-run checklist (do this before any demo)

1. **Settings → Threat Intel:** paste your AlienVault OTX API key (free at
   otx.alienvault.com). Without it, Abuse.ch live feeds still work; OTX stays
   honestly labeled SIMULATED.
2. **Settings → REST API security:** replace the DEMO token
   (`DEMO-TOKEN-CHANGE-ME`) with your own. Set `PAKCYBER_API_TOKEN` env var
   for unattended runs.
3. **RBAC (sidebar):** sign in as `admin` / `Admin123!` — you will see a
   **⚠ CHANGE ME** banner. Change all four demo passwords immediately
   (RBAC panel → change-password form).
4. **Settings → Access control:** enable **Require login** for production.
5. **Website Monitor:** register each site's access-log path
   (Technical Safeguards → SOAR Gate → Website Monitor). Remote servers can
   also POST lines to the authenticated `POST /websites/ingest` endpoint.
6. Confirm the SIEM tab shows **LIVE** (journald / Event Log / syslog), not
   "unavailable".

## 5. Unsigned-binary warning

Release binaries are **not code-signed**. Expect:

- Windows SmartScreen "Unknown publisher" prompt → *More info → Run anyway*.
- Antivirus heuristics may quarantine a PyInstaller bundle on first run —
  allow-list the install folder.

A code-signing certificate (and the associated identity validation) is the
company's responsibility before any customer rollout.

## 6. Troubleshooting FAQ

| Symptom | Cause / fix |
|---|---|
| SIEM shows "LIVE telemetry unavailable" | No journald/Event Log access and no syslog senders. Run as admin/root, or point rsyslog at `127.0.0.1:1514`. |
| Threat-intel live fetch fails | No outbound HTTPS. Feeds degrade gracefully; simulated feeds keep working. |
| Auto-block says APPLICATION-LAYER ACL | Process isn't privileged, or no firewall binary found. Detection still works. |
| REST API returns 401 | Wrong/missing `Authorization: Bearer <token>` header. `/health` is public. |
| `POST /websites/ingest` returns 503 | Desktop app isn't running (the monitor singleton lives in the app process). |
| Port 8501 busy | Another Streamlit instance is running; stop it first. |
| Slow first load after enabling live TI | The URLhaus import is ~17k IOCs; one-time SQLite insert takes a few seconds. |

## 7. Pilot limitations (do not oversell)

- **Single node, SQLite.** No clustering, no HA, no multi-user concurrency
  beyond a small SOC team.
- **Threat intel keys are yours.** Abuse.ch feeds are free; OTX needs the
  company's own free API key.
- **Native testing is yours.** Windows Event Log flow and the Windows `.exe`
  must be verified on the company's own machines; only Linux was
  launch-tested for this release.
- **Firewall/AV/SmartScreen** behavior on locked-down corporate images must be
  validated by the company's IT.
- **Website log paths** must be real, readable access logs; symlinks are
  resolved and canonicalized before opening.

## 8. Backup

Copy the `database/` folder (SQLite + evidence PDFs + `mock_acl_rules.txt`).
On attack, SOAR also writes an air-gapped snapshot to `database/backups/`.
