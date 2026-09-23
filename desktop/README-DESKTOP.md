# Pak-CyberPulse Desktop App — v4

Pak-CyberPulse (SIEM / SOAR / GRC) as a real desktop app. Double-click to
run — it starts a local server and opens your browser to
**http://localhost:8501**. No terminal, no setup.

## What's new in v4

- **Anomaly Detection tab** — explainable statistical ML on the live stream:
  z-score / modified z-score outliers, EWMA event-rate spike detection,
  Shannon-entropy screen for DGA-like hostnames, and UEBA-lite per-user
  risk scores (usual hours, usual IPs, failure ratio) with plain-English
  explanations. High/Critical anomalies raise incidents + alerts like any
  other detection. A "Run anomaly demo vector" button trains a baseline
  and fires a live demo anomaly for defense demos.
- **More log connectors** (Technical Safeguards → Log Ingest → Connectors):
  JSON log parser, CSV log import, Windows Event Log XML parser, and a
  user-defined named-group regex parser with a live tester.
- **Threat-intel import** (Threat Intel → Import indicators): bulk CSV
  import of indicators (deduplicated against the existing store) and an
  optional AlienVault OTX free-tier fetch (needs a free OTX API key;
  offline or no key = graceful skip, nothing breaks).
- **Faster ingestion**: batch ingestion path (BatchIngester) and a
  single-fsync batch append for large log bursts; benchmarked at tens of
  thousands of events/sec on a laptop (see tests/test_perf.py).
- **API**: new authenticated `GET /anomalies` endpoint (ML anomaly
  incidents from the detection ledger).

Honest scope note: v4 adds the *detection* capabilities of expensive
SIEMs (the part a student can genuinely build and defend). It does NOT
do clustered/distributed processing or petabyte-scale indexing — it is
still a single-machine desktop app, and the README + UI say so.

## Zero-config first run

After install and launch, everything starts by itself:

- Browser opens to http://localhost:8501 automatically
- Demo users are created automatically
- The SIEM log tailer starts automatically
- The **syslog listener auto-starts** on 127.0.0.1:1514 (TCP + UDP), so any
  logs you forward to it appear in the SIEM live, with no button to press
  (the Log ingest tab still has manual Start/Stop as an override)

## Install on Linux (Kali / Ubuntu / Debian)

The release ZIP contains: `Pak-CyberPulse` (binary), `install-linux.sh`,
`Pak-CyberPulse.desktop`.

```bash
unzip Pak-CyberPulse-Desktop-Linux.zip
cd Pak-CyberPulse-Desktop-Linux
chmod +x install-linux.sh
./install-linux.sh
```

What the installer does:

1. Copies the binary to `~/.local/bin/Pak-CyberPulse`
2. Installs the app launcher (find Pak-CyberPulse in your applications menu)
3. Asks if it should start automatically at login (optional)
4. Launches the app

Uninstall: delete `~/.local/bin/Pak-CyberPulse`,
`~/.local/share/applications/Pak-CyberPulse.desktop`, and (if you want a
clean slate) `~/.pak-cyberpulse/`.

## Build + install on Windows

A Windows `.exe` cannot be built on Linux — build it on the Windows PC
itself. Everything is scripted; no manual steps.

**Step 1 — build** (on the Windows PC):

1. Copy the `desktop` folder (or the whole project) to the Windows PC.
2. Double-click **`build-windows.bat`**. It does everything:
   - Checks for Python 3.10+ (tries to install Python 3.11 via winget if
     missing; otherwise install from https://www.python.org/downloads/
     and tick "Add python.exe to PATH", then re-run)
   - Installs the project requirements and PyInstaller
   - Builds `desktop\dist\Pak-CyberPulse.exe` (takes several minutes)

**Step 2 — install:**

3. Double-click **`install-windows.bat`**. It:
   - Copies the exe to `%LOCALAPPDATA%\PakCyberPulse\`
   - Creates a Start Menu shortcut
   - Asks whether to run at Windows startup (optional)
   - Launches the app; your browser opens to http://localhost:8501

## Live logs from YOUR system (not just the demo)

The bundled demo telemetry works out of the box, but the app also ingests
real logs through the auto-started syslog listener (127.0.0.1:1514).

**Linux** — forward system logs with rsyslog:

```bash
echo "*.* @@127.0.0.1:1514" | sudo tee /etc/rsyslog.d/99-cyberpulse.conf
sudo systemctl restart rsyslog
```

Real SSH logins, auth failures, etc. now stream into the SIEM live, and the
brute-force detector fires on real data. Try a real test: run `nmap` or a
few wrong SSH logins against your own machine and watch the alerts.

**Windows** — two honest options:
- **Live forwarding (recommended):** install **nxlog Community Edition**
  (~3-4 MB, https://nxlog.co) and forward Event Logs to `127.0.0.1:1514`
  via TCP syslog — five-minute setup, then Windows logs stream live.
- **Offline import (new in v4):** export events with
  `wevtutil qe Security /f:xml /c:100 > events.xml`, then parse them in
  the app under Technical Safeguards → **Connectors** → Windows Event XML.
  Not live, but zero extra software.

The app itself cannot read the Windows Event Log API directly (Windows
does not expose it to normal apps) — the listening/parsing side is built
in; collection needs one of the two options above.

## Where your data lives

- Linux/macOS: `~/.pak-cyberpulse/` — `database/` (SQLite + live log),
  `reports/` (incident PDFs), `backups/` (air-gapped snapshots),
  `mock_acl_rules.txt`, `desktop.log`
- Windows: `%USERPROFILE%\.pak-cyberpulse\` (same layout)

The app bundle itself is never modified.

## Login accounts (demo)

| Username         | Password    | Role           |
|------------------|-------------|----------------|
| admin            | Admin123!   | Admin          |
| soc.manager      | Soc12345    | SOC Manager    |
| senior.analyst   | Senior123   | Senior Analyst |
| analyst          | Analyst123  | Analyst        |

## Troubleshooting

- **App won't start / nothing opens:** check `~/.pak-cyberpulse/desktop.log`
  (Windows: `%USERPROFILE%\.pak-cyberpulse\desktop.log`) for the full error.
- **Port 8501 already in use:** close the other copy of the app (or the
  `streamlit run` dev server) and relaunch.
- **Browser didn't open:** go to http://localhost:8501 manually.
- **Rebuilding on Linux:** `cd desktop && ./build.sh` → `dist/Pak-CyberPulse`.
