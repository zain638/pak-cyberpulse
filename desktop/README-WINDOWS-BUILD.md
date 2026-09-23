# Pak-CyberPulse — Windows Build Kit (Build from Source)

This kit contains the **full, test-verified Pak-CyberPulse source tree**
(pytest 160/160 passed on 2026-09-23) plus everything needed to build
`Pak-CyberPulse.exe` on a Windows PC. (PyInstaller cannot cross-compile, so
the Windows `.exe` must be built natively on Windows — that is what this kit
is for.)

## What's inside

- `app.py` — the Streamlit app (black / red / neon-green SOC theme)
- `modules/` — all 19 engine modules (SIEM, SOAR, GRC, RBAC, REST API, ...)
- `database/`, `reports/`, `.streamlit/config.toml` — runtime assets
  (the config.toml forces Streamlit's dark base theme so tab labels and
  inputs stay visible)
- `desktop/build-windows.bat` — **double-click build script (does everything)**
- `desktop/pak_cyberpulse.spec` — PyInstaller spec with the fpdf2 /
  cryptography hidden-import fixes (`collect_all("fpdf")` +
  `copy_metadata("fpdf2")`) and the dark-theme `config.toml` bundling
- `desktop/run_desktop.py` — the frozen entry point (referenced by the spec)
- `desktop/install-windows.bat` — installer helper
- `tests/`, `requirements.txt`, `README.md`, `README-DEPLOY.md`, `CHANGELOG.md`

## Build steps (on a Windows 10/11 PC)

1. Install **Python 3.12** from https://www.python.org/downloads/
   - Tick **"Add python.exe to PATH"** during setup.
2. Extract this ZIP anywhere (e.g. `D:\pak-cyberpulse`).
3. Open the `desktop` folder and **double-click `build-windows.bat`**.
   - It checks Python, installs `requirements.txt` + PyInstaller,
     then builds `desktop\dist\Pak-CyberPulse.exe` (onefile).
   - Takes several minutes. It is normal for the antivirus to inspect
     the new binary.
4. Run `desktop\dist\Pak-CyberPulse.exe`. The app opens in your browser at
   http://127.0.0.1:8501.
5. (Optional) run `desktop\install-windows.bat` for a Start-Menu shortcut.

## First-run notes

- The binary is **unsigned** → expect a Windows SmartScreen prompt; click
  "More info → Run anyway".
- SIEM live sources: on Windows the app reads the **Windows Event Log**
  (Security/System channels); demo mode is **opt-in only** — real "no data"
  states are shown honestly.
- Change the seeded demo admin password on first login (RBAC will force it).
- Put your own OTX API key in Settings (or the `OTX_API_KEY` env var);
  secrets are never echoed back to the browser.
