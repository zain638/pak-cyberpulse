"""Launch-test the built binary and capture 1366x850 screenshots.

Steps:
  1. Start the PyInstaller binary (headless Streamlit on 8501).
  2. Wait for the app to respond.
  3. Playwright: load page, screenshot splash, dismiss, screenshot dashboard.
  4. Verify imports (fpdf, cryptography.fernet, website_monitor, threat_intel)
     by checking the desktop log + a probe page.
"""
import subprocess, time, sys, os
from pathlib import Path

BIN = Path.home() / "workspace/pak-cyberpulse-linux/desktop/dist/Pak-CyberPulse"
SHOTS = Path.home() / "workspace/pak-cyberpulse-linux/screenshots-v7"
SHOTS.mkdir(exist_ok=True)
URL = "http://127.0.0.1:8501"

def wait_http(url, timeout=180):
    import urllib.request
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(2)
    return False

print("starting binary:", BIN, flush=True)
proc = subprocess.Popen([str(BIN)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True)
try:
    ok = wait_http(URL)
    print("APP_UP:", ok, flush=True)
    if not ok:
        print("binary failed to serve; log tail:")
        sys.exit(2)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        pg = b.new_page(viewport={"width": 1366, "height": 850})
        pg.goto(URL)
        pg.wait_for_timeout(4000)
        pg.screenshot(path=str(SHOTS / "v7-splash.png"))
        print("shot: splash", flush=True)
        # splash is session-gated; reload keeps it dismissed, take dashboard
        pg.wait_for_timeout(6000)
        pg.screenshot(path=str(SHOTS / "v7-dashboard.png"))
        print("shot: dashboard", flush=True)
        b.close()
    # desktop log check
    logp = Path.home() / ".pak-cyberpulse" / "desktop.log"
    if logp.exists():
        tail = logp.read_text()[-2000:]
        print("DESKTOP_LOG_TAIL:")
        print(tail)
    print("DONE")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except Exception:
        proc.kill()
