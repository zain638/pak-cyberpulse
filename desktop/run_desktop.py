"""Pak-CyberPulse desktop entry point (PyInstaller onefile).

- Ensures the per-user data dir (~/.pak-cyberpulse/) exists and is seeded.
- Launches the Streamlit app programmatically on port 8501.
- Opens the system browser to the app after a short delay.
- Any fatal startup error is written to ~/.pak-cyberpulse/desktop.log so the
  app never dies silently when launched from a desktop icon.
"""

from __future__ import annotations

import sys
import threading
import time
import traceback
import webbrowser
from pathlib import Path


def _bundle_root() -> Path:
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    # dev fallback: run_desktop.py lives in desktop/, project root is parent
    return Path(__file__).resolve().parent.parent


def _log_file() -> Path:
    d = Path.home() / ".pak-cyberpulse"
    d.mkdir(parents=True, exist_ok=True)
    return d / "desktop.log"


def _fail(exc: BaseException) -> "NoReturn":  # noqa: F821
    log = _log_file()
    with open(log, "a", encoding="utf-8") as fh:
        fh.write("=" * 70 + "\n")
        fh.write(time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) + "\n")
        traceback.print_exception(exc, file=fh)
    try:
        import tkinter
        from tkinter import messagebox

        root = tkinter.Tk()
        root.withdraw()
        messagebox.showerror(
            "Pak-CyberPulse",
            f"Startup failed. Details were written to:\n{log}\n\n{exc}",
        )
        root.destroy()
    except Exception:
        pass
    raise SystemExit(1)


def _open_browser_delayed(url: str, delay: int = 6) -> None:
    def _go() -> None:
        time.sleep(delay)
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass

    threading.Thread(target=_go, name="browser-opener", daemon=True).start()


def main() -> None:
    bundle = _bundle_root()
    # Make the bundled project tree importable (database/, modules/, ...).
    if str(bundle) not in sys.path:
        sys.path.insert(0, str(bundle))

    try:
        from database.db_manager import ensure_user_data

        ensure_user_data()
    except Exception as exc:  # noqa: BLE001
        _fail(exc)

    app_py = bundle / "app.py"
    if not app_py.exists():
        _fail(FileNotFoundError(f"Bundled app.py not found at {app_py}"))

    url = "http://localhost:8501"
    _open_browser_delayed(url)

    try:
        from streamlit.web.cli import main as st_main

        sys.argv = [
            "streamlit",
            "run",
            str(app_py),
            "--server.port=8501",
            "--server.headless=true",  # we open the browser ourselves
            "--global.developmentMode=false",
            "--server.fileWatcherType=none",
            "--theme.base=dark",  # force dark base so tab labels/buttons stay
            # legible on the app's dark CSS even if the user has a light
            # Streamlit theme configured globally
        ]
        st_main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


if __name__ == "__main__":
    main()
