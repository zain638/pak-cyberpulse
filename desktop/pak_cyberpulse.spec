# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Pak-CyberPulse desktop app (Windows/Linux onefile).

FIXED v5 (2026-09-22): bundles fpdf2 AND cryptography explicitly.
  Root cause of "ModuleNotFoundError: No module named 'fpdf'": the app
  imports `from fpdf import FPDF` (modules/soar_engine.py) but PyInstaller's
  static analysis misses the fpdf2 package, so the frozen exe crashed at
  startup/first report. collect_all("fpdf") forces the package, its data
  files and its hidden imports into the bundle.
  Same class of bug for `from cryptography.fernet import ...`
  (modules/tech_controls.py): cryptography ships Rust-compiled backends
  (cryptography.hazmat.bindings._rust) invisible to static analysis, so the
  frozen exe died at that import. collect_all("cryptography") (+ its cffi
  dependency) fixes it.

Build:  cd desktop && build-windows-FIXEDv3.bat   (Windows)
        cd desktop && ./build.sh                    (Linux)
The whole project tree is bundled as datas so the frozen app keeps the
exact source layout (database/, modules/, app.py, ...). Writable state is
redirected to ~/.pak-cyberpulse/ by database/db_manager.py when frozen.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_all, copy_metadata

import streamlit  # noqa: F401  (ensures the package is importable at spec time)

PROJECT = Path(SPECPATH)  # desktop/ (SPECPATH is the spec file's directory)
APP_ROOT = PROJECT.parent         # pak-cyberpulse/

# Bundle the full project tree (code + demo assets) preserving layout.
datas = [
    (str(APP_ROOT / "app.py"), "."),
    (str(APP_ROOT / "database" / "__init__.py"), "database"),
    (str(APP_ROOT / "database" / "live_siem_stream.log"), "database"),
    (str(APP_ROOT / "mock_acl_rules.txt"), "."),
    (str(APP_ROOT / ".streamlit" / "config.toml"), ".streamlit"),  # dark theme
    (str(APP_ROOT / "modules"), "modules"),
    (str(APP_ROOT / "reports"), "reports"),
]

# Streamlit reads its own version via importlib.metadata at import time;
# PyInstaller does not bundle dist-info metadata by default, so copy it in.
# (Same guard for a few other metadata-reading deps in the chain.)
datas += copy_metadata("streamlit")
for _dist in ("altair", "protobuf", "click", "tornado", "fpdf2"):
    try:
        datas += copy_metadata(_dist)
    except Exception:
        pass

# fpdf2 (imported as `fpdf` by modules/soar_engine.py) is missed by
# PyInstaller's static analysis -> bundle it explicitly: package code,
# data files and hidden imports.
_fpdf_datas, _fpdf_binaries, _fpdf_hidden = collect_all("fpdf")
datas += _fpdf_datas

# cryptography (used as `cryptography.fernet` by modules/tech_controls.py)
# ships Rust-compiled backends (cryptography.hazmat.bindings._rust) that
# PyInstaller's static analysis misses -> bundle it explicitly, same as fpdf.
_crypto_datas, _crypto_binaries, _crypto_hidden = collect_all("cryptography")
datas += _crypto_datas
# cryptography depends on cffi; its backend module is equally invisible to
# static analysis, so collect it too.
_cffi_datas, _cffi_binaries, _cffi_hidden = collect_all("cffi")
datas += _cffi_datas

# Streamlit's frontend (index.html + JS/CSS) lives in streamlit/static/ and
# is loaded from disk at runtime — the default hooks miss it, so bundle it.
_st_root = Path(streamlit.__file__).resolve().parent
_st_static = _st_root / "static"
if _st_static.is_dir():
    datas.append((str(_st_static), "streamlit/static"))

hiddenimports = [
    "streamlit.web.cli",
    "streamlit.runtime.scriptrunner.magic_funcs",
    "fpdf",
    "cryptography",
    "cryptography.fernet",
    "cffi",
]
hiddenimports += _fpdf_hidden
hiddenimports += _crypto_hidden
hiddenimports += _cffi_hidden

a = Analysis(
    [str(PROJECT / "run_desktop.py")],
    pathex=[str(APP_ROOT)],
    binaries=_fpdf_binaries + _crypto_binaries + _cffi_binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Pak-CyberPulse",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX often missing on target machines; skip for reliability
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI launch; fatal errors go to ~/.pak-cyberpulse/desktop.log
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
