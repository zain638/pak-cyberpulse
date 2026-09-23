#!/usr/bin/env bash
# Build the Pak-CyberPulse Linux desktop binary (PyInstaller onefile).
# Run from this directory:  ./build.sh
set -euo pipefail

cd "$(dirname "$0")"

echo "[1/3] Installing PyInstaller..."
python3 -m pip install --user --break-system-packages -q pyinstaller

echo "[2/3] Building onefile binary (this takes several minutes)..."
python3 -m PyInstaller --clean --noconfirm pak_cyberpulse.spec

echo "[3/3] Done."
ls -lh dist/Pak-CyberPulse
echo "Binary: $(pwd)/dist/Pak-CyberPulse"
