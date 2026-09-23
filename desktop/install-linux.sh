#!/usr/bin/env bash
# =====================================================================
# Pak-CyberPulse - Linux installer
#   Installs the Pak-CyberPulse binary to ~/.local/bin,
#   installs the .desktop launcher, optionally enables autostart,
#   then launches the app.
# Usage: ./install-linux.sh   (run from the folder containing the binary)
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"

BIN_SRC="./Pak-CyberPulse"
BIN_DST="$HOME/.local/bin/Pak-CyberPulse"
DESKTOP_SRC="./Pak-CyberPulse.desktop"
APPS_DIR="$HOME/.local/share/applications"

if [ ! -x "$BIN_SRC" ]; then
    echo "ERROR: Pak-CyberPulse binary not found next to this script."
    echo "Copy the binary from the release ZIP into this folder first."
    exit 1
fi

echo "[1/4] Installing binary to ~/.local/bin ..."
mkdir -p "$HOME/.local/bin"
cp "$BIN_SRC" "$BIN_DST"
chmod +x "$BIN_DST"

echo "[2/4] Installing desktop launcher ..."
mkdir -p "$APPS_DIR"
# Point Exec at the installed location (absolute path, no PATH dependency)
sed "s|^Exec=.*|Exec=$BIN_DST|" "$DESKTOP_SRC" > "$APPS_DIR/Pak-CyberPulse.desktop"
chmod +x "$APPS_DIR/Pak-CyberPulse.desktop" 2>/dev/null || true
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
fi

echo "[3/4] Autostart ..."
read -r -p "Start Pak-CyberPulse automatically at login? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    mkdir -p "$HOME/.config/autostart"
    cp "$APPS_DIR/Pak-CyberPulse.desktop" "$HOME/.config/autostart/"
    echo "Autostart enabled."
else
    echo "Autostart skipped."
fi

echo "[4/4] Launching Pak-CyberPulse ..."
echo "Your browser will open to http://localhost:8501"
nohup "$BIN_DST" >/dev/null 2>&1 &
echo "Done. Find Pak-CyberPulse in your applications menu."
