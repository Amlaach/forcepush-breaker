#!/usr/bin/env bash
# Builds the standalone UnForce (ForcePush-Breaker) Chromium Desktop Application for macOS / Linux.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[1/4] Synchronizing unified logo, app icons & pre-rendered UI bundle..."
python3 scripts/generate_icons.py
python3 scripts/build_ui_bundle.py

echo "[2/4] Compiling standalone Python forensics engine via PyInstaller..."
rm -rf build_backend
python3 -m PyInstaller \
  --noconfirm \
  --clean \
  --onedir \
  --noconsole \
  --name unforce-engine \
  --exclude-module PySide6 \
  --exclude-module shiboken6 \
  --exclude-module PyQt5 \
  --exclude-module PyQt6 \
  --exclude-module qtpy \
  --exclude-module webview \
  --exclude-module PIL \
  --exclude-module tkinter \
  --exclude-module _tkinter \
  --exclude-module cryptography \
  --exclude-module pytest \
  --exclude-module setuptools \
  --exclude-module pip \
  --exclude-module wheel \
  --add-data "gitghost/static:gitghost/static" \
  --distpath "build_backend" \
  --workpath "build/pyinstaller_work" \
  gitghost/__main__.py

echo "[3/4] Installing Electron Chromium dependencies..."
cd "$REPO_ROOT/desktop"
npm install
node node_modules/electron/install.js || true

echo "[4/4] Packaging Chromium Desktop Application..."
export CSC_IDENTITY_AUTO_DISCOVERY=false
if [[ "$(uname -s)" == "Darwin" ]]; then
  npm run dist:mac
else
  npm run dist:linux
fi

cd "$REPO_ROOT"
mkdir -p release
cp desktop/dist/UnForce-* release/ 2>/dev/null || true
echo "[OK] Build complete! Artifacts placed in $REPO_ROOT/release"
