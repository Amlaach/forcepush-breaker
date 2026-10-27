# Builds the standalone UnForce (ForcePush-Breaker) Chromium Desktop Application for Windows.
# Output artifacts:
#   - desktop/dist/UnForce-Setup-0.7.2.exe    (NSIS Installer)
#   - desktop/dist/UnForce-Portable-0.7.2.exe (Zero-install Portable EXE)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $RepoRoot

Write-Host "[1/4] Synchronizing unified logo, app icons & pre-rendered UI bundle..." -ForegroundColor Cyan
python scripts/generate_icons.py
python scripts/build_ui_bundle.py

Write-Host "[2/4] Compiling standalone Python forensics engine via PyInstaller..." -ForegroundColor Cyan
if (Test-Path "build_backend") { Remove-Item -Recurse -Force "build_backend" }
python -m PyInstaller `
  --noconfirm `
  --clean `
  --onedir `
  --noconsole `
  --name unforce-engine `
  --icon "desktop/assets/icon.ico" `
  --exclude-module PySide6 `
  --exclude-module shiboken6 `
  --exclude-module PyQt5 `
  --exclude-module PyQt6 `
  --exclude-module qtpy `
  --exclude-module webview `
  --exclude-module PIL `
  --exclude-module tkinter `
  --exclude-module _tkinter `
  --exclude-module cryptography `
  --exclude-module pytest `
  --exclude-module setuptools `
  --exclude-module pip `
  --exclude-module wheel `
  --exclude-module numpy `
  --exclude-module pandas `
  --exclude-module scipy `
  --exclude-module matplotlib `
  --exclude-module torch `
  --add-data "gitghost/static;gitghost/static" `
  --distpath "build_backend" `
  --workpath "build/pyinstaller_work" `
  gitghost/__main__.py

Write-Host "[3/4] Installing Electron Chromium dependencies..." -ForegroundColor Cyan
Set-Location -LiteralPath (Join-Path $RepoRoot "desktop")
if (-not (Test-Path "node_modules")) {
  & npm.cmd install
}
if (-not (Test-Path "node_modules/electron/dist/electron.exe")) {
  node node_modules/electron/install.js
}

Write-Host "[4/4] Packaging Chromium Desktop Installer & Portable EXE..." -ForegroundColor Cyan
$env:CSC_IDENTITY_AUTO_DISCOVERY = "false"
& npm.cmd run dist:win
if ($LASTEXITCODE -ne 0) { throw "electron-builder packaging failed with exit code $LASTEXITCODE" }

Set-Location -LiteralPath $RepoRoot
New-Item -ItemType Directory -Force -Path "release" | Out-Null
Copy-Item "desktop/dist/UnForce-*.exe" -Destination "release/" -Force

Write-Host "`n[OK] Build complete! Ready-to-download executables are in: $RepoRoot\release" -ForegroundColor Green
Get-ChildItem "release"
