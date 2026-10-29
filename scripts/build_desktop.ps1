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

Write-Host "[4/4] Packaging Standalone Zero-Install Portable Studio (No Installer)..." -ForegroundColor Cyan
$env:CSC_IDENTITY_AUTO_DISCOVERY = "false"
& npm.cmd run dist:win
if ($LASTEXITCODE -ne 0) { throw "electron-builder packaging failed with exit code $LASTEXITCODE" }

# Locate makensis.exe
$MakeNsis = (Get-Command makensis -ErrorAction SilentlyContinue).Source
if (-not $MakeNsis) {
  $candidates = Get-ChildItem -Path "$env:LOCALAPPDATA\electron-builder\cache\nsis" -Recurse -Filter "makensis.exe" -ErrorAction SilentlyContinue
  if ($candidates) { $MakeNsis = $candidates[0].FullName }
}
if (-not $MakeNsis) {
  throw "makensis.exe not found. Please install NSIS or ensure electron-builder cache is present."
}

Write-Host "Compiling standalone self-extracting portable runner ($MakeNsis)..." -ForegroundColor Cyan
Set-Location -LiteralPath (Join-Path $RepoRoot "scripts")
& $MakeNsis package_portable.nsi
if ($LASTEXITCODE -ne 0) { throw "makensis packaging failed with exit code $LASTEXITCODE" }

Set-Location -LiteralPath $RepoRoot
# Remove legacy installer if present
if (Test-Path "release/UnForce-Setup-*.exe") { Remove-Item -Force "release/UnForce-Setup-*.exe" }

# Synchronize unpacked studio files to root folder so the environment is ready immediately
$RootStudioDir = Join-Path $RepoRoot "..\UnForce Studio"
if (Test-Path $RootStudioDir) {
  Copy-Item -Recurse -Force "desktop/dist/win-unpacked/*" $RootStudioDir
}

Write-Host "`n[OK] Build complete! Zero-install portable executable is in: $RepoRoot\release\UnForce-Portable.exe" -ForegroundColor Green
Get-ChildItem "release"
