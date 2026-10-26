<div align="center">

<img src="assets/logo.png" width="168" height="168" alt="UnForce Official Logo">

# UnForce — ForcePush-Breaker (`v1.0.0`)

### **Cyber-Forensics Chromium Desktop Studio for GitHub Commit Recovery & Secret Hunting**

*"Think `git push --force` or `git rm .env` erased your commits or leaked API keys on GitHub? Paste the repo URL and find out."*

[![CI](https://github.com/Amlaach/forcepush-breaker/actions/workflows/ci.yml/badge.svg)](https://github.com/Amlaach/forcepush-breaker/actions)
[![Desktop Releases](https://github.com/Amlaach/forcepush-breaker/actions/workflows/release.yml/badge.svg)](https://github.com/Amlaach/forcepush-breaker/releases)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/Amlaach/forcepush-breaker)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-purple.svg)](https://sarifweb.azurewebsites.net/)
[![Chromium Electron UI](https://img.shields.io/badge/Desktop-Chromium%20%2F%20Electron-00ff9d.svg)](#download--install)

</div>

---

## Download & Install

Anyone can download and launch **UnForce Studio** immediately — **no Python or Node.js required** (only Git):

| Platform | Download Package | Description |
| :--- | :--- | :--- |
| **Windows Installer (x64)** | [**UnForce-Setup-1.0.0.exe**](https://github.com/Amlaach/forcepush-breaker/releases/latest) | Instant-launch desktop installation with Start Menu & Desktop shortcuts |
| **Windows Portable** | [**UnForce-Portable-1.0.0.exe**](https://github.com/Amlaach/forcepush-breaker/releases/latest) | Zero-install single executable |
| **macOS** | [**UnForce-macOS-1.0.0.dmg**](https://github.com/Amlaach/forcepush-breaker/releases/latest) | Native macOS `.dmg` & `.zip` app bundle |
| **Linux** | [**UnForce-Linux-1.0.0.AppImage**](https://github.com/Amlaach/forcepush-breaker/releases/latest) | Universal `.AppImage` and Debian/Ubuntu `.deb` |

---

## How It Works in 3 Seconds

1. **Copy any GitHub Repository URL** from your browser (`https://github.com/owner/repo` — public or private; private repos authenticate automatically via Git Credential Manager).
2. **Click "Paste & Scan"** inside **UnForce Studio**.
3. **Inspect, Recover, or Purge**:
   - **Ghost & Commit File-Tree Explorer**: View Unified Diffs and browse the complete historical file tree of any ghost or branch commit, previewing and downloading snapshots at any point in time.
   - **`.env` & Config Time-Machine**: Exhume `.env`, `.pem`, `.key`, `.tfstate`, and secret config files deleted via `git rm` or overwritten in `force-push` history.
   - **Secrets & Passive Key Liveness**: Detect 18+ credential families with Shannon entropy + strict cryptographic redaction, and passively verify whether tokens are `ACTIVE` or `REVOKED`.
   - **Deep Search & GitHub Purge Playbook**: Search across every commit, diff, and blob, export `.ZIP` / `JSON` / `SARIF` bundles, and generate ready-to-run `git filter-repo --mirror` purge scripts + GitHub Support cache-purge tickets.

---

## Cyber-Forensics Engineering Highlights

- **Zero Console Flashes (`CREATE_NO_WINDOW`)**: All background Git plumbing and credential operations run completely silently on Windows without spawning console windows.
- **Sub-Second Instant UI Boot**: Pre-rendered Chromium UI bundle loads from local disk in `< 250ms` while the standalone `unforce-engine` daemon binds asynchronously in parallel.
- **Bilingual Cyber HUD (`עברית` RTL + `English` LTR)**: Switch languages with 1 click while keeping SHAs, diffs, and terminal telemetry strictly LTR monospace.
- **Strict Redaction by Default**: Raw credentials never leak into UI tables, AI prompts, or exported reports unless unredacted export is explicitly toggled on.

---

## Developer CLI & Build Instructions

```powershell
# Run full test suite
cd gitghost
python -m pytest -q

# Build standalone Windows Installer & Portable EXE
powershell -ExecutionPolicy Bypass -File scripts/build_desktop.ps1
```

---

## License

MIT License. See [LICENSE](LICENSE) for full details.
