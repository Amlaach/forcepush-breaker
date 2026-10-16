<div align="center">

```
   ██████╗ ██╗████████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║╚══██╔══╝██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗██║   ██║   ██║  ███╗███████║██║   ██║███████╗   ██║   
  ██║   ██║██║   ██║   ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
  ╚██████╔╝██║   ██║   ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
   ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
```

# 👻 GitGhost

### **Enterprise Git Object Forensics, Dangling Secret Hunter & Excision Playbook**

*Unearthing what `git reset --hard` left behind in your `.git` graveyard.*

[![CI](https://github.com/your-username/gitghost/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/gitghost/actions)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/gitghost/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-purple.svg)](https://sarifweb.azurewebsites.net/)
[![UI Desktop & Web](https://img.shields.io/badge/UI-Desktop%20%26%20Web-cyan.svg)](#-interactive-desktop--web-uiux)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/your-username/gitghost/pulls)

</div>

---

## 🪝 The Hook: Why GitGhost?

Developers frequently believe that running commands like:
```bash
git reset --hard HEAD~1
git rebase -i
git branch -D feature/leaked-credentials
```
permanently removes committed secrets or private configurations from their repository.

**In reality, Git does NOT delete them.**

Git preserves these objects as **Dangling Commits** and **Unreachable Blobs** inside the local object store (`.git/objects/`). They remain quietly on disk, accessible through object hashes, surviving in developer workstations, CI/CD caches, and backup snapshots.

**GitGhost** is a specialized forensics and security engineering tool for local repositories and CI/CD pipelines. It exhuming orphaned objects, calculates Shannon entropy, strictly redacts credentials, performs AI context triage, grades repository hygiene, and provides targeted remediation recipes.

---

## 📊 How It Works: The Ghost Object Lifecycle

```mermaid
flowchart TD
    A["Developer accidentally commits .env or API keys"] --> B["Developer runs 'git reset --hard HEAD~1'"]
    B --> C["'git log' appears completely clean"]
    C -. Secrets linger in database .-> D[".git/objects (Dangling Commits & Blobs)"]
    D --> E["GitGhost Forensics Engine (git fsck)"]
    E --> F["Shannon Entropy & Regex Detector"]
    F --> G["Strict Redaction Layer (Zero Raw Exposure)"]
    G --> H["AI Context Triage (LLM / Heuristic Engine)"]
    H --> I["Repository Hygiene Scorecard (0-100)"]
    I --> J["Remediation & Excision Playbook (git gc / filter-repo)"]
```

---

## ✨ Core Features

- **🌐 Remote GitHub Forensics & Smart Mirror Cloner (`github_remote.py`)**:
  - Accepts remote GitHub URLs (`https://github.com/owner/repo`, `git@github.com:owner/repo.git`, or `owner/repo`) directly in the UI and CLI.
  - Queries the GitHub REST API (`/events`, `/pulls?state=closed`, `/commits/{sha}`) to detect **Force-Push overwrites**, deleted branch refs, and unmerged PR commits (`before` SHAs).
  - Performs a smart `--mirror` clone (`+refs/pull/*:refs/pull/*`), explicitly fetches orphaned commit SHAs from GitHub's object store, and guarantees automatic temporary workspace cleanup.

- **🔍 Live Object-Store Forensics (`git_forensics.py`)**:
  - Supports both standard working-tree `.git` repositories and bare/mirror repositories.
  - Traverses the object database using `git fsck --full --no-reflogs --unreachable --lost-found`.
  - Exhumes unreachable commits, trees, and blobs disconnected from active refs (`HEAD`, branches, tags) while enforcing strict resource bounds (`MAX_TEXT_SCAN_BYTES = 10MB`) and command timeouts.

- **🛡️ Multi-Line Diff Attribution & Strict Secret Redaction (`redactor.py`, `pipeline.py`)**:
  - Parses unified `diff --git` and `@@ -a,b +c,d @@` hunk headers per file for exact file path and line number attribution across multi-file commits.
  - Computes Shannon entropy and evaluates 14+ regex rules for AWS keys, GitHub/GitLab tokens, Slack webhooks, Private Keys, Database URIs, and `.env` secrets.
  - Generates multi-line **Redacted Diff Hunks** (`diff_hunk`) and stores strictly redacted commit diffs (`redacted_diff`) and blob contents (`redacted_content`).

- **📦 Safe File & Commit Recovery Engine (`recovery.py`)**:
  - Recovers deleted files (`recover_commit_file`), unified commit patches (`recover_commit_diff`), and detached blobs (`recover_blob`).
  - Generates a self-contained **Recovery ZIP Bundle** (`gitghost_recovery_bundle.zip`) containing Markdown/JSON/SARIF reports, commit `.patch` files, and recovered files.
  - **Redacted by Default, Raw on Explicit Request**: Defaults to strict secret redaction (`include_raw=False`), with an explicit opt-in (`include_raw=True` / `--include-raw`) when full unredacted file recovery is required.

- **🤖 AI-Powered Context Triage (`ai_triage.py`)**:
  - Distinguishes real active leaks from false positives (test fixtures, documentation samples, mock keys).
  - Multi-provider support: Google Gemini, OpenAI GPT-4o, Anthropic Claude, local Ollama, or built-in offline Heuristics.

- **📈 Repo Hygiene Scorecard (`scoring.py`) & Remediation Playbook (`remediation.py`)**:
  - Computes a 0–100 repository hygiene grade with itemized deductions.
  - Generates customized `git filter-repo` and `git gc --prune=now --aggressive` excision scripts.

---

## 🖥️ Interactive Desktop & Web UI/UX

GitGhost includes a self-contained dark-mode cybersecurity dashboard powered by an asynchronous background job manager:

```bash
# Launch native desktop application (Edge WebView2 / PySide6)
gitghost ui

# Or launch in your default web browser
gitghost ui --web

# Specify custom port or target repository
gitghost ui /path/to/repo --port 8765
```

### Dashboard Highlights:
- **Remote & Local Target Bar**: Paste any GitHub repository URL (`https://github.com/owner/repo`) or local path, with optional in-memory GitHub token support.
- **Real-Time Asynchronous Progress Polling**: Background scan worker (`POST /api/scan/start` + `GET /api/scan/status`) streams live cloning, object exhumation, and secret scanning progress without browser timeouts.
- **Syntax-Highlighted Redacted Diff Viewer**: Inspect multi-line unified diffs with highlighted additions (`+`), deletions (`-`), hunk headers (`@@`), and masked credential badges.
- **Graveyard & Force-Push Explorer**: Browse GitHub force-push/branch-deletion events, inspect full commit diffs, and recover individual deleted files or `.patch` diffs in one click.
- **One-Click Download Center**: Directly download the full **Recovery Bundle (.ZIP)**, **JSON**, **Markdown**, or **SARIF 2.1.0** reports from the browser.

---

## 🚀 Quickstart & CLI Usage

### ⚡ 5-Second Instant Sandbox Demo

Test GitGhost in 5 seconds without touching any real repositories:

```bash
gitghost demo
```

### Live Forensics Scan (Local & Remote GitHub)

```bash
# Audit local repository with offline heuristic triage
gitghost scan .

# Audit a remote GitHub repository (smart mirror clone + force-push event analysis)
gitghost scan https://github.com/owner/repo --github-token ghp_your_token

# Export full Recovery ZIP Bundle (strictly redacted by default)
gitghost scan https://github.com/owner/repo --recover-zip recovery_bundle.zip

# Export unredacted (raw) files in the Recovery ZIP Bundle when full recovery is needed
gitghost scan . --recover-zip raw_recovery_bundle.zip --include-raw

# CI/CD mode: fail pipeline if hygiene score < 70 or critical leaks exist
gitghost scan . --strict --format sarif --output audit_report.sarif
```

### Install Pre-Push Protection Hook & Safe Cleanup

```bash
# Install pre-push hook
gitghost install-hook .

# Preview and execute physical purge of unreferenced local objects
gitghost clean --dry-run
gitghost clean
```

---

## 🔒 Security & Privacy Guarantee

1. **In-Memory Ephemeral GitHub Token**: Tokens supplied in the UI or CLI are held strictly in memory for API/clone headers, never written to `.git/config`, and automatically scrubbed from all logs and error messages.
2. **Never Sends Raw Secrets to AI**: The redaction engine runs **prior** to AI prompt construction. LLMs only ever observe masked placeholders (e.g. `AKIA************MPLE`).
3. **Resource Limits & Guaranteed Cleanup**: Enforces execution timeouts, skips binary or oversized blobs (`>10MB`), and cleans up temporary mirror clones inside `try/finally` blocks.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for full details.

