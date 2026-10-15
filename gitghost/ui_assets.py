"""
UI Assets and Single Page Application for GitGhost Interactive Dashboard.
Fully self-contained dark-mode cybersecurity forensics dashboard with zero external CDN requirements.
"""

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GitGhost - Git Forensics & Secret Recovery</title>
  <style>
    :root {
      --bg-base: #090d16;
      --bg-surface: #0f172a;
      --bg-card: #141e33;
      --bg-card-hover: #1a2744;
      --border: #22324f;
      --border-accent: #3b82f6;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --cyan: #06b6d4;
      --magenta: #ec4899;
      --purple: #8b5cf6;
      --emerald: #10b981;
      --amber: #f59e0b;
      --rose: #f43f5e;
      --code-bg: #060911;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* Top Navigation */
    header {
      background: rgba(15, 23, 42, 0.95);
      backdrop-filter: blur(8px);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 50;
      padding: 0.75rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .brand-icon {
      font-size: 1.75rem;
      filter: drop-shadow(0 0 10px rgba(6, 182, 212, 0.6));
    }
    .brand-title {
      font-size: 1.25rem;
      font-weight: 800;
      letter-spacing: -0.025em;
      background: linear-gradient(135deg, #06b6d4, #a855f7);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand-tag {
      font-size: 0.65rem;
      padding: 0.15rem 0.5rem;
      background: rgba(139, 92, 246, 0.2);
      border: 1px solid rgba(139, 92, 246, 0.4);
      color: #c084fc;
      border-radius: 9999px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.05em;
    }

    /* Repository Control Bar */
    .control-panel {
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border);
      padding: 1rem 1.5rem;
    }
    .control-row {
      display: flex;
      gap: 0.75rem;
      align-items: center;
      flex-wrap: wrap;
    }
    .repo-input-wrapper {
      flex: 1;
      min-width: 280px;
      position: relative;
    }
    .repo-input {
      width: 100%;
      background: var(--bg-base);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 0.65rem 1rem 0.65rem 2.5rem;
      border-radius: 8px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
      transition: all 0.2s;
    }
    .repo-input:focus {
      outline: none;
      border-color: var(--cyan);
      box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.25);
    }
    .input-icon {
      position: absolute;
      left: 0.85rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      pointer-events: none;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.65rem 1.25rem;
      font-size: 0.875rem;
      font-weight: 600;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
      border: 1px solid transparent;
      user-select: none;
    }
    .btn-primary {
      background: linear-gradient(135deg, #06b6d4, #0284c7);
      color: #ffffff;
      box-shadow: 0 4px 12px rgba(6, 182, 212, 0.25);
    }
    .btn-primary:hover {
      box-shadow: 0 6px 18px rgba(6, 182, 212, 0.4);
      filter: brightness(1.1);
    }
    .btn-primary:active { transform: translateY(1px); }
    .btn-secondary {
      background: var(--bg-card);
      border-color: var(--border);
      color: var(--text-main);
    }
    .btn-secondary:hover {
      background: var(--bg-card-hover);
      border-color: #3b82f6;
    }
    .btn-danger {
      background: rgba(244, 63, 94, 0.15);
      border-color: rgba(244, 63, 94, 0.4);
      color: #fda4af;
    }
    .btn-danger:hover {
      background: rgba(244, 63, 94, 0.25);
    }

    .settings-dropdown-toggle {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 0.65rem;
      border-radius: 8px;
      cursor: pointer;
    }
    .settings-dropdown-toggle:hover {
      color: var(--text-main);
      border-color: var(--cyan);
    }

    .scan-options-row {
      display: flex;
      gap: 1.5rem;
      margin-top: 0.85rem;
      padding-top: 0.85rem;
      border-top: 1px dashed var(--border);
      font-size: 0.825rem;
      color: var(--text-muted);
      align-items: center;
      flex-wrap: wrap;
    }
    .option-group {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .select-input {
      background: var(--bg-base);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 0.3rem 0.6rem;
      border-radius: 6px;
      font-size: 0.825rem;
    }

    /* Main Container */
    main {
      flex: 1;
      padding: 1.5rem;
      max-width: 1440px;
      width: 100%;
      margin: 0 auto;
    }

    /* Dashboard Metrics Grid */
    .metrics-grid {
      display: grid;
      grid-template-columns: 280px 1fr;
      gap: 1.25rem;
      margin-bottom: 1.5rem;
    }
    @media (max-width: 900px) {
      .metrics-grid { grid-template-columns: 1fr; }
    }

    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }

    /* Score Card */
    .score-card {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .score-gauge-wrapper {
      position: relative;
      width: 150px;
      height: 150px;
      margin: 0.5rem auto;
    }
    .score-gauge-svg {
      transform: rotate(-90deg);
      width: 100%;
      height: 100%;
    }
    .gauge-bg {
      stroke: var(--border);
      stroke-width: 10;
      fill: none;
    }
    .gauge-progress {
      stroke: var(--cyan);
      stroke-width: 10;
      stroke-linecap: round;
      fill: none;
      stroke-dasharray: 440;
      stroke-dashoffset: 440;
      transition: stroke-dashoffset 1s ease-out, stroke 0.5s;
    }
    .score-text-overlay {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .score-number {
      font-size: 2.25rem;
      font-weight: 800;
      color: var(--text-main);
      line-height: 1;
    }
    .score-grade {
      font-size: 0.85rem;
      font-weight: 700;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      margin-top: 0.25rem;
      background: rgba(6, 182, 212, 0.15);
      color: var(--cyan);
    }
    .score-verdict {
      font-size: 0.825rem;
      color: var(--text-muted);
      margin-top: 0.5rem;
      font-weight: 500;
    }

    /* Stat Cards */
    .stat-cards-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      height: 100%;
    }
    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: border-color 0.2s;
    }
    .stat-card:hover { border-color: #38bdf8; }
    .stat-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      color: var(--text-muted);
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .stat-value {
      font-size: 2rem;
      font-weight: 800;
      margin: 0.35rem 0;
      color: var(--text-main);
    }
    .stat-sub {
      font-size: 0.75rem;
      color: var(--text-muted);
    }

    /* Navigation Tabs */
    .tab-bar {
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.25rem;
      padding-bottom: 0.25rem;
    }
    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 0.9rem;
      font-weight: 600;
      padding: 0.65rem 1.15rem;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.2s;
    }
    .tab-btn:hover {
      color: var(--text-main);
      background: var(--bg-card);
    }
    .tab-btn.active {
      color: var(--cyan);
      background: rgba(6, 182, 212, 0.12);
      border: 1px solid rgba(6, 182, 212, 0.3);
    }
    .tab-pill {
      font-size: 0.7rem;
      padding: 0.1rem 0.45rem;
      border-radius: 9999px;
      background: var(--bg-card-hover);
      color: var(--text-muted);
    }
    .tab-btn.active .tab-pill {
      background: rgba(6, 182, 212, 0.3);
      color: #67e8f9;
    }

    /* Table Styles */
    .table-container {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--bg-surface);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.85rem;
    }
    th {
      background: var(--bg-card);
      color: var(--text-muted);
      padding: 0.75rem 1rem;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.7rem;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 0.85rem 1rem;
      border-bottom: 1px solid rgba(34, 50, 79, 0.6);
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(30, 41, 59, 0.4); }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      font-size: 0.725rem;
      font-weight: 700;
      padding: 0.2rem 0.55rem;
      border-radius: 6px;
      letter-spacing: 0.025em;
      text-transform: uppercase;
    }
    .badge-critical {
      background: rgba(244, 63, 94, 0.18);
      border: 1px solid rgba(244, 63, 94, 0.5);
      color: #fda4af;
    }
    .badge-high {
      background: rgba(245, 158, 11, 0.18);
      border: 1px solid rgba(245, 158, 11, 0.5);
      color: #fcd34d;
    }
    .badge-medium {
      background: rgba(6, 182, 212, 0.18);
      border: 1px solid rgba(6, 182, 212, 0.5);
      color: #67e8f9;
    }
    .badge-low {
      background: rgba(16, 185, 129, 0.18);
      border: 1px solid rgba(16, 185, 129, 0.5);
      color: #6ee7b7;
    }

    .code-badge {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.8rem;
      background: var(--code-bg);
      border: 1px solid var(--border);
      padding: 0.2rem 0.45rem;
      border-radius: 4px;
      color: #38bdf8;
    }

    /* Secret masked snippet */
    .secret-masked {
      font-family: ui-monospace, monospace;
      background: rgba(245, 158, 11, 0.12);
      border: 1px dashed rgba(245, 158, 11, 0.35);
      color: #fde68a;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      display: inline-block;
      max-width: 320px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    /* Modal / Inspector Drawer */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(4px);
      z-index: 100;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .modal-box {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      width: 100%;
      max-width: 800px;
      max-height: 90vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
      animation: modalFadeIn 0.2s ease-out;
    }
    @keyframes modalFadeIn {
      from { opacity: 0; transform: scale(0.96); }
      to { opacity: 1; transform: scale(1); }
    }
    .modal-header {
      padding: 1.25rem 1.5rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .modal-body {
      padding: 1.5rem;
      overflow-y: auto;
      flex: 1;
    }
    .modal-footer {
      padding: 1rem 1.5rem;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: flex-end;
      gap: 0.75rem;
    }

    /* Code block inside modal */
    .code-view {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.825rem;
      color: #e2e8f0;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      margin-top: 0.75rem;
    }

    /* Remediation Commands */
    .command-box {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.85rem 1rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      margin: 0.5rem 0 1rem;
    }
    .command-text {
      font-family: ui-monospace, monospace;
      font-size: 0.85rem;
      color: #38bdf8;
      overflow-x: auto;
      white-space: nowrap;
    }

    /* Toast Notification */
    .toast {
      position: fixed;
      bottom: 2rem;
      right: 2rem;
      background: var(--bg-card);
      border: 1px solid var(--border-accent);
      color: var(--text-main);
      padding: 0.75rem 1.25rem;
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
      z-index: 200;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-size: 0.875rem;
      opacity: 0;
      transform: translateY(10px);
      transition: all 0.25s ease;
      pointer-events: none;
    }
    .toast.show {
      opacity: 1;
      transform: translateY(0);
      pointer-events: auto;
    }

    /* Live Progress Bar */
    .scan-progress-container {
      display: none;
      margin-top: 1rem;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem 1rem;
    }
    .scan-progress-bar {
      height: 6px;
      width: 100%;
      background: var(--border);
      border-radius: 3px;
      overflow: hidden;
      margin-top: 0.5rem;
    }
    .scan-progress-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, #06b6d4, #a855f7);
      transition: width 0.3s;
    }
    .spinner {
      display: inline-block;
      width: 14px;
      height: 14px;
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-top-color: #ffffff;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>

  <!-- Top Navigation Header -->
  <header>
    <div class="brand">
      <span class="brand-icon">👻</span>
      <div>
        <div class="brand-title">GitGhost</div>
        <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 500;">Git Object Forensics & Ghost Commit Hunter</div>
      </div>
      <span class="brand-tag">v0.1.0 Enterprise</span>
    </div>

    <div style="display: flex; gap: 0.5rem; align-items: center;">
      <button class="btn btn-secondary" onclick="exportSARIF()" title="Export SARIF 2.1.0 for GitHub Code Scanning">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
        Export SARIF
      </button>
      <button class="btn btn-secondary" onclick="installHook()" title="Install Pre-Push Protection Hook into repository">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
        Install Hook
      </button>
    </div>
  </header>

  <!-- Control & Repository Selection Bar -->
  <section class="control-panel">
    <div class="control-row">
      <div class="repo-input-wrapper">
        <svg class="input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
        <input type="text" id="repoPathInput" class="repo-input" placeholder="/path/to/target/git/repository" value=".">
      </div>
      <button class="btn btn-secondary" onclick="browseFolder()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 8 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/></svg>
        Browse
      </button>
      <button class="btn btn-primary" id="scanBtn" onclick="startScan()">
        <svg id="scanIcon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        <span id="scanBtnText">Scan Repository</span>
      </button>
      <button class="settings-dropdown-toggle" onclick="toggleSettings()" title="Scan Configuration">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="21" x2="4" y2="14"></line><line x1="4" y1="10" x2="4" y2="3"></line><line x1="12" y1="21" x2="12" y2="12"></line><line x1="12" y1="8" x2="12" y2="3"></line><line x1="20" y1="21" x2="20" y2="16"></line><line x1="20" y1="12" x2="20" y2="3"></line><line x1="1" y1="14" x2="7" y2="14"></line><line x1="9" y1="8" x2="15" y2="8"></line><line x1="17" y1="16" x2="23" y2="16"></line></svg>
      </button>
    </div>

    <!-- Scan Options Bar (Collapsible) -->
    <div id="scanOptions" class="scan-options-row" style="display: none;">
      <div class="option-group">
        <label for="aiProviderSelect">AI Triage Provider:</label>
        <select id="aiProviderSelect" class="select-input">
          <option value="heuristic" selected>Heuristic Rule-Engine (Offline / Fast)</option>
          <option value="auto">Auto-Detect Available LLM</option>
          <option value="gemini">Google Gemini</option>
          <option value="openai">OpenAI GPT-4o</option>
          <option value="anthropic">Anthropic Claude</option>
          <option value="ollama">Local Ollama</option>
          <option value="none">Disabled (No Triage)</option>
        </select>
      </div>
      <div class="option-group">
        <label for="entropyThreshold">Shannon Entropy Sensitivity:</label>
        <input type="range" id="entropyThreshold" min="3.0" max="5.5" step="0.1" value="4.0" oninput="document.getElementById('entropyVal').innerText = this.value">
        <span id="entropyVal" style="font-weight: 700; color: var(--cyan);">4.0</span>
      </div>
      <div class="option-group">
        <label><input type="checkbox" id="strictMode"> Strict CI Gatekeeper</label>
      </div>
    </div>

    <!-- Live Progress Bar -->
    <div id="scanProgressContainer" class="scan-progress-container">
      <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--cyan);">
        <span id="progressStatusText">Exhuming unreachable Git objects...</span>
        <span id="progressPctText">0%</span>
      </div>
      <div class="scan-progress-bar">
        <div id="scanProgressFill" class="scan-progress-fill"></div>
      </div>
    </div>
  </section>

  <!-- Main Content Dashboard -->
  <main>
    <!-- Top Metrics Overview -->
    <div class="metrics-grid">
      <!-- Hygiene Score Card -->
      <div class="card score-card">
        <div style="font-size: 0.75rem; text-transform: uppercase; font-weight: 700; color: var(--text-muted); letter-spacing: 0.05em;">Repo Hygiene Score</div>
        <div class="score-gauge-wrapper">
          <svg class="score-gauge-svg" viewBox="0 0 160 160">
            <circle class="gauge-bg" cx="80" cy="80" r="70"></circle>
            <circle id="gaugeCircle" class="gauge-progress" cx="80" cy="80" r="70"></circle>
          </svg>
          <div class="score-text-overlay">
            <span id="scoreNumber" class="score-number">100</span>
            <span id="scoreGrade" class="score-grade">A+ Pristine</span>
          </div>
        </div>
        <div id="scoreSummary" class="score-verdict">Ready for live repository forensics audit.</div>
      </div>

      <!-- Stat Cards -->
      <div class="stat-cards-row">
        <div class="stat-card">
          <div class="stat-header">
            <span>Dangling Commits</span>
            <span>👻</span>
          </div>
          <div id="statCommits" class="stat-value">0</div>
          <div class="stat-sub">Orphaned commits in .git/objects</div>
        </div>

        <div class="stat-card">
          <div class="stat-header">
            <span>Dangling Blobs</span>
            <span>📦</span>
          </div>
          <div id="statBlobs" class="stat-value">0</div>
          <div class="stat-sub">Unreachable file blobs</div>
        </div>

        <div class="stat-card">
          <div class="stat-header">
            <span>Secrets Detected</span>
            <span>🔑</span>
          </div>
          <div id="statSecrets" class="stat-value" style="color: var(--emerald);">0</div>
          <div id="statSecretsBreakdown" class="stat-sub">Strictly masked & triaged</div>
        </div>

        <div class="stat-card">
          <div class="stat-header">
            <span>Total Ghost Objects</span>
            <span>🪦</span>
          </div>
          <div id="statTotalObjects" class="stat-value">0</div>
          <div class="stat-sub">Evaluated via git fsck</div>
        </div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('findings')">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        Discovered Secrets & Findings
        <span id="tabCountFindings" class="tab-pill">0</span>
      </button>

      <button class="tab-btn" onclick="switchTab('graveyard')">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="m15 9-6 6"></path><path d="m9 9 6 6"></path></svg>
        Git Graveyard (Dangling Objects)
        <span id="tabCountGraveyard" class="tab-pill">0</span>
      </button>

      <button class="tab-btn" onclick="switchTab('scoring')">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg>
        Scorecard Deductions
        <span id="tabCountDeductions" class="tab-pill">0</span>
      </button>

      <button class="tab-btn" onclick="switchTab('remediation')">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path></svg>
        Remediation Playbook
      </button>
    </div>

    <!-- TAB 1: Findings Table -->
    <div id="tabFindings" class="tab-content">
      <div style="display: flex; justify-content: space-between; margin-bottom: 0.85rem; align-items: center; gap: 1rem; flex-wrap: wrap;">
        <div style="display: flex; gap: 0.5rem; align-items: center;">
          <input type="text" id="findingsFilter" placeholder="Filter findings..." class="select-input" style="width: 220px;" oninput="filterFindings()">
          <select id="severityFilter" class="select-input" onchange="filterFindings()">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
        <div style="font-size: 0.75rem; color: var(--text-muted);">
          🔒 Strict Redaction Active: Raw tokens are cryptographically masked before render.
        </div>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>Rule / Finding Type</th>
              <th>Masked Credential</th>
              <th>Location</th>
              <th>Entropy</th>
              <th>AI Triage Verdict</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="findingsTableBody">
            <tr>
              <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 3rem 1rem;">
                No scan run yet. Select a local Git repository and click <strong>Scan Repository</strong>.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 2: Graveyard (Dangling Commits & Blobs) -->
    <div id="tabGraveyard" class="tab-content" style="display: none;">
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem;">
        <!-- Dangling Commits Panel -->
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h3 style="font-size: 1rem; font-weight: 700; color: var(--magenta);">👻 Dangling Commits</h3>
            <span id="graveyardCommitCount" class="tab-pill">0 objects</span>
          </div>
          <div id="danglingCommitsList" style="display: flex; flex-direction: column; gap: 0.75rem; max-height: 520px; overflow-y: auto;">
            <div style="color: var(--text-muted); font-size: 0.85rem; text-align: center; padding: 2rem;">No dangling commits detected.</div>
          </div>
        </div>

        <!-- Dangling Blobs Panel -->
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h3 style="font-size: 1rem; font-weight: 700; color: var(--amber);">📦 Dangling Blobs</h3>
            <span id="graveyardBlobCount" class="tab-pill">0 objects</span>
          </div>
          <div id="danglingBlobsList" style="display: flex; flex-direction: column; gap: 0.75rem; max-height: 520px; overflow-y: auto;">
            <div style="color: var(--text-muted); font-size: 0.85rem; text-align: center; padding: 2rem;">No dangling blobs detected.</div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 3: Scorecard Deductions -->
    <div id="tabScoring" class="tab-content" style="display: none;">
      <div class="card">
        <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem; color: var(--cyan);">Repository Hygiene Deductions Breakdown</h3>
        <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1.25rem;">
          The GitGhost Hygiene Score is calculated from 100 points, penalizing orphaned secrets, unreachable commit accumulation, and threat recency.
        </p>
        <div id="deductionsList" style="display: flex; flex-direction: column; gap: 0.75rem;">
          <div style="color: var(--emerald); font-size: 0.875rem;">✨ No deductions. Repository is in pristine health!</div>
        </div>
      </div>
    </div>

    <!-- TAB 4: Remediation Playbook -->
    <div id="tabRemediation" class="tab-content" style="display: none;">
      <div class="card">
        <div style="background: rgba(244, 63, 94, 0.15); border: 1px solid rgba(244, 63, 94, 0.4); border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; color: #fecdd3; font-size: 0.875rem;">
          <strong>⚠️ Critical Credential Rotation Notice:</strong>
          <span id="remediationRotationWarning">Always rotate any compromised credentials with your identity provider or cloud dashboard before deleting git history objects.</span>
        </div>

        <h3 style="font-size: 1rem; font-weight: 700; margin-bottom: 0.5rem;">Targeted History Excision Recipes</h3>
        <div id="remediationStepsList">
          <!-- Steps populated dynamically -->
        </div>

        <h3 style="font-size: 1rem; font-weight: 700; margin-top: 1.5rem; margin-bottom: 0.5rem;">Automated Excision Scripts</h3>
        <div style="display: flex; gap: 0.5rem; margin-bottom: 0.75rem;">
          <button id="btnScriptBash" class="tab-btn active" style="padding: 0.4rem 0.8rem; font-size: 0.8rem;" onclick="switchScriptTab('bash')">Bash Script (.sh)</button>
          <button id="btnScriptPS" class="tab-btn" style="padding: 0.4rem 0.8rem; font-size: 0.8rem;" onclick="switchScriptTab('ps')">PowerShell Script (.ps1)</button>
        </div>
        <div id="bashScriptContainer" class="command-box" style="flex-direction: column; align-items: stretch;">
          <pre id="remediationBashScript" style="font-family: monospace; font-size: 0.8rem; overflow-x: auto; max-height: 250px; white-space: pre-wrap; color: #a5f3fc;"># Run scan to generate customized Bash script</pre>
          <div style="text-align: right; margin-top: 0.5rem;">
            <button class="btn btn-secondary" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;" onclick="copyScript('bash')">Copy Bash Script</button>
          </div>
        </div>
        <div id="psScriptContainer" class="command-box" style="flex-direction: column; align-items: stretch; display: none;">
          <pre id="remediationPSScript" style="font-family: monospace; font-size: 0.8rem; overflow-x: auto; max-height: 250px; white-space: pre-wrap; color: #a5f3fc;"># Run scan to generate customized PowerShell script</pre>
          <div style="text-align: right; margin-top: 0.5rem;">
            <button class="btn btn-secondary" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;" onclick="copyScript('ps')">Copy PowerShell Script</button>
          </div>
        </div>

        <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
          <div>
            <div style="font-weight: 700; font-size: 0.9rem;">Execute Live Safe Cleanup</div>
            <div style="font-size: 0.75rem; color: var(--text-muted);">Permanently prunes unreferenced objects with git reflog expire & git gc.</div>
          </div>
          <button class="btn btn-danger" onclick="confirmExecuteCleanup()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"></path><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path></svg>
            Execute Cleanup (Purge Unreachable)
          </button>
        </div>
      </div>
    </div>
  </main>

  <!-- Finding Detail Modal -->
  <div id="detailModal" class="modal-overlay">
    <div class="modal-box">
      <div class="modal-header">
        <div>
          <h3 id="modalTitle" style="font-size: 1.1rem; font-weight: 700;">Finding Details</h3>
          <div id="modalSubtitle" style="font-size: 0.75rem; color: var(--text-muted);">ID: SEC-0000</div>
        </div>
        <button onclick="closeModal()" style="background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 1.25rem;">✕</button>
      </div>
      <div class="modal-body">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
          <div>
            <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Severity & AI Verdict</div>
            <div id="modalSeverityBadge" style="margin-top: 0.25rem;"></div>
          </div>
          <div>
            <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Shannon Entropy</div>
            <div id="modalEntropyVal" style="font-weight: 700; margin-top: 0.25rem; color: var(--cyan);"></div>
          </div>
        </div>

        <div style="margin-bottom: 1rem;">
          <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">AI Technical Explanation</div>
          <div id="modalExplanation" style="font-size: 0.85rem; margin-top: 0.25rem; line-height: 1.4; color: var(--text-main);"></div>
        </div>

        <div style="margin-bottom: 1rem;">
          <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Recommended Security Action</div>
          <div id="modalAction" style="font-size: 0.85rem; margin-top: 0.25rem; color: #a5f3fc;"></div>
        </div>

        <div>
          <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Strictly Redacted Code Diff / Context</div>
          <pre id="modalCodeView" class="code-view"></pre>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeModal()">Close</button>
      </div>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast" class="toast">
    <span id="toastIcon">ℹ️</span>
    <span id="toastMessage">Notification message</span>
  </div>

  <!-- Client-Side Dashboard Logic -->
  <script>
    let currentAuditData = null;
    let allFindings = [];

    // Folder selection
    async function browseFolder() {
      try {
        const res = await fetch('/api/browse', { method: 'POST' });
        const data = await res.json();
        if (data && data.folder) {
          document.getElementById('repoPathInput').value = data.folder;
          showToast('Folder selected: ' + data.folder, '📁');
        }
      } catch (err) {
        console.error('Browse folder error:', err);
      }
    }

    function toggleSettings() {
      const panel = document.getElementById('scanOptions');
      panel.style.display = panel.style.display === 'none' ? 'flex' : 'none';
    }

    function switchTab(tabName) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(content => content.style.display = 'none');

      if (tabName === 'findings') {
        document.getElementById('tabFindings').style.display = 'block';
        event.currentTarget.classList.add('active');
      } else if (tabName === 'graveyard') {
        document.getElementById('tabGraveyard').style.display = 'block';
        event.currentTarget.classList.add('active');
      } else if (tabName === 'scoring') {
        document.getElementById('tabScoring').style.display = 'block';
        event.currentTarget.classList.add('active');
      } else if (tabName === 'remediation') {
        document.getElementById('tabRemediation').style.display = 'block';
        event.currentTarget.classList.add('active');
      }
    }

    // Trigger Scan
    async function startScan() {
      const repoPath = document.getElementById('repoPathInput').value.trim() || '.';
      const aiProvider = document.getElementById('aiProviderSelect').value;
      const entropyThreshold = parseFloat(document.getElementById('entropyThreshold').value);
      const strict = document.getElementById('strictMode').checked;

      const scanBtn = document.getElementById('scanBtn');
      const scanBtnText = document.getElementById('scanBtnText');
      const progressContainer = document.getElementById('scanProgressContainer');
      const progressFill = document.getElementById('scanProgressFill');
      const progressStatus = document.getElementById('progressStatusText');
      const progressPct = document.getElementById('progressPctText');

      scanBtn.disabled = true;
      scanBtnText.innerText = 'Scanning...';
      progressContainer.style.display = 'block';
      progressFill.style.width = '20%';
      progressStatus.innerText = 'Exhuming object graveyard (.git/objects)...';
      progressPct.innerText = '20%';

      try {
        const payload = {
          repo_path: repoPath,
          ai_provider: aiProvider,
          entropy_threshold: entropyThreshold,
          strict: strict
        };

        // Animate fake progress steps while backend runs live forensics
        const pInterval = setInterval(() => {
          let curr = parseInt(progressFill.style.width);
          if (curr < 85) {
            curr += 15;
            progressFill.style.width = curr + '%';
            progressPct.innerText = curr + '%';
            if (curr === 50) progressStatus.innerText = 'Scanning with Shannon entropy & redacting secrets...';
            if (curr === 75) progressStatus.innerText = 'Running AI triage & calculating hygiene score...';
          }
        }, 300);

        const response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        clearInterval(pInterval);
        progressFill.style.width = '100%';
        progressPct.innerText = '100%';
        progressStatus.innerText = 'Forensics audit complete.';

        setTimeout(() => {
          progressContainer.style.display = 'none';
        }, 800);

        if (!response.ok) {
          const errData = await response.json();
          alert('Scan Error: ' + (errData.error || response.statusText));
          return;
        }

        const data = await response.json();
        currentAuditData = data;
        renderDashboard(data);
        showToast('Forensics scan completed successfully!', '✅');

      } catch (err) {
        alert('Network/Server Error: ' + err.message);
      } finally {
        scanBtn.disabled = false;
        scanBtnText.innerText = 'Scan Repository';
      }
    }

    function renderDashboard(data) {
      // 1. Score Gauge
      const score = data.hygiene_score.score;
      const scoreGrade = data.hygiene_score.grade;
      const scoreSummary = data.hygiene_score.summary;

      document.getElementById('scoreNumber').innerText = score;
      document.getElementById('scoreGrade').innerText = scoreGrade;
      document.getElementById('scoreSummary').innerText = scoreSummary;

      // 440 circumference
      const offset = 440 - (440 * (score / 100));
      const gaugeCircle = document.getElementById('gaugeCircle');
      gaugeCircle.style.strokeDashoffset = offset;

      if (score >= 90) {
        gaugeCircle.style.stroke = 'var(--emerald)';
        document.getElementById('scoreGrade').style.color = 'var(--emerald)';
      } else if (score >= 75) {
        gaugeCircle.style.stroke = 'var(--cyan)';
        document.getElementById('scoreGrade').style.color = 'var(--cyan)';
      } else if (score >= 60) {
        gaugeCircle.style.stroke = 'var(--amber)';
        document.getElementById('scoreGrade').style.color = 'var(--amber)';
      } else {
        gaugeCircle.style.stroke = 'var(--rose)';
        document.getElementById('scoreGrade').style.color = 'var(--rose)';
      }

      // 2. Stat Cards
      document.getElementById('statCommits').innerText = data.dangling_commits.length;
      document.getElementById('statBlobs').innerText = data.dangling_blobs.length;
      document.getElementById('statTotalObjects').innerText = data.total_objects_scanned;

      allFindings = data.findings || [];
      document.getElementById('statSecrets').innerText = allFindings.length;
      document.getElementById('statSecrets').style.color = allFindings.length > 0 ? 'var(--rose)' : 'var(--emerald)';
      document.getElementById('statSecretsBreakdown').innerText = `${data.hygiene_score.critical_findings_count} critical, ${data.hygiene_score.high_findings_count} high`;

      document.getElementById('tabCountFindings').innerText = allFindings.length;
      document.getElementById('tabCountGraveyard').innerText = data.dangling_commits.length + data.dangling_blobs.length;
      document.getElementById('tabCountDeductions').innerText = (data.hygiene_score.deductions || []).length;

      // 3. Render Findings Table
      renderFindingsTable(allFindings);

      // 4. Render Graveyard
      renderGraveyard(data.dangling_commits, data.dangling_blobs);

      // 5. Render Deductions
      renderDeductions(data.hygiene_score.deductions || []);

      // 6. Render Remediation
      renderRemediation(data.remediation);
    }

    function renderFindingsTable(findings) {
      const tbody = document.getElementById('findingsTableBody');
      tbody.innerHTML = '';

      if (!findings || findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--emerald); padding: 2.5rem 1rem;">
          ✨ No credentials or secret patterns detected in unreachable objects.
        </td></tr>`;
        return;
      }

      findings.forEach(f => {
        const tr = document.createElement('tr');
        const sevClass = f.triage_severity === 'Critical' ? 'badge-critical' :
                         (f.triage_severity === 'High' ? 'badge-high' :
                         (f.triage_severity === 'Medium' ? 'badge-medium' : 'badge-low'));

        tr.innerHTML = `
          <td><span class="code-badge">${f.finding_id}</span></td>
          <td><span class="badge ${sevClass}">${f.triage_severity || f.severity_estimate}</span></td>
          <td style="font-weight: 600;">${f.rule_name}</td>
          <td><span class="secret-masked" title="${f.masked_value}">${f.masked_value}</span></td>
          <td><span class="code-badge">${f.file_path}:${f.line_number}</span></td>
          <td style="font-weight: 700; color: var(--cyan);">${f.entropy.toFixed(2)}</td>
          <td>
            <div style="font-size: 0.8rem; font-weight: 600;">${f.is_false_positive ? '🟢 False Positive' : '🔴 True Leak (Risk: ' + (f.triage_risk_score || 'N/A') + ')'}</div>
            <div style="font-size: 0.7rem; color: var(--text-muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${f.triage_explanation || ''}</div>
          </td>
          <td>
            <button class="btn btn-secondary" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;" onclick='openDetailModal(${JSON.stringify(f)})'>Inspect</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    function filterFindings() {
      const q = document.getElementById('findingsFilter').value.toLowerCase();
      const sev = document.getElementById('severityFilter').value;

      const filtered = allFindings.filter(f => {
        const matchesQuery = f.rule_name.toLowerCase().includes(q) ||
                             f.file_path.toLowerCase().includes(q) ||
                             f.finding_id.toLowerCase().includes(q) ||
                             (f.commit_hash && f.commit_hash.toLowerCase().includes(q));
        const matchesSev = (sev === 'ALL') ||
                           ((f.triage_severity || f.severity_estimate).toUpperCase() === sev);
        return matchesQuery && matchesSev;
      });

      renderFindingsTable(filtered);
    }

    function renderGraveyard(commits, blobs) {
      const commitList = document.getElementById('danglingCommitsList');
      commitList.innerHTML = '';
      document.getElementById('graveyardCommitCount').innerText = commits.length + ' commits';

      if (!commits || commits.length === 0) {
        commitList.innerHTML = '<div style="color: var(--emerald); font-size: 0.85rem; text-align: center; padding: 2rem;">No dangling commits!</div>';
      } else {
        commits.forEach(c => {
          const item = document.createElement('div');
          item.style.background = 'var(--bg-card)';
          item.style.border = '1px solid var(--border)';
          item.style.borderRadius = '8px';
          item.style.padding = '0.75rem 1rem';
          item.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span class="code-badge" style="color: var(--magenta);">commit ${c.commit_hash.substring(0, 10)}</span>
              <span style="font-size: 0.75rem; color: var(--text-muted);">${c.date ? c.date.substring(0, 10) : ''}</span>
            </div>
            <div style="font-size: 0.85rem; font-weight: 600; margin: 0.35rem 0;">"${c.message ? c.message.split('\n')[0] : 'No message'}"</div>
            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.75rem; color: var(--text-muted);">
              <span>Author: ${c.author || 'Unknown'}</span>
              <span>${c.changed_files ? c.changed_files.length : 0} file(s) changed</span>
            </div>
          `;
          commitList.appendChild(item);
        });
      }

      const blobList = document.getElementById('danglingBlobsList');
      blobList.innerHTML = '';
      document.getElementById('graveyardBlobCount').innerText = blobs.length + ' blobs';

      if (!blobs || blobs.length === 0) {
        blobList.innerHTML = '<div style="color: var(--emerald); font-size: 0.85rem; text-align: center; padding: 2rem;">No dangling blobs!</div>';
      } else {
        blobs.forEach(b => {
          const item = document.createElement('div');
          item.style.background = 'var(--bg-card)';
          item.style.border = '1px solid var(--border)';
          item.style.borderRadius = '8px';
          item.style.padding = '0.75rem 1rem';
          item.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span class="code-badge" style="color: var(--amber);">${b.blob_hash.substring(0, 10)}</span>
              <span style="font-size: 0.75rem; color: var(--text-muted);">${b.size} bytes</span>
            </div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.35rem;">
              Path: ${b.associated_path || 'Detached Unlinked Blob'}
            </div>
          `;
          blobList.appendChild(item);
        });
      }
    }

    function renderDeductions(deductions) {
      const list = document.getElementById('deductionsList');
      list.innerHTML = '';

      if (!deductions || deductions.length === 0) {
        list.innerHTML = '<div style="color: var(--emerald); font-size: 0.875rem;">✨ No deductions. Repository is in pristine health!</div>';
        return;
      }

      deductions.forEach(d => {
        const item = document.createElement('div');
        item.style.background = 'var(--bg-card)';
        item.style.border = '1px solid var(--border)';
        item.style.borderRadius = '8px';
        item.style.padding = '0.85rem 1rem';
        item.style.display = 'flex';
        item.style.justifyContent = 'space-between';
        item.style.alignItems = 'center';

        item.innerHTML = `
          <div>
            <div style="font-weight: 600; font-size: 0.875rem;">${d.category}</div>
            <div style="font-size: 0.775rem; color: var(--text-muted);">${d.reason}</div>
          </div>
          <span class="badge badge-critical" style="font-size: 0.8rem;">-${d.points} pts</span>
        `;
        list.appendChild(item);
      });
    }

    function renderRemediation(rem) {
      if (!rem) return;
      document.getElementById('remediationRotationWarning').innerText = rem.rotation_warning || 'Rotate compromised credentials immediately.';

      const container = document.getElementById('remediationStepsList');
      container.innerHTML = '';

      (rem.steps || []).forEach(s => {
        const card = document.createElement('div');
        card.style.marginBottom = '1.25rem';
        card.innerHTML = `
          <div style="font-weight: 700; font-size: 0.9rem; color: var(--amber); margin-bottom: 0.35rem;">
            Step ${s.order}: ${s.title}
          </div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem;">
            ${s.description}
          </div>
          ${(s.commands || []).map(cmd => `
            <div class="command-box">
              <span class="command-text">$ ${cmd}</span>
              <button class="btn btn-secondary" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;" onclick="copyCommand('${cmd.replace(/'/g, "\\'")}')">Copy</button>
            </div>
          `).join('')}
        `;
        container.appendChild(card);
      });

      if (rem.bash_script) {
        document.getElementById('remediationBashScript').innerText = rem.bash_script;
      }
      if (rem.powershell_script) {
        document.getElementById('remediationPSScript').innerText = rem.powershell_script;
      }
    }

    function switchScriptTab(type) {
      if (type === 'bash') {
        document.getElementById('bashScriptContainer').style.display = 'flex';
        document.getElementById('psScriptContainer').style.display = 'none';
        document.getElementById('btnScriptBash').classList.add('active');
        document.getElementById('btnScriptPS').classList.remove('active');
      } else {
        document.getElementById('bashScriptContainer').style.display = 'none';
        document.getElementById('psScriptContainer').style.display = 'flex';
        document.getElementById('btnScriptBash').classList.remove('active');
        document.getElementById('btnScriptPS').classList.add('active');
      }
    }

    function copyScript(type) {
      const text = type === 'bash'
        ? document.getElementById('remediationBashScript').innerText
        : document.getElementById('remediationPSScript').innerText;
      navigator.clipboard.writeText(text);
      showToast(`${type === 'bash' ? 'Bash' : 'PowerShell'} script copied to clipboard!`, '📋');
    }

    function copyCommand(cmd) {
      navigator.clipboard.writeText(cmd);
      showToast('Command copied to clipboard!', '📋');
    }

    function openDetailModal(f) {
      document.getElementById('modalTitle').innerText = f.rule_name;
      document.getElementById('modalSubtitle').innerText = `ID: ${f.finding_id} | Path: ${f.file_path}:${f.line_number}`;

      const sev = f.triage_severity || f.severity_estimate;
      const sevClass = sev === 'Critical' ? 'badge-critical' : (sev === 'High' ? 'badge-high' : 'badge-medium');
      document.getElementById('modalSeverityBadge').innerHTML = `<span class="badge ${sevClass}">${sev}</span>`;
      document.getElementById('modalEntropyVal').innerText = (f.entropy || 0).toFixed(2);
      document.getElementById('modalExplanation').innerText = f.triage_explanation || 'No AI explanation available.';
      document.getElementById('modalAction').innerText = f.triage_action || 'Rotate credentials and prune repository.';
      document.getElementById('modalCodeView').innerText = f.context_line || f.masked_value;

      document.getElementById('detailModal').style.display = 'flex';
    }

    function closeModal() {
      document.getElementById('detailModal').style.display = 'none';
    }

    // Pre-push hook installer
    async function installHook() {
      const repoPath = document.getElementById('repoPathInput').value.trim() || '.';
      try {
        const res = await fetch('/api/hook', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repo_path: repoPath })
        });
        const data = await res.json();
        if (data.success) {
          showToast('Pre-push hook installed successfully!', '🛡️');
        } else {
          alert('Failed to install hook: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    // Export SARIF report
    async function exportSARIF() {
      if (!currentAuditData) {
        alert('Please run a scan first before exporting SARIF.');
        return;
      }
      const repoPath = document.getElementById('repoPathInput').value.trim() || '.';
      try {
        const res = await fetch('/api/export', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repo_path: repoPath, format: 'sarif' })
        });
        const data = await res.json();
        if (data.success) {
          showToast('SARIF report exported to: ' + data.file_path, '📄');
        } else {
          alert('Export error: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    // Execute cleanup
    async function confirmExecuteCleanup() {
      if (!confirm('Are you sure you want to permanently excise all unreferenced objects?\n\nThis executes:\ngit reflog expire --expire=now --all\ngit gc --prune=now --aggressive')) {
        return;
      }
      const repoPath = document.getElementById('repoPathInput').value.trim() || '.';
      try {
        const res = await fetch('/api/cleanup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repo_path: repoPath })
        });
        const data = await res.json();
        if (data.success) {
          showToast('Unreferenced objects permanently excised!', '🧹');
          // Re-scan repository
          startScan();
        } else {
          alert('Cleanup failed: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    function showToast(message, icon = 'ℹ️') {
      const toast = document.getElementById('toast');
      document.getElementById('toastIcon').innerText = icon;
      document.getElementById('toastMessage').innerText = message;
      toast.classList.add('show');
      setTimeout(() => { toast.classList.remove('show'); }, 3500);
    }
  </script>
</body>
</html>
"""
