/* UnForce (ForcePush-Breaker) — Cyber-Forensics Studio Frontend Engine */
"use strict";

let currentLang = localStorage.getItem("unforce_lang") || "he";
let API_BASE = window.UNFORCE_API_BASE || "";
let currentScanData = null;
let activeRepoTarget = "";
let activeGithubHtmlUrl = "";
let activeView = "overview";
let activeCommitSubtab = "dangling";
let activeCommitObj = null;
let activePreviewedFile = null;
let activeScriptLang = "bash";
let activeModalContext = null;
let ephemeralSession = { aiKey: "", ghToken: "", ghAutoDetected: false };
let seenPhaseLogs = new Set();
let cmdSelectedIndex = 0;
let cachedTimeMachineEntries = [];

function t(key) {
  const dict = (window.UNFORCE_I18N && window.UNFORCE_I18N[currentLang]) || window.UNFORCE_I18N.he;
  return dict[key] || (window.UNFORCE_I18N.en && window.UNFORCE_I18N.en[key]) || key;
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* ---- Dynamic Backend URL Resolution (Instant file:// + HTTP compatibility) ---- */
async function ensureApiBase() {
  if (API_BASE) return API_BASE;
  if (window.location.protocol === "http:" || window.location.protocol === "https:") {
    API_BASE = window.location.origin;
    return API_BASE;
  }
  if (window.unforceDesktop && typeof window.unforceDesktop.getBackendUrl === "function") {
    const url = await window.unforceDesktop.getBackendUrl();
    if (url) {
      API_BASE = url.replace(/\/+$/, "");
      return API_BASE;
    }
  }
  return "";
}

async function apiFetch(endpoint, options = {}) {
  const base = await ensureApiBase();
  return fetch(`${base}${endpoint}`, options);
}

/* ---- GitHub URL Parsing & Validation (ONLY Allowed Target Method) ---- */
function parseGitHubRepoInput(rawInput) {
  const raw = String(rawInput || "").trim();
  if (!raw) return null;
  if (/^[a-zA-Z]:[\\/]/.test(raw) || raw.startsWith("/") || raw.startsWith("\\") || raw.startsWith(".")) {
    return null;
  }
  let m = raw.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#].*)?$/i);
  if (!m) {
    m = raw.match(/^git@github\.com:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i);
  }
  if (!m) {
    m = raw.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  }
  if (!m) return null;
  const owner = m[1];
  const repo = m[2].replace(/\.git$/i, "");
  const reserved = ["settings", "orgs", "organizations", "users", "marketplace", "explore", "topics", "login"];
  if (!owner || !repo || reserved.includes(owner.toLowerCase())) return null;
  return {
    owner,
    repo,
    slug: `${owner}/${repo}`,
    cleanUrl: `https://github.com/${owner}/${repo}`,
  };
}

function updateTargetTypeBadge() {
  const input = document.getElementById("repoPathInput");
  const badge = document.getElementById("repoTargetBadgeText");
  const pill = document.getElementById("repoTargetBadge");
  if (!input || !badge || !pill) return;
  const parsed = parseGitHubRepoInput(input.value);
  if (parsed) {
    badge.textContent = parsed.slug;
    pill.style.borderColor = "rgba(0, 255, 157, 0.5)";
    pill.style.color = "var(--neon-green)";
  } else {
    badge.textContent = t("githubTargetPill");
    pill.style.borderColor = "rgba(0, 229, 255, 0.35)";
    pill.style.color = "var(--cyan-bright)";
  }
}

/* ---- Live Hacker Terminal Stream ---- */
function logTerminal(tag, message, tone = "") {
  const body = document.getElementById("terminalLogBody");
  if (!body) return;
  const now = new Date();
  const hh = String(now.getHours()).padStart(2, "0");
  const mm = String(now.getMinutes()).padStart(2, "0");
  const ss = String(now.getSeconds()).padStart(2, "0");
  const cls = tone === "ok" ? "term-ok" : tone === "warn" ? "term-warn" : tone === "err" ? "term-err" : tone === "cmd" ? "term-cmd" : "";
  const div = document.createElement("div");
  div.className = "term-line";
  div.innerHTML = `<span class="term-ts">[${hh}:${mm}:${ss}] [${escapeHtml(tag)}]</span><span class="${cls}">${escapeHtml(message)}</span>`;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
}

function clearTerminalLogs() {
  const body = document.getElementById("terminalLogBody");
  if (body) body.innerHTML = "";
  logTerminal("SYS", "Console cleared. Ready for next GitHub target.", "ok");
}

/* ---- Clipboard & Quick Input Helpers ---- */
async function readClipboardTextSafe() {
  try {
    if (window.unforceDesktop && typeof window.unforceDesktop.readClipboard === "function") {
      return (await window.unforceDesktop.readClipboard()) || "";
    }
    if (navigator.clipboard && navigator.clipboard.readText) {
      return (await navigator.clipboard.readText()) || "";
    }
  } catch (_) {}
  return "";
}

async function writeClipboardTextSafe(text) {
  try {
    if (window.unforceDesktop && typeof window.unforceDesktop.writeClipboard === "function") {
      await window.unforceDesktop.writeClipboard(String(text || ""));
      return true;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(String(text || ""));
      return true;
    }
  } catch (_) {}
  return false;
}

async function pasteGitHubUrlOnly() {
  const clip = (await readClipboardTextSafe()).trim();
  const input = document.getElementById("repoPathInput");
  if (!clip) {
    showToast(t("clipboardEmpty"));
    if (input) input.focus();
    return false;
  }
  const parsed = parseGitHubRepoInput(clip);
  if (input) {
    input.value = parsed ? parsed.cleanUrl : clip;
    updateTargetTypeBadge();
    input.focus();
  }
  if (!parsed) {
    showToast(t("invalidGhUrl"));
    return false;
  }
  logTerminal("CLIPBOARD", `Target loaded: ${parsed.cleanUrl}`, "cmd");
  return true;
}

async function pasteAndScanGitHub() {
  const input = document.getElementById("repoPathInput");
  const clip = (await readClipboardTextSafe()).trim();
  if (clip && parseGitHubRepoInput(clip)) {
    input.value = parseGitHubRepoInput(clip).cleanUrl;
    updateTargetTypeBadge();
    await startScan();
    return;
  }
  if (input && parseGitHubRepoInput(input.value)) {
    await startScan();
    return;
  }
  if (input) input.focus();
  showToast(t("invalidGhUrl"));
}

function focusGitHubInput() {
  const input = document.getElementById("repoPathInput");
  if (input) {
    input.focus();
    input.select();
  }
}

function loadSampleGitHubUrl(url) {
  const input = document.getElementById("repoPathInput");
  if (!input) return;
  input.value = url;
  updateTargetTypeBadge();
  startScan();
}

/* ---- Window Controls & External Links ---- */
function winMinimize() {
  if (window.unforceDesktop && window.unforceDesktop.minimize) window.unforceDesktop.minimize();
}
function winMaximize() {
  if (window.unforceDesktop && window.unforceDesktop.maximize) window.unforceDesktop.maximize();
}
function winClose() {
  if (window.unforceDesktop && window.unforceDesktop.close) window.unforceDesktop.close();
}

function openExternalUrl(url) {
  if (!url) return;
  if (window.unforceDesktop && window.unforceDesktop.openExternal) {
    window.unforceDesktop.openExternal(url);
  } else {
    window.open(url, "_blank", "noopener,noreferrer");
  }
}

function openActiveRepoOnGitHub() {
  if (activeGithubHtmlUrl) {
    openExternalUrl(activeGithubHtmlUrl);
  }
}

function openActiveCommitOnGitHub() {
  if (!activeCommitObj || !activeGithubHtmlUrl) return;
  openExternalUrl(`${activeGithubHtmlUrl}/commit/${activeCommitObj.commit_hash}`);
}

/* ---- Toast ---- */
let toastTimer = null;
function showToast(msg) {
  const el = document.getElementById("toast");
  const txt = document.getElementById("toastMessage");
  if (!el || !txt) return;
  txt.textContent = msg;
  el.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3400);
}

/* ---- Language & RTL/LTR ---- */
function applyLanguage() {
  document.documentElement.lang = currentLang;
  document.documentElement.dir = currentLang === "he" ? "rtl" : "ltr";

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (key) el.textContent = t(key);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key) el.setAttribute("placeholder", t(key));
  });
  updateTargetTypeBadge();
  renderRecentRepos();
}

function toggleLanguage() {
  currentLang = currentLang === "he" ? "en" : "he";
  localStorage.setItem("unforce_lang", currentLang);
  applyLanguage();
}

/* ---- Recent Scanned GitHub Repos ---- */
function getRecentRepos() {
  try {
    const arr = JSON.parse(localStorage.getItem("unforce_recent_gh_repos") || "[]");
    return Array.isArray(arr) ? arr.filter((u) => Boolean(parseGitHubRepoInput(u))) : [];
  } catch (_) {
    return [];
  }
}

function addRecentRepo(cleanUrl) {
  const parsed = parseGitHubRepoInput(cleanUrl);
  if (!parsed) return;
  let list = getRecentRepos().filter((item) => item.toLowerCase() !== parsed.cleanUrl.toLowerCase());
  list.unshift(parsed.cleanUrl);
  list = list.slice(0, 8);
  localStorage.setItem("unforce_recent_gh_repos", JSON.stringify(list));
  renderRecentRepos();
}

function clearRecentRepos() {
  localStorage.removeItem("unforce_recent_gh_repos");
  renderRecentRepos();
}

function renderRecentRepos() {
  const box = document.getElementById("recentReposList");
  if (!box) return;
  const list = getRecentRepos();
  if (!list.length) {
    box.innerHTML = `<div style="font-size:11.5px;color:var(--text-muted);padding:4px 8px;">${escapeHtml(t("recentEmpty"))}</div>`;
    return;
  }
  box.innerHTML = list
    .map((url) => {
      const p = parseGitHubRepoInput(url);
      const label = p ? p.slug : url;
      return `<button class="recent-repo-btn" onclick="loadSampleGitHubUrl('${escapeHtml(url)}')" title="${escapeHtml(url)}">
        <span style="color:var(--neon-green);">●</span>
        <span>${escapeHtml(label)}</span>
      </button>`;
    })
    .join("");
}

/* ---- Navigation ---- */
function switchView(viewName) {
  activeView = viewName;
  const map = {
    overview: "viewOverview",
    commits: "viewCommits",
    findings: "viewFindings",
    timemachine: "viewTimeMachine",
    searchblobs: "viewSearchBlobs",
    remediation: "viewRemediation",
  };
  Object.entries(map).forEach(([k, id]) => {
    const panel = document.getElementById(id);
    if (panel) panel.classList.toggle("active", k === viewName);
  });
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-view") === viewName);
  });
}

function openCommitsWithSubtab(subtab) {
  switchView("commits");
  switchCommitSubtab(subtab);
}

/* ---- Scan Execution ---- */
async function startScan() {
  const input = document.getElementById("repoPathInput");
  const rawVal = (input ? input.value : "").trim();
  const parsed = parseGitHubRepoInput(rawVal);

  if (!parsed) {
    showToast(t("invalidGhUrl"));
    logTerminal("ERR", t("invalidGhUrl"), "err");
    if (input) input.focus();
    return;
  }

  input.value = parsed.cleanUrl;
  updateTargetTypeBadge();

  const scanBtn = document.getElementById("scanBtn");
  const scanBtnText = document.getElementById("scanBtnText");
  const progBox = document.getElementById("scanProgressContainer");
  const progFill = document.getElementById("scanProgressFill");
  const progTxt = document.getElementById("progressStatusText");
  const progPct = document.getElementById("progressPctText");

  if (scanBtn) scanBtn.disabled = true;
  if (scanBtnText) scanBtnText.textContent = t("scanningBtn");
  if (progBox) progBox.classList.add("active");
  if (progFill) progFill.style.width = "6%";
  if (progTxt) progTxt.textContent = `Connecting to GitHub: ${parsed.slug}...`;
  if (progPct) progPct.textContent = "6%";

  seenPhaseLogs.clear();
  logTerminal("TARGET", `$ unforce scan ${parsed.cleanUrl} --mirror --forensics`, "cmd");

  const aiProvider = (document.getElementById("aiProviderSelect") || {}).value || "heuristic";
  const entropy = parseFloat((document.getElementById("entropyThreshold") || {}).value || "4.0");
  const scanForks = Boolean((document.getElementById("scanForksToggle") || { checked: true }).checked);

  try {
    const startResp = await apiFetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repo_path: parsed.cleanUrl,
        ai_provider: aiProvider,
        ai_api_key: ephemeralSession.aiKey || undefined,
        github_token: ephemeralSession.ghToken || undefined,
        entropy_threshold: entropy,
        scan_forks: scanForks,
      }),
    });
    const startJson = await startResp.json();
    if (!startResp.ok || startJson.error) {
      throw new Error(startJson.error || `HTTP ${startResp.status}`);
    }

    const jobId = startJson.job_id;
    let finalResult = null;

    while (true) {
      await new Promise((r) => setTimeout(r, 240));
      const stResp = await apiFetch(`/api/scan/status?job_id=${encodeURIComponent(jobId)}`);
      const stData = await stResp.json();
      if (!stResp.ok && !stData.status) {
        throw new Error(stData.error || "Failed polling scan status");
      }

      const pct = Number(stData.progress_pct || 0);
      if (progFill) progFill.style.width = `${pct}%`;
      if (progPct) progPct.textContent = `${pct}%`;
      if (progTxt && stData.phase_message) progTxt.textContent = stData.phase_message;

      if (Array.isArray(stData.phase_logs)) {
        stData.phase_logs.forEach((entry) => {
          const msg = typeof entry === "string" ? entry : entry.msg || "";
          if (msg && !seenPhaseLogs.has(msg)) {
            seenPhaseLogs.add(msg);
            const tone = msg.startsWith("[ERROR]") ? "err" : pct >= 100 ? "ok" : "";
            logTerminal("GIT", msg, tone);
          }
        });
      }

      if (stData.status === "completed") {
        finalResult = stData.result;
        break;
      }
      if (stData.status === "failed") {
        throw new Error(stData.error || "Scan failed");
      }
    }

    activeRepoTarget = finalResult.repo_path || parsed.cleanUrl;
    activeGithubHtmlUrl = finalResult.github_html_url || parsed.cleanUrl;
    addRecentRepo(parsed.cleanUrl);
    renderScanResult(finalResult, parsed);

    const ghostCount = (finalResult.dangling_commits || []).length;
    const branchCount = (finalResult.branch_commits || []).length;
    const secCount = (finalResult.findings || []).length;
    logTerminal(
      "DONE",
      `Audit complete on ${parsed.slug} -> Hygiene: ${finalResult.hygiene_score.score}/100 | Ghost Commits: ${ghostCount} | Repo Commits: ${branchCount} | Secrets: ${secCount}`,
      secCount > 0 ? "warn" : "ok"
    );
    showToast(`✓ ${parsed.slug} — Score: ${finalResult.hygiene_score.score}/100`);
  } catch (err) {
    logTerminal("ERROR", String(err.message || err), "err");
    showToast(`✗ ${err.message || err}`);
  } finally {
    if (scanBtn) scanBtn.disabled = false;
    if (scanBtnText) scanBtnText.textContent = t("scanBtn");
    setTimeout(() => {
      if (progBox) progBox.classList.remove("active");
    }, 900);
  }
}

/* ---- Render Full Scan Dashboard ---- */
function renderScanResult(data, parsedTarget) {
  currentScanData = data;
  const welcome = document.getElementById("welcomeBanner");
  if (welcome) welcome.style.display = "none";

  // Meta Strip
  const strip = document.getElementById("repoMetaStrip");
  if (strip) strip.classList.add("active");
  const metaPath = document.getElementById("metaRepoPath");
  if (metaPath) metaPath.textContent = parsedTarget ? parsedTarget.cleanUrl : data.github_html_url || data.repo_path;
  const metaBranch = document.getElementById("metaBranchBadge");
  const curBranch = (data.repo_metadata && data.repo_metadata.current_branch) || "main";
  if (metaBranch) metaBranch.textContent = `HEAD: ${curBranch}`;
  const metaClean = document.getElementById("metaCleanBadge");
  if (metaClean) metaClean.textContent = `OBJECTS SCANNED: ${data.total_objects_scanned || 0}`;

  // Score Gauge
  const scoreObj = data.hygiene_score || { score: 100, grade: "A+", summary: "", deductions: [] };
  const score = Number(scoreObj.score ?? 100);
  const circle = document.getElementById("gaugeCircle");
  if (circle) {
    const circumference = 440;
    circle.style.strokeDashoffset = String(circumference - (score / 100) * circumference);
    circle.style.stroke = score >= 85 ? "var(--neon-green)" : score >= 60 ? "var(--amber)" : "var(--rose)";
  }
  document.getElementById("scoreNumber").textContent = String(score);
  document.getElementById("scoreGrade").textContent = scoreObj.grade || "A+";
  document.getElementById("scoreSummary").textContent = scoreObj.summary || "";

  // KPIs & Sidebar Badges
  const danglingCommits = data.dangling_commits || [];
  const branchCommits = data.branch_commits || [];
  const findings = data.findings || [];
  const blobs = data.dangling_blobs || [];
  const historyEvents = data.history_events || [];
  const discoveredForks = data.discovered_forks || [];
  const remoteEventsCount = historyEvents.length + discoveredForks.length;

  const tmEntries = buildTimeMachineEntries(data);

  document.getElementById("statCommits").textContent = String(danglingCommits.length);
  document.getElementById("statBranchCommits").textContent = String(branchCommits.length);
  document.getElementById("statSecrets").textContent = String(findings.length);
  document.getElementById("statSecrets").style.color = findings.length > 0 ? "var(--rose)" : "var(--neon-green)";
  document.getElementById("statTotalObjects").textContent = String(tmEntries.length);

  document.getElementById("navBadgeScore").textContent = `${score}`;
  document.getElementById("navBadgeCommits").textContent = String(danglingCommits.length + branchCommits.length);
  const navFindingsBadge = document.getElementById("navBadgeFindings");
  navFindingsBadge.textContent = String(findings.length);
  navFindingsBadge.classList.toggle("alert", findings.length > 0);
  document.getElementById("navBadgeTimeMachine").textContent = String(tmEntries.length);
  document.getElementById("navBadgeBlobs").textContent = String(blobs.length);

  document.getElementById("subCountDangling").textContent = String(danglingCommits.length);
  document.getElementById("subCountBranch").textContent = String(branchCommits.length);
  document.getElementById("subCountRemote").textContent = String(remoteEventsCount);

  // Deductions
  const dedList = document.getElementById("deductionsList");
  const deductions = scoreObj.deductions || [];
  if (!deductions.length) {
    dedList.innerHTML = `<div style="color:var(--neon-green);font-size:13px;" class="ltr-mono">[OK] 0 hygiene deductions — repository history is clean!</div>`;
  } else {
    dedList.innerHTML = deductions
      .map(
        (d) => `<div style="padding:8px 10px;border-radius:8px;background:rgba(255,42,109,0.09);border:1px solid rgba(255,42,109,0.3);font-size:12.5px;color:#ffd0df;">
          <strong class="ltr-mono">[-${d.points ?? ""} pts]</strong> ${escapeHtml(d.reason || d.category || "")}
        </div>`
      )
      .join("");
  }

  // Overview Latest Commits
  const overviewCommits = danglingCommits.length ? danglingCommits.slice(0, 5) : branchCommits.slice(0, 5);
  const ovBox = document.getElementById("overviewRecentCommits");
  if (!overviewCommits.length) {
    ovBox.innerHTML = `<div style="color:var(--text-muted);font-size:13px;">No commits found in repository.</div>`;
  } else {
    const targetSub = danglingCommits.length ? "dangling" : "branch";
    ovBox.innerHTML = overviewCommits
      .map(
        (c) => `<div class="commit-item-card" onclick="jumpToCommit('${escapeHtml(c.commit_hash)}', '${targetSub}')">
          <div style="display:flex;justify-content:space-between;gap:8px;align-items:center;">
            <span style="font-weight:700;color:#ffffff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(c.message || "(no message)")}</span>
            <span class="code-chip">${escapeHtml((c.commit_hash || "").slice(0, 8))}</span>
          </div>
          <div style="font-size:11.5px;color:var(--text-muted);margin-top:4px;" class="ltr-mono">
            ${escapeHtml(c.author || "Unknown")} • ${escapeHtml((c.date || "").slice(0, 19))}
          </div>
        </div>`
      )
      .join("");
  }

  activeCommitObj = null;
  if (danglingCommits.length > 0) {
    switchCommitSubtab("dangling");
  } else {
    switchCommitSubtab("branch");
  }

  renderRemoteEventsAndForks(historyEvents, discoveredForks);
  filterFindings();
  filterTimeMachine();
  renderDetachedBlobs(blobs);
  renderRemediation(data.remediation || {});
}

/* ---- View 2: Commit & File-Tree Explorer ---- */
function switchCommitSubtab(tab) {
  activeCommitSubtab = tab;
  document.getElementById("segBtnDangling").classList.toggle("active", tab === "dangling");
  document.getElementById("segBtnBranch").classList.toggle("active", tab === "branch");
  document.getElementById("segBtnRemote").classList.toggle("active", tab === "remote");

  const split = document.getElementById("subpanelCommitsSplit");
  const remote = document.getElementById("subpanelRemote");
  if (tab === "remote") {
    split.style.display = "none";
    remote.style.display = "block";
  } else {
    split.style.display = "grid";
    remote.style.display = "none";
    renderCommitsList();
  }
}

function getActiveCommitsArray() {
  if (!currentScanData) return [];
  return activeCommitSubtab === "dangling"
    ? currentScanData.dangling_commits || []
    : currentScanData.branch_commits || [];
}

function renderCommitsList() {
  const container = document.getElementById("commitsListContainer");
  if (!container) return;
  if (!currentScanData) {
    container.innerHTML = `<div class="card" style="text-align:center;color:var(--text-muted);padding:32px;">Paste a GitHub URL above to scan commits.</div>`;
    return;
  }

  const q = ((document.getElementById("commitFilterInput") || {}).value || "").trim().toLowerCase();
  const sourceList = getActiveCommitsArray();
  const filtered = sourceList.filter((c) => {
    if (!q) return true;
    return (
      (c.commit_hash || "").toLowerCase().includes(q) ||
      (c.message || "").toLowerCase().includes(q) ||
      (c.author || "").toLowerCase().includes(q) ||
      (c.changed_files || []).some((f) => f.toLowerCase().includes(q))
    );
  });

  if (!filtered.length) {
    if (activeCommitSubtab === "dangling" && (currentScanData.branch_commits || []).length > 0 && !q) {
      const totalBranch = (currentScanData.branch_commits || []).length;
      container.innerHTML = `<div class="card" style="text-align:center;padding:26px;">
        <div style="color:var(--neon-green);font-weight:800;margin-bottom:6px;">✓ 0 Force-Pushed Ghost Commits Exposed</div>
        <div style="color:var(--text-secondary);font-size:12.5px;margin-bottom:14px;">GitHub did not expose un-GC'd dangling commits on this repo, and <strong>${totalBranch}</strong> repository commits are mirrored and ready for inspection.</div>
        <button class="btn btn-primary btn-sm" onclick="switchCommitSubtab('branch')">Browse All ${totalBranch} Repo Commits →</button>
      </div>`;
      return;
    }
    container.innerHTML = `<div class="card" style="text-align:center;color:var(--text-muted);padding:28px;">No matching commits found.</div>`;
    return;
  }

  container.innerHTML = filtered
    .map((c) => {
      const isAct = activeCommitObj && activeCommitObj.commit_hash === c.commit_hash;
      const badgeTone = c.is_dangling ? "badge-critical" : "badge-medium";
      const badgeLabel = c.is_dangling ? "GHOST" : "COMMIT";
      const aiBadge = c.is_ai_agent
        ? `<span class="badge badge-high" style="margin-inline-start:4px;">AI: ${escapeHtml(c.ai_agent_name || "Agent")}</span>`
        : "";
      return `<div class="commit-item-card ${isAct ? "active" : ""}" onclick="selectCommit('${escapeHtml(c.commit_hash)}')">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:6px;">
          <span class="badge ${badgeTone}">${badgeLabel}</span>
          ${aiBadge}
          <span class="code-chip" style="margin-inline-start:auto;">${escapeHtml(c.commit_hash.slice(0, 8))}</span>
        </div>
        <div style="font-weight:700;color:#ffffff;margin-top:7px;font-size:13px;">${escapeHtml(c.message || "(no commit message)")}</div>
        <div style="font-size:11.5px;color:var(--text-muted);margin-top:5px;" class="ltr-mono">
          ${escapeHtml(c.author || "Unknown")} • ${escapeHtml((c.date || "").slice(0, 16))} • ${(c.changed_files || []).length} files
        </div>
      </div>`;
    })
    .join("");

  if (!activeCommitObj && filtered.length > 0) {
    selectCommit(filtered[0].commit_hash);
  }
}

function jumpToCommit(sha, subtab) {
  switchView("commits");
  switchCommitSubtab(subtab || "branch");
  selectCommit(sha);
}

async function selectCommit(sha) {
  if (!currentScanData) return;
  const all = [...(currentScanData.dangling_commits || []), ...(currentScanData.branch_commits || [])];
  const found = all.find((c) => c.commit_hash === sha || c.commit_hash.startsWith(sha));
  if (!found) return;

  activeCommitObj = found;
  activePreviewedFile = null;
  renderCommitsList();

  document.getElementById("commitInspectorEmpty").style.display = "none";
  document.getElementById("commitInspectorContent").style.display = "flex";

  document.getElementById("inspCommitTitle").textContent = found.message || "(no commit message)";
  document.getElementById("inspCommitMeta").textContent = `${found.author || "Unknown"} • ${found.date || ""}`;
  document.getElementById("inspCommitShaChip").textContent = found.commit_hash.slice(0, 12);

  // Render or fetch Unified Diff on-demand
  const diffViewer = document.getElementById("inspDiffViewer");
  const rawDiff = found.redacted_diff || "";
  if (rawDiff) {
    renderDiffLines(diffViewer, rawDiff);
  } else {
    diffViewer.innerHTML = `<div class="diff-line" style="color:var(--cyan-bright);">Loading commit diff from GitHub mirror...</div>`;
    try {
      const includeRaw = Boolean((document.getElementById("includeRawToggle") || {}).checked);
      const resp = await apiFetch("/api/commit/diff", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_path: activeRepoTarget,
          commit_hash: found.commit_hash,
          include_raw: includeRaw,
        }),
      });
      const dj = await resp.json();
      if (resp.ok && dj.diff !== undefined) {
        found.redacted_diff = dj.diff;
        if (activeCommitObj && activeCommitObj.commit_hash === found.commit_hash) {
          renderDiffLines(diffViewer, dj.diff || "(Empty diff — merge or metadata commit)");
        }
      } else {
        diffViewer.innerHTML = `<div class="diff-line term-err">${escapeHtml(dj.error || "Could not load diff")}</div>`;
      }
    } catch (e) {
      diffViewer.innerHTML = `<div class="diff-line term-err">${escapeHtml(e.message)}</div>`;
    }
  }

  loadCommitFileTree(found.commit_hash);
}

function renderDiffLines(container, diffText) {
  if (!container) return;
  const lines = String(diffText || "").split("\n");
  if (!lines.length || (lines.length === 1 && !lines[0])) {
    container.innerHTML = `<div class="diff-line" style="color:var(--text-muted);">(No diff changes in this commit)</div>`;
    return;
  }
  container.innerHTML = lines
    .slice(0, 900)
    .map((line) => {
      let cls = "diff-line";
      if (line.startsWith("+") && !line.startsWith("+++")) cls += " diff-add";
      else if (line.startsWith("-") && !line.startsWith("---")) cls += " diff-del";
      else if (line.startsWith("@@") || line.startsWith("diff --git")) cls += " diff-hunk";
      return `<div class="${cls}">${escapeHtml(line)}</div>`;
    })
    .join("");
}

function switchInspectorMode(mode) {
  document.getElementById("inspTabDiff").classList.toggle("active", mode === "diff");
  document.getElementById("inspTabFiles").classList.toggle("active", mode === "files");
  document.getElementById("inspDiffBody").style.display = mode === "diff" ? "block" : "none";
  document.getElementById("inspFilesBody").style.display = mode === "files" ? "block" : "none";
}

async function loadCommitFileTree(commitSha) {
  const treeBox = document.getElementById("inspFilesTreeList");
  const codeBox = document.getElementById("inspFilePreviewCode");
  const nameChip = document.getElementById("inspPreviewFileName");
  const btnSave = document.getElementById("btnSaveThisFileAs");
  const btnCopy = document.getElementById("btnCopyThisFile");

  if (!treeBox) return;
  treeBox.innerHTML = `<div style="color:var(--cyan-bright);font-size:12px;padding:8px;" class="ltr-mono">Loading tree...</div>`;
  nameChip.textContent = "Select a file";
  btnSave.style.display = "none";
  btnCopy.style.display = "none";
  codeBox.innerHTML = `<div class="diff-line" style="color:var(--text-muted);">Select any file on the left to inspect its full snapshot at commit ${escapeHtml(commitSha.slice(0, 8))}.</div>`;

  try {
    const resp = await apiFetch("/api/commit/files", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_path: activeRepoTarget, commit_hash: commitSha }),
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error || "Tree load failed");
    const files = data.files || [];
    if (!files.length) {
      treeBox.innerHTML = `<div style="color:var(--text-muted);font-size:12px;padding:8px;">(Empty commit tree)</div>`;
      return;
    }
    treeBox.innerHTML = files
      .map((f, idx) => {
        const star = f.is_changed ? `<span style="color:var(--neon-green);margin-right:4px;">●</span>` : `📄 `;
        return `<button class="tree-file-btn" id="treeFileBtn_${idx}" onclick="previewCommitFile('${escapeHtml(commitSha)}', ${idx})" data-filepath="${escapeHtml(f.path)}" title="${escapeHtml(f.path)} (${f.size || 0} B)">
          ${star}${escapeHtml(f.path)}
        </button>`;
      })
      .join("");
  } catch (err) {
    treeBox.innerHTML = `<div style="color:var(--rose);font-size:12px;padding:8px;">${escapeHtml(err.message)}</div>`;
  }
}

async function previewCommitFile(commitSha, btnIdx) {
  const btn = document.getElementById(`treeFileBtn_${btnIdx}`);
  if (!btn) return;
  const filePath = btn.getAttribute("data-filepath");
  document.querySelectorAll(".tree-file-btn").forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");

  const codeBox = document.getElementById("inspFilePreviewCode");
  const nameChip = document.getElementById("inspPreviewFileName");
  const btnSave = document.getElementById("btnSaveThisFileAs");
  const btnCopy = document.getElementById("btnCopyThisFile");

  nameChip.textContent = filePath;
  codeBox.innerHTML = `<div class="diff-line" style="color:var(--cyan-bright);">Reading ${escapeHtml(filePath)}...</div>`;

  try {
    const includeRaw = Boolean((document.getElementById("includeRawToggle") || {}).checked);
    const resp = await apiFetch("/api/commit/file-preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repo_path: activeRepoTarget,
        commit_hash: commitSha,
        file_path: filePath,
        include_raw: includeRaw,
      }),
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error || "Preview failed");

    activePreviewedFile = {
      commitHash: commitSha,
      filePath,
      content: data.content || "",
    };
    btnSave.style.display = "inline-flex";
    btnCopy.style.display = "inline-flex";

    const lines = String(data.content || "").split("\n");
    codeBox.innerHTML = lines
      .slice(0, 1200)
      .map((ln, i) => `<div class="diff-line"><span style="color:#476288;margin-right:10px;user-select:none;">${String(i + 1).padStart(4, " ")}</span>${escapeHtml(ln)}</div>`)
      .join("");
  } catch (err) {
    codeBox.innerHTML = `<div class="diff-line term-err">${escapeHtml(err.message)}</div>`;
  }
}

async function copyPreviewedFile() {
  if (!activePreviewedFile) return;
  await writeClipboardTextSafe(activePreviewedFile.content);
  showToast(`✓ Copied ${activePreviewedFile.filePath}`);
}

async function savePreviewedFileAs() {
  if (!activePreviewedFile) return;
  const baseName = activePreviewedFile.filePath.split("/").pop() || "recovered_file.txt";
  await saveTextArtifact(baseName, activePreviewedFile.content);
}

async function copyActiveCommitSha() {
  if (!activeCommitObj) return;
  await writeClipboardTextSafe(activeCommitObj.commit_hash);
  showToast(`✓ Copied SHA: ${activeCommitObj.commit_hash.slice(0, 12)}`);
}

async function exportActiveCommitPatch() {
  if (!activeCommitObj) return;
  const sha = activeCommitObj.commit_hash;
  const diff = activeCommitObj.redacted_diff || "";
  const header = `From ${sha} Mon Sep 17 00:00:00 2001\nFrom: ${activeCommitObj.author || "Unknown"}\nDate: ${activeCommitObj.date || ""}\nSubject: [PATCH] ${activeCommitObj.message || ""}\n\n`;
  await saveTextArtifact(`commit_${sha.slice(0, 8)}.patch`, header + diff);
}

function renderRemoteEventsAndForks(events, forks) {
  const evBox = document.getElementById("historyEventsList");
  const fkBox = document.getElementById("forksAuditList");

  if (!events.length) {
    evBox.innerHTML = `<div style="color:var(--text-muted);font-size:13px;">No Push / Force-Push overwrite events recorded in GitHub's recent Events feed.</div>`;
  } else {
    evBox.innerHTML = events
      .map(
        (ev) => `<div style="padding:10px 12px;border-radius:9px;background:var(--bg-card);border:1px solid var(--border);">
