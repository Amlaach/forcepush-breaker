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
let currentUiState = "landing"; // "landing" | "workspace"
let latestReleaseInfo = null;
let clientLogs = [];
let lastServerLogId = 0;
let activeLogFilter = "all";
let autoScrollLogs = true;

/* ---- UI State Machine: Landing vs Workspace ---- */
function setUiState(state) {
  currentUiState = state;
  const landing = document.getElementById("landingView");
  const ws = document.getElementById("workspaceView");
  if (state === "landing") {
    document.body.classList.remove("state-workspace");
    document.body.classList.add("state-landing");
    if (ws) ws.style.display = "none";
    if (landing) landing.style.display = "flex";
    const inp = document.getElementById("repoPathInput");
    if (inp) inp.focus();
  } else {
    document.body.classList.remove("state-landing");
    document.body.classList.add("state-workspace");
    if (landing) landing.style.display = "none";
    if (ws) ws.style.display = "flex";
  }
}

function returnToLanding() {
  setUiState("landing");
  const progBox = document.getElementById("scanProgressContainer");
  if (progBox) progBox.style.display = "none";
}

/* ---- In-App Version Update System (Instant GitHub Release Detection & Safe SSL) ---- */
async function checkAppVersion(isManual = false) {
  try {
    logEvent("INFO", "updater", "Checking for updates on GitHub (v0.8.0)...");
    const res = await apiFetch("/api/version/check");
    if (!res.ok) {
      if (isManual) showToast("שגיאה בבדיקת עדכונים: " + res.statusText);
      return;
    }
    const data = await res.json();
    if (data && data.has_update) {
      latestReleaseInfo = data;
      const btn = document.getElementById("updateAvailableBtn");
      const badge = document.getElementById("updateVerBadge");
      if (btn) btn.style.display = "inline-flex";
      if (badge) badge.textContent = data.latest_version;
      logEvent("WARN", "updater", `New version available on GitHub: v${data.latest_version}`);
      if (isManual) {
        openUpdateModal();
      }
    } else {
      const btn = document.getElementById("updateAvailableBtn");
      if (btn) btn.style.display = "none";
      if (isManual) {
        showToast(currentLang === "he" ? "המערכת מעודכנת לגירסה העדכנית (v0.8.0)" : "Software is up to date (v0.8.0)");
      }
      logEvent("INFO", "updater", "Software is up to date (v0.8.0).");
    }
  } catch (err) {
    logEvent("ERROR", "updater", "Update check failed: " + err.message);
    if (isManual) showToast("בדיקת עדכונים נכשלה: " + err.message);
  }
}

function openUpdateModal() {
  if (!latestReleaseInfo) {
    latestReleaseInfo = {
      latest_version: "0.7.2",
      release_name: "UnForce v0.8.0",
      release_notes: "Latest stable release for UnForce Forensics Studio.",
      html_url: "https://github.com/Amlaach/forcepush-breaker/releases",
      assets: []
    };
  }
  const modal = document.getElementById("updateModal");
  const targetVer = document.getElementById("modalUpdateTargetVer");
  const notes = document.getElementById("modalUpdateNotes");
  if (targetVer) targetVer.textContent = `v${latestReleaseInfo.latest_version}`;
  if (notes) notes.textContent = latestReleaseInfo.release_notes || "Release notes available on GitHub.";
  if (modal) modal.style.display = "flex";
}

function closeUpdateModal() {
  const modal = document.getElementById("updateModal");
  if (modal) modal.style.display = "none";
}

function openReleasePageGH() {
  const url = (latestReleaseInfo && latestReleaseInfo.html_url) || "https://github.com/Amlaach/forcepush-breaker/releases";
  openExternalUrl(url);
}

async function downloadLatestRelease() {
  if (!latestReleaseInfo || !latestReleaseInfo.assets || latestReleaseInfo.assets.length === 0) {
    openReleasePageGH();
    return;
  }
  const asset = latestReleaseInfo.assets[0];
  const progBox = document.getElementById("updateDownloadProgressBox");
  const progFill = document.getElementById("updateProgressFill");
  const progText = document.getElementById("updateProgressText");
  const progPct = document.getElementById("updateProgressPct");
  const btn = document.getElementById("btnDownloadUpdate");

  if (progBox) progBox.style.display = "block";
  if (btn) btn.disabled = true;
  if (progFill) progFill.style.width = "40%";
  if (progPct) progPct.textContent = "40%";
  if (progText) progText.textContent = t("updateDownloading");

  try {
    const res = await apiFetch("/api/version/download", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ download_url: asset.download_url, filename: asset.name }),
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    if (progFill) progFill.style.width = "100%";
    if (progPct) progPct.textContent = "100%";
    if (progText) progText.textContent = t("updateDone");
    showToast(currentLang === "he" ? `העדכון נשמר ב: ${data.saved_path}` : `Update saved to: ${data.saved_path}`);
    logEvent("INFO", "updater", `Update binary saved to: ${data.saved_path}`);
  } catch (err) {
    if (progText) progText.textContent = "שגיאה בהורדת קובץ: " + err.message;
    showToast("שגיאה בהורדת עדכון: " + err.message);
    logEvent("ERROR", "updater", "שגיאה בהורדת קובץ: " + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ---- Dedicated Forensics Activity & Logs Console ---- */
function logEvent(level, source, message, details = null) {
  const entry = {
    id: Date.now() * 1000 + Math.floor(Math.random() * 999),
    timestamp: new Date().toTimeString().split(" ")[0],
    level: String(level || "INFO").toUpperCase(),
    source: String(source || "engine").toLowerCase(),
    message: String(message || ""),
    details,
  };
  clientLogs.push(entry);
  if (clientLogs.length > 1500) clientLogs.shift();

  updateLogsBadges();
  appendLogToConsole(entry);

  ensureApiBase().then((base) => {
    if (base) {
      fetch(`${base}/api/logs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry),
      }).catch(() => {});
    }
  });
}

function updateLogsBadges() {
  const count = clientLogs.length;
  const b1 = document.getElementById("titlebarLogsBadge");
  const b2 = document.getElementById("wsLogsBadge");
  const b3 = document.getElementById("logsTotalCountBadge");
  if (b1) b1.textContent = String(count);
  if (b2) b2.textContent = String(count);
  if (b3) b3.textContent = String(count);
}

function appendLogToConsole(entry) {
  const container = document.getElementById("logsConsoleBody");
  if (!container) return;

  if (activeLogFilter !== "all" && entry.level.toLowerCase() !== activeLogFilter) {
    return;
  }

  const row = document.createElement("div");
  row.className = "log-entry-row";
  row.innerHTML = `
    <span class="log-ts">[${escapeHtml(entry.timestamp)}]</span>
    <span class="log-tag log-tag-${entry.level.toLowerCase()}">${escapeHtml(entry.level)}</span>
    <span class="log-src">[${escapeHtml(entry.source.toUpperCase())}]</span>
    <span class="log-msg">${escapeHtml(entry.message)}</span>
  `;
  container.appendChild(row);

  if (autoScrollLogs) {
    container.scrollTop = container.scrollHeight;
  }
}

function renderLogsConsole() {
  const container = document.getElementById("logsConsoleBody");
  if (!container) return;
  const searchInput = document.getElementById("logsSearchInput");
  const search = (searchInput ? searchInput.value : "").toLowerCase();
  container.innerHTML = "";

  const filtered = clientLogs.filter((l) => {
    if (activeLogFilter !== "all" && l.level.toLowerCase() !== activeLogFilter) return false;
    if (search && !l.message.toLowerCase().includes(search) && !l.source.toLowerCase().includes(search)) return false;
    return true;
  });

  filtered.forEach((entry) => {
    const row = document.createElement("div");
    row.className = "log-entry-row";
    row.innerHTML = `
      <span class="log-ts">[${escapeHtml(entry.timestamp)}]</span>
      <span class="log-tag log-tag-${entry.level.toLowerCase()}">${escapeHtml(entry.level)}</span>
      <span class="log-src">[${escapeHtml(entry.source.toUpperCase())}]</span>
      <span class="log-msg">${escapeHtml(entry.message)}</span>
    `;
    container.appendChild(row);
  });

  if (autoScrollLogs) {
    container.scrollTop = container.scrollHeight;
  }
}

function filterLogs(level) {
  activeLogFilter = level;
  document.querySelectorAll(".log-filter-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-filter") === level);
  });
  renderLogsConsole();
}

function toggleLogsAutoScroll(val) {
  autoScrollLogs = Boolean(val);
}

function openLogsConsole() {
  const drawer = document.getElementById("logsDrawer");
  if (drawer) drawer.style.display = "flex";
  syncLogsFromServer();
  renderLogsConsole();
}

function closeLogsConsole() {
  const drawer = document.getElementById("logsDrawer");
  if (drawer) drawer.style.display = "none";
}

function copyAllLogs() {
  const text = clientLogs.map((l) => `[${l.timestamp}] [${l.level}] [${l.source.toUpperCase()}] ${l.message}`).join("\n");
  writeClipboardTextSafe(text);
  showToast(currentLang === "he" ? "כל הלוגים הועתקו ללוח!" : "All logs copied to clipboard!");
}

async function clearAllLogs() {
  clientLogs = [];
  updateLogsBadges();
  renderLogsConsole();
  try {
    await apiFetch("/api/logs/clear", { method: "POST" });
  } catch (_) {}
  showToast(currentLang === "he" ? "יומן הלוגים נוקה" : "Logs cleared");
}

async function syncLogsFromServer() {
  try {
    const res = await apiFetch(`/api/logs?since_id=${lastServerLogId}`);
    if (res.ok) {
      const data = await res.json();
      if (data && data.logs && data.logs.length > 0) {
        data.logs.forEach((srvLog) => {
          if (!clientLogs.some((c) => c.id === srvLog.id)) {
            clientLogs.push(srvLog);
          }
          if (srvLog.id > lastServerLogId) {
            lastServerLogId = srvLog.id;
          }
        });
        updateLogsBadges();
        renderLogsConsole();
      }
    }
  } catch (_) {}
}

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

/* ---- Smart Target Parsing & Validation (Local Repositories, GitHub, GitLab, Bitbucket) ---- */
function parseSmartTarget(rawInput) {
  const raw = String(rawInput || "").trim();
  if (!raw) return null;

  // Local filesystem directory detection
  const isWindowsPath = /^[a-zA-Z]:[\\/]/.test(raw) || raw.startsWith("\\\\");
  const isUnixPath = raw.startsWith("/") || raw.startsWith("~/");
  const isRelative = raw === "." || raw === ".." || raw.startsWith("./") || raw.startsWith(".\\") || raw.startsWith("../") || raw.startsWith("..\\");

  if (isWindowsPath || isUnixPath || isRelative) {
    const parts = raw.replace(/\\/g, "/").split("/").filter(Boolean);
    const slug = parts.length > 0 ? parts[parts.length - 1] : raw;
    return {
      type: "local",
      platform: "local",
      path: raw,
      slug: slug,
      cleanUrl: raw,
    };
  }

  // GitLab
  const mGitLab = raw.match(/^(?:https?:\/\/)?(?:www\.)?gitlab\.com\/([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*?)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#].*)?$/i) ||
                  raw.match(/^git@gitlab\.com:([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*?)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i);
  if (mGitLab) {
    const group = mGitLab[1];
    const repo = mGitLab[2].replace(/\.git$/i, "");
    const slug = `${group}/${repo}`;
    return {
      type: "gitlab",
      platform: "gitlab",
      owner: group,
      repo: repo,
      slug: slug,
      cleanUrl: `https://gitlab.com/${slug}`,
    };
  }

  // Bitbucket
  const mBb = raw.match(/^(?:https?:\/\/)?(?:www\.)?bitbucket\.org\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#].*)?$/i) ||
              raw.match(/^git@bitbucket\.org:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i);
  if (mBb) {
    const ws = mBb[1];
    const repo = mBb[2].replace(/\.git$/i, "");
    const slug = `${ws}/${repo}`;
    return {
      type: "bitbucket",
      platform: "bitbucket",
      owner: ws,
      repo: repo,
      slug: slug,
      cleanUrl: `https://bitbucket.org/${slug}`,
    };
  }

  // GitHub
  let mGh = raw.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#].*)?$/i);
  if (!mGh) {
    mGh = raw.match(/^git@github\.com:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i);
  }
  if (!mGh) {
    mGh = raw.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  }
  if (mGh) {
    const owner = mGh[1];
    const repo = mGh[2].replace(/\.git$/i, "");
    const reserved = ["settings", "orgs", "organizations", "users", "marketplace", "explore", "topics", "login"];
    if (owner && repo && !reserved.includes(owner.toLowerCase())) {
      return {
        type: "github",
        platform: "github",
        owner: owner,
        repo: repo,
        slug: `${owner}/${repo}`,
        cleanUrl: `https://github.com/${owner}/${repo}`,
      };
    }
  }

  if (raw.length >= 2 && !raw.includes("http://") && !raw.includes("https://")) {
    return {
      type: "local",
      platform: "local",
      path: raw,
      slug: raw,
      cleanUrl: raw,
    };
  }

  return null;
}

function parseGitHubRepoInput(rawInput) {
  return parseSmartTarget(rawInput);
}

async function selectLocalFolder() {
  if (window.unforceDesktop && typeof window.unforceDesktop.selectDirectoryDialog === "function") {
    try {
      const res = await window.unforceDesktop.selectDirectoryDialog();
      if (res && !res.canceled && res.path) {
        const input = document.getElementById("repoPathInput");
        if (input) {
          input.value = res.path;
          updateTargetTypeBadge();
          logTerminal("LOCAL", `Selected local repository: ${res.path}`, "ok");
          startScan();
        }
      }
    } catch (err) {
      logTerminal("ERR", `Directory dialog error: ${err.message}`, "err");
    }
    return;
  }
  const fallback = prompt(t("promptLocalPath") || "Enter local Git repository directory path:", "");
  if (fallback && fallback.trim()) {
    const input = document.getElementById("repoPathInput");
    if (input) {
      input.value = fallback.trim();
      updateTargetTypeBadge();
      startScan();
    }
  }
}

function updateTargetTypeBadge() {
  const input = document.getElementById("repoPathInput");
  const badge = document.getElementById("repoTargetBadgeText");
  const pill = document.getElementById("repoTargetBadge");
  if (!input || !badge || !pill) return;
  const parsed = parseSmartTarget(input.value);
  if (parsed) {
    if (parsed.type === "local") {
      badge.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-inline-end:4px;vertical-align:middle;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg><span>${escapeHtml(parsed.slug)}</span>`;
      pill.style.borderColor = "rgba(0, 229, 255, 0.5)";
      pill.style.color = "var(--cyan-bright)";
    } else if (parsed.type === "gitlab") {
      badge.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-inline-end:4px;vertical-align:middle;"><path d="m22 13.29-1.32-4.06a.84.84 0 0 0-.32-.42.85.85 0 0 0-.52-.16.87.87 0 0 0-.52.17.84.84 0 0 0-.32.41L17.3 14H6.7l-1.72-4.77a.85.85 0 0 0-.84-.58.85.85 0 0 0-.84.58L2 13.29a.86.86 0 0 0 .31 1l9.34 6.8a.86.86 0 0 0 .7 0l9.34-6.8a.86.86 0 0 0 .31-1z"></path></svg><span>${escapeHtml(parsed.slug)}</span>`;
      pill.style.borderColor = "rgba(252, 109, 38, 0.6)";
      pill.style.color = "#fc6d26";
    } else if (parsed.type === "bitbucket") {
      badge.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-inline-end:4px;vertical-align:middle;"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg><span>${escapeHtml(parsed.slug)}</span>`;
      pill.style.borderColor = "rgba(38, 132, 255, 0.6)";
      pill.style.color = "#2684ff";
    } else {
      badge.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-inline-end:4px;vertical-align:middle;"><path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/></svg><span>${escapeHtml(parsed.slug)}</span>`;
      pill.style.borderColor = "rgba(0, 255, 157, 0.5)";
      pill.style.color = "var(--neon-green)";
    }
  } else {
    badge.textContent = t("githubTargetPill");
    pill.style.borderColor = "rgba(0, 229, 255, 0.35)";
    pill.style.color = "var(--cyan-bright)";
  }
}

/* ---- Live Hacker Terminal Stream ---- */
function logTerminal(tag, message, tone = "") {
  let level = "INFO";
  if (tone === "err" || tag === "ERR" || tag === "ERROR") level = "ERROR";
  else if (tone === "warn" || tag === "WARN") level = "WARN";
  else if (tag === "TARGET" || tag === "OBJECT" || tag === "GHOST" || tag === "GIT") level = "FORENSICS";
  logEvent(level, tag || "forensics", message);
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
  const input = document.getElementById("repoPathInput");
  let clip = (await readClipboardTextSafe()).trim();
  if (!clip) {
    showToast(t("clipboardEmpty") || "לוח ההעתקה ריק — העתק תחילה כתובת ריפו", "warn");
    if (input) input.focus();
    return false;
  }
  clip = clip.replace(/^["'`<]|["'`>]$/g, "").trim();
  const parsed = parseSmartTarget(clip);
  if (input) {
    input.value = parsed ? parsed.cleanUrl : clip;
    updateTargetTypeBadge();
    input.focus();
  }
  if (!parsed) {
    showToast(t("invalidGhUrl") || "הכתובת אינה מזוהה כריפו תקין", "warn");
    return false;
  }
  showToast(t("pastedSuccess") || "הכתובת הודבקה בהצלחה", "success");
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
function showToast(msg, type = "info") {
  const el = document.getElementById("toast");
  const txt = document.getElementById("toastMessage");
  const ico = document.getElementById("toastIcon");
  if (!el || !txt) return;

  let cleanMsg = String(msg || "");
  let inferredType = type;

  if (cleanMsg.startsWith("✓")) {
    inferredType = "success";
    cleanMsg = cleanMsg.replace(/^✓\s*/, "");
  } else if (cleanMsg.startsWith("✗")) {
    inferredType = "error";
    cleanMsg = cleanMsg.replace(/^✗\s*/, "");
  } else if (cleanMsg.startsWith("⚠")) {
    inferredType = "warn";
    cleanMsg = cleanMsg.replace(/^⚠\s*/, "");
  }

  el.classList.remove("toast-success", "toast-error", "toast-warn", "toast-info");
  el.classList.add(`toast-${inferredType}`);

  if (ico) {
    if (inferredType === "success") {
      ico.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--neon-green)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    } else if (inferredType === "error") {
      ico.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--crimson)" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    } else if (inferredType === "warn") {
      ico.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="2.5"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
    } else {
      ico.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }
  }

  txt.textContent = cleanMsg;
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
        <svg width="8" height="8" viewBox="0 0 10 10" style="vertical-align:middle;margin-inline-end:4px;"><circle cx="5" cy="5" r="4" fill="var(--neon-green)"/></svg>
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
  document.querySelectorAll(".nav-item, .ws-tab-btn").forEach((btn) => {
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

  setUiState("workspace");
  switchView("overview");
  if (scanBtn) scanBtn.disabled = true;
  if (scanBtnText) scanBtnText.textContent = t("scanningBtn");
  if (progBox) {
    progBox.style.display = "block";
    progBox.classList.add("active");
  }
  if (progFill) progFill.style.width = "6%";
  if (progTxt) progTxt.textContent = `${t("connectingTarget") || "מתחבר למאגר:"} ${parsed.slug}...`;
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
    if (progBox) progBox.style.display = "none";

    const ghostCount = (finalResult.dangling_commits || []).length;
    const branchCount = (finalResult.branch_commits || []).length;
    const secCount = (finalResult.findings || []).length;
    logTerminal(
      "DONE",
      `Audit complete on ${parsed.slug} -> Hygiene: ${finalResult.hygiene_score.score}/100 | Ghost Commits: ${ghostCount} | Repo Commits: ${branchCount} | Secrets: ${secCount}`,
      secCount > 0 ? "warn" : "ok"
    );
    showToast(`${parsed.slug} — Score: ${finalResult.hygiene_score.score}/100`);
  } catch (err) {
    logTerminal("ERROR", String(err.message || err), "err");
    showToast(`${err.message || err}`);
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
        <div style="color:var(--neon-green);font-weight:800;margin-bottom:6px;display:flex;align-items:center;justify-content:center;gap:6px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--neon-green)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg> 0 Force-Pushed Ghost Commits Exposed</div>
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
        const star = f.is_changed ? `<svg width="8" height="8" viewBox="0 0 10 10" style="vertical-align:middle;margin-inline-end:4px;"><circle cx="5" cy="5" r="4" fill="var(--neon-green)"/></svg>` : `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" style="vertical-align:middle;margin-inline-end:4px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>`;
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
  showToast(`Copied ${activePreviewedFile.filePath}`);
}

async function savePreviewedFileAs() {
  if (!activePreviewedFile) return;
  const baseName = activePreviewedFile.filePath.split("/").pop() || "recovered_file.txt";
  await saveTextArtifact(baseName, activePreviewedFile.content);
}

async function copyActiveCommitSha() {
  if (!activeCommitObj) return;
  await writeClipboardTextSafe(activeCommitObj.commit_hash);
  showToast(`Copied SHA: ${activeCommitObj.commit_hash.slice(0, 12)}`);
}

async function restoreCommitToNewBranch(commitHash) {
  const repoInput = document.getElementById("repoPathInput");
  const repoPath = repoInput ? repoInput.value.trim() : "";
  const defaultBranch = `recovered/${commitHash.slice(0, 7)}`;
  const branchName = prompt(t("branchPrompt") || "Enter name for the new branch:", defaultBranch);
  if (!branchName || !branchName.trim()) return;

  logTerminal("GIT", `Restoring commit ${commitHash.slice(0, 7)} to branch '${branchName.trim()}'...`, "cmd");
  try {
    const resp = await apiFetch("/api/git/restore-branch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repo_path: repoPath,
        commit_hash: commitHash,
        branch_name: branchName.trim(),
        checkout: false,
      }),
    });
    const result = await resp.json();
    if (result.success) {
      logTerminal("OK", result.message || `Branch '${branchName}' created successfully!`, "ok");
      alert(result.message || `${t("branchRestored")}: ${branchName}`);
    } else {
      logTerminal("ERR", result.error || "Branch restoration failed.", "err");
      alert(`Error: ${result.error || "Failed to create branch."}`);
    }
  } catch (err) {
    logTerminal("ERR", `Restore request failed: ${err.message}`, "err");
    alert(`Error: ${err.message}`);
  }
}

async function cherryPickCommitToCurrent(commitHash) {
  const repoInput = document.getElementById("repoPathInput");
  const repoPath = repoInput ? repoInput.value.trim() : "";
  if (!confirm(`Cherry-pick commit ${commitHash.slice(0, 7)} onto current active branch?`)) return;

  logTerminal("GIT", `Cherry-picking commit ${commitHash.slice(0, 7)}...`, "cmd");
  try {
    const resp = await apiFetch("/api/git/cherry-pick", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repo_path: repoPath,
        commit_hash: commitHash,
        no_commit: false,
      }),
    });
    const result = await resp.json();
    if (result.success) {
      logTerminal("OK", result.message || "Cherry-pick completed successfully!", "ok");
      alert(result.message || "Cherry-pick completed successfully!");
    } else {
      logTerminal("ERR", result.error || "Cherry-pick failed.", "err");
      alert(`Error: ${result.error || "Cherry-pick failed."}`);
    }
  } catch (err) {
    logTerminal("ERR", `Cherry-pick request failed: ${err.message}`, "err");
    alert(`Error: ${err.message}`);
  }
}

function cherryPickActiveCommit() {
  if (activeCommitObj && activeCommitObj.commit_hash) {
    cherryPickCommitToCurrent(activeCommitObj.commit_hash);
  }
}

function restoreActiveCommitBranch() {
  if (activeCommitObj && activeCommitObj.commit_hash) {
    restoreCommitToNewBranch(activeCommitObj.commit_hash);
  }
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
      .map((ev) => {
        const isGcPurged = ev.gc_purged || ev.status === "GC_PURGED_REMOTE";
        const gcBadge = isGcPurged ? `<span class="badge-gc-purged" title="${t("gcPurgedDesc")}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-inline-end:3px;"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>GC_PURGED_REMOTE</span>` : "";
        const gcDiag = isGcPurged ? `
          <div class="gc-diagnostic-card">
            <div class="gc-diag-header">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
              <span>${t("gcPurgedTitle")}</span>
            </div>
            <p class="gc-diag-body">${escapeHtml(ev.diagnostic_message || t("gcPurgedDesc"))}</p>
            <button class="btn btn-sm btn-outline-amber" onclick="selectLocalFolder()">${t("scanLocalCloneBtn")}</button>
          </div>` : "";
        return `<div style="padding:10px 12px;border-radius:9px;background:var(--bg-card);border:1px solid var(--border);">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
              <span class="badge ${ev.event_type === "force_push" ? "badge-critical" : "badge-medium"}">${escapeHtml(ev.event_type)}</span>
              ${gcBadge}
            </div>
            <span class="ltr-mono" style="font-size:11px;color:var(--text-muted);">${escapeHtml((ev.created_at || "").slice(0, 19))}</span>
          </div>
          <div style="font-size:12.5px;margin-top:6px;color:#ffffff;">${escapeHtml(ev.description || "")}</div>
          <div style="font-size:11.5px;color:var(--cyan-bright);margin-top:4px;" class="ltr-mono">Actor: @${escapeHtml(ev.actor || "unknown")} ${ev.before_sha ? "• Before: " + escapeHtml(ev.before_sha.slice(0, 10)) : ""}</div>
          ${gcDiag}
        </div>`;
      })
      .join("");
  }

  if (!forks.length) {
    fkBox.innerHTML = `<div style="color:var(--text-muted);font-size:13px;">No public forks found on this GitHub repository.</div>`;
  } else {
    fkBox.innerHTML = forks
      .map((fk) => {
        const forkUrl = fk.html_url || `https://github.com/${fk.full_name}`;
        return `<div style="padding:10px 12px;border-radius:9px;background:var(--bg-card);border:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">
          <div>
            <div style="font-weight:700;color:#ffffff;" class="ltr-mono">${escapeHtml(fk.full_name)}</div>
            <div style="font-size:11.5px;color:var(--text-muted);" class="ltr-mono">Branch: ${escapeHtml(fk.default_branch || "main")} • Pushed: ${escapeHtml((fk.pushed_at || "").slice(0, 10))}</div>
          </div>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-primary btn-sm" onclick="loadSampleGitHubUrl('${escapeHtml(forkUrl)}')">Scan Fork</button>
            <button class="btn btn-secondary btn-sm" onclick="openExternalUrl('${escapeHtml(forkUrl)}')">GitHub ↗</button>
          </div>
        </div>`;
      })
      .join("");
  }
}

/* ---- View 3: Secrets & AI Triage ---- */
function filterFindings() {
  const tbody = document.getElementById("findingsTableBody");
  if (!tbody || !currentScanData) return;

  const q = ((document.getElementById("findingsFilter") || {}).value || "").trim().toLowerCase();
  const sev = ((document.getElementById("severityFilter") || {}).value || "ALL").toUpperCase();
  const findings = (currentScanData.findings || []).filter((f) => {
    const fSev = String(f.triage_severity || f.severity_estimate || "HIGH").toUpperCase();
    if (sev !== "ALL" && fSev !== sev) return false;
    if (!q) return true;
    const sha = f.commit_hash || f.blob_hash || "";
    return (
      (f.rule_name || "").toLowerCase().includes(q) ||
      (f.file_path || "").toLowerCase().includes(q) ||
      (f.masked_value || "").toLowerCase().includes(q) ||
      sha.toLowerCase().includes(q)
    );
  });

  if (!findings.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--neon-green);padding:32px;" class="ltr-mono">[CLEAN] 0 matching secret exposures detected.</td></tr>`;
    return;
  }

  tbody.innerHTML = findings
    .map((f, idx) => {
      const fSev = String(f.triage_severity || f.severity_estimate || "High");
      const sevCls =
        fSev.toLowerCase() === "critical"
          ? "badge-critical"
          : fSev.toLowerCase() === "high"
          ? "badge-high"
          : fSev.toLowerCase() === "medium"
          ? "badge-medium"
          : "badge-low";
      const sha = f.commit_hash || f.blob_hash || "";
      const verdict = f.is_false_positive
        ? "Likely False Positive"
        : `${fSev} Risk (${f.triage_risk_score ?? "8.0"}/10)`;
      return `<tr>
        <td class="ltr-mono" style="color:var(--text-muted);">${escapeHtml(f.finding_id || "#" + (idx + 1))}</td>
        <td><span class="badge ${sevCls}">${escapeHtml(fSev)}</span></td>
        <td style="font-weight:700;color:#ffffff;">${escapeHtml(f.rule_name)}</td>
        <td><span class="code-chip" style="color:#ff94b4;border-color:rgba(255,42,109,0.35);">${escapeHtml(f.masked_value)}</span></td>
        <td class="ltr-mono" style="font-size:12px;">${escapeHtml(f.file_path || "blob")}:${f.line_number || 1} @ ${escapeHtml(sha.slice(0, 8))}</td>
        <td class="ltr-mono">${Number(f.entropy || 0).toFixed(2)}</td>
        <td style="font-size:12px;color:var(--text-secondary);">${escapeHtml(verdict)}</td>
        <td>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-secondary btn-sm" onclick="inspectFinding('${escapeHtml(f.finding_id || "")}', ${idx})">Inspect</button>
          </div>
        </td>
      </tr>`;
    })
    .join("");
}

function inspectFinding(findingId, fallbackIdx) {
  if (!currentScanData) return;
  const findings = currentScanData.findings || [];
  const f = findings.find((x) => x.finding_id === findingId) || findings[fallbackIdx];
  if (!f) return;

  const sha = f.commit_hash || f.blob_hash || "";
  const fSev = String(f.triage_severity || f.severity_estimate || "High");

  activeModalContext = {
    type: "finding",
    finding: f,
    copyText: f.diff_hunk || f.context_line || f.masked_value || "",
  };

  document.getElementById("modalTitle").textContent = f.rule_name || "Secret Finding";
  document.getElementById("modalSubtitle").textContent = `${f.file_path || "detached_blob"}:${f.line_number || 1} • SHA: ${sha}`;
  document.getElementById("modalTriageMeta").style.display = "block";
  document.getElementById("modalSeverityBadge").innerHTML = `<span class="badge badge-critical">${escapeHtml(fSev)}</span>`;
  document.getElementById("modalEntropyVal").textContent = `${Number(f.entropy || 0).toFixed(2)} bits/char`;
  document.getElementById("modalExplanation").textContent =
    f.triage_explanation || "Detected credential pattern in repository object database.";
  document.getElementById("modalAction").textContent =
    f.triage_action || "Rotate this credential immediately and purge GitHub commit history.";
  document.getElementById("modalLivenessRow").style.display = "none";

  renderDiffLines(document.getElementById("modalCodeView"), f.diff_hunk || f.context_line || f.masked_value);

  document.getElementById("modalVerifyBtn").style.display = "inline-flex";
  document.getElementById("modalCopyBtn").style.display = "inline-flex";
  document.getElementById("modalRecoverBtn").style.display = f.file_path || f.blob_hash ? "inline-flex" : "none";
  document.getElementById("detailModal").classList.add("active");
}

async function verifyActiveModalKey() {
  if (!activeModalContext || activeModalContext.type !== "finding") return;
  const f = activeModalContext.finding;
  const row = document.getElementById("modalLivenessRow");
  const badge = document.getElementById("modalLivenessBadge");
  const details = document.getElementById("modalLivenessDetails");
  row.style.display = "block";
  badge.textContent = "בודק תקינות מפתח מול שרת הספק...";
  details.textContent = "";

  try {
    const resp = await apiFetch("/api/verify/key", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repo_path: activeRepoTarget,
        finding_id: f.finding_id,
        rule_name: f.rule_name,
      }),
    });
    const res = await resp.json();
    if (!resp.ok || res.error) throw new Error(res.error || "Verification error");
    const st = res.status || "UNVERIFIABLE";
    badge.style.color = st === "ACTIVE" ? "var(--rose)" : st === "REVOKED" ? "var(--neon-green)" : "var(--amber)";
    badge.textContent = `[${st}] (${res.provider || "Provider"})`;
    details.textContent = res.details || "";
  } catch (err) {
    badge.style.color = "var(--amber)";
    badge.textContent = "[לא ניתן לאימות]";
    details.textContent = err.message;
  }
}

/* ---- View 4: .env & Config Time-Machine ---- */
function classifyConfigCategory(filePath) {
  const lower = String(filePath || "").toLowerCase();
  const base = lower.split("/").pop() || "";
  if (base.startsWith(".env") || lower.endsWith(".env") || lower.includes(".env.")) return "env";
  if (/\.(pem|key|p12|pfx|jks|keystore|asc)$/.test(lower) || base.includes("id_rsa") || base.includes("id_ed25519")) return "key";
  if (lower.endsWith(".tfstate") || lower.endsWith(".tfvars")) return "terraform";
  if (/(secret|credential|token|passwd|htpasswd|netrc|npmrc|pypirc|dockercfg|kubeconfig)/.test(lower)) return "credential";
  if (/\.(yml|yaml|toml|ini|conf|cfg)$/.test(lower) || /(config|settings)\.(json|js|ts|py)$/.test(lower)) return "config";
  return null;
}

function buildTimeMachineEntries(data) {
  if (!data) return [];
  const entries = [];
  const seen = new Set();

  // 1. Deleted & sensitive config files discovered by backend forensics (ghost + git rm parent_sha)
  (data.deleted_config_files || []).forEach((cf) => {
    const key = `${cf.commit_hash || cf.blob_hash}:${cf.file_path}`;
    if (seen.has(key)) return;
    seen.add(key);
    entries.push({
      filePath: cf.file_path,
      category: cf.file_type || classifyConfigCategory(cf.file_path) || "config",
      originType: cf.blob_hash && !cf.commit_hash ? "blob" : "file",
      recoverCommitSha: cf.commit_hash || "",
      blobHash: cf.blob_hash || "",
      displaySha: cf.commit_hash || cf.blob_hash || "",
      author: cf.author || "Unknown",
      date: (cf.date || "").slice(0, 16),
      note: "Exhumed Config Snapshot",
    });
  });

  // 2. Branch commits touching sensitive config files
  (data.branch_commits || []).forEach((c) => {
    (c.changed_files || []).forEach((fp) => {
      const cat = classifyConfigCategory(fp);
      if (!cat) return;
      const key = `${c.commit_hash}:${fp}`;
      if (seen.has(key)) return;
      seen.add(key);
      entries.push({
        filePath: fp,
        category: cat,
        originType: "file",
        recoverCommitSha: c.commit_hash,
        blobHash: "",
        displaySha: c.commit_hash,
        author: c.author || "Unknown",
        date: (c.date || "").slice(0, 16),
        note: "Historical Commit Snapshot",
      });
    });
  });

  // 3. Detached Blobs
  (data.dangling_blobs || []).forEach((b) => {
    const key = `blob:${b.blob_hash}`;
    if (seen.has(key)) return;
    seen.add(key);
    entries.push({
      filePath: b.associated_path || `detached_blob_${b.blob_hash.slice(0, 8)}.txt`,
      category: classifyConfigCategory(b.associated_path || "") || "credential",
      originType: "blob",
      recoverCommitSha: "",
      blobHash: b.blob_hash,
      displaySha: b.blob_hash,
      author: "Detached Git Blob",
      date: `${b.size || 0} bytes`,
      note: "Unlinked Blob",
    });
  });

  return entries;
}

function filterTimeMachine() {
  const tbody = document.getElementById("timeMachineTableBody");
  if (!tbody || !currentScanData) return;

  cachedTimeMachineEntries = buildTimeMachineEntries(currentScanData);
  const q = ((document.getElementById("timeMachineFilter") || {}).value || "").trim().toLowerCase();
  const catFilter = (document.getElementById("timeMachineTypeFilter") || {}).value || "ALL";

  const filtered = cachedTimeMachineEntries.filter((e) => {
    if (catFilter !== "ALL" && e.category !== catFilter) return false;
    if (!q) return true;
    return e.filePath.toLowerCase().includes(q) || (e.displaySha || "").toLowerCase().includes(q);
  });

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px;">No matching .env or sensitive configuration snapshots found in this repository.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered
    .map((e) => {
      const realIdx = cachedTimeMachineEntries.indexOf(e);
      const badgeCls = e.category === "env" || e.category === "key" ? "badge-critical" : "badge-medium";
      return `<tr>
        <td class="ltr-mono" style="font-weight:700;color:#ffffff;">${escapeHtml(e.filePath)}</td>
        <td><span class="badge ${badgeCls}">${escapeHtml(e.category.toUpperCase())}</span></td>
        <td class="ltr-mono"><span class="code-chip">${escapeHtml((e.displaySha || "").slice(0, 10))}</span> <span style="font-size:11.5px;color:var(--text-muted);">${escapeHtml(e.note)}</span></td>
        <td class="ltr-mono" style="font-size:12px;color:var(--text-secondary);">${escapeHtml(e.author)} • ${escapeHtml(e.date)}</td>
        <td>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-secondary btn-sm" onclick="previewTimeMachineEntry(${realIdx})">Preview</button>
            <button class="btn btn-emerald btn-sm" onclick="downloadTimeMachineEntry(${realIdx})">Save File</button>
          </div>
        </td>
      </tr>`;
    })
    .join("");
}

async function fetchTimeMachineContent(entry) {
  const includeRaw = Boolean((document.getElementById("includeRawToggle") || {}).checked);
  const payload =
    entry.originType === "blob"
      ? { repo_path: activeRepoTarget, object_type: "blob", blob_hash: entry.blobHash, include_raw: includeRaw }
      : {
          repo_path: activeRepoTarget,
          object_type: "file",
          commit_hash: entry.recoverCommitSha,
          file_path: entry.filePath,
          include_raw: includeRaw,
        };
  const resp = await apiFetch("/api/recover/file", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const res = await resp.json();
  if (!resp.ok || res.error) throw new Error(res.error || "Could not recover snapshot");
  return res;
}

async function previewTimeMachineEntry(idx) {
  const entry = cachedTimeMachineEntries[idx];
  if (!entry) return;
  try {
    const res = await fetchTimeMachineContent(entry);
    activeModalContext = {
      type: "file",
      filename: res.filename || entry.filePath.split("/").pop() || "recovered.env",
      content: res.content || "",
      copyText: res.content || "",
    };
    document.getElementById("modalTitle").textContent = entry.filePath;
    document.getElementById("modalSubtitle").textContent = `${entry.note} • ${res.is_redacted ? "Strict Redaction Active" : "Raw Unmasked"}`;
    document.getElementById("modalTriageMeta").style.display = "none";
    renderDiffLines(document.getElementById("modalCodeView"), res.content || "(empty file)");
    document.getElementById("modalVerifyBtn").style.display = "none";
    document.getElementById("modalCopyBtn").style.display = "inline-flex";
    document.getElementById("modalRecoverBtn").style.display = "inline-flex";
    document.getElementById("detailModal").classList.add("active");
  } catch (err) {
    showToast(`${err.message}`);
  }
}

async function downloadTimeMachineEntry(idx) {
  const entry = cachedTimeMachineEntries[idx];
  if (!entry) return;
  try {
    const res = await fetchTimeMachineContent(entry);
    await saveTextArtifact(res.filename || entry.filePath.split("/").pop() || "recovered_config.txt", res.content || "");
  } catch (err) {
    showToast(`${err.message}`);
  }
}

/* ---- View 5: Deep Search & Detached Blobs ---- */
async function runDeepSearch() {
  const q = ((document.getElementById("deepSearchInput") || {}).value || "").trim();
  const box = document.getElementById("deepSearchResults");
  if (!box) return;
  if (!currentScanData || !activeRepoTarget) {
    showToast(t("invalidGhUrl"));
    return;
  }
  if (!q) return;

  box.style.display = "flex";
  box.innerHTML = `<div style="color:var(--cyan-bright);font-size:12.5px;" class="ltr-mono">Searching across all commits, diffs, and blobs...</div>`;

  try {
    const resp = await apiFetch("/api/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_path: activeRepoTarget, query: q }),
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error || "Search error");
    const matches = data.matches || [];
    if (!matches.length) {
      box.innerHTML = `<div style="color:var(--text-muted);font-size:13px;">0 matches found for "${escapeHtml(q)}".</div>`;
      return;
    }
    box.innerHTML = matches
      .map((m) => {
        const sub = m.is_dangling ? "dangling" : "branch";
        const clickHandler =
          m.kind === "commit"
            ? `jumpToCommit('${escapeHtml(m.hash)}', '${sub}')`
            : m.kind === "blob"
            ? `inspectDetachedBlob('${escapeHtml(m.hash)}')`
            : `inspectFinding('${escapeHtml(m.finding_id || "")}', 0)`;
        return `<div class="commit-item-card" onclick="${clickHandler}">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span class="badge badge-medium">${escapeHtml((m.kind || "match").toUpperCase())}</span>
            <span class="code-chip">${escapeHtml((m.hash || "").slice(0, 10))}</span>
          </div>
          <div style="font-weight:700;color:#ffffff;margin-top:5px;">${escapeHtml(m.title || "")}</div>
          <div style="font-size:11.5px;color:var(--text-muted);margin-top:2px;" class="ltr-mono">${escapeHtml(m.subtitle || "")}</div>
          <div style="font-size:12px;color:var(--neon-green);margin-top:4px;" class="ltr-mono">${escapeHtml(m.snippet || "")}</div>
        </div>`;
      })
      .join("");
  } catch (err) {
    box.innerHTML = `<div class="term-err">${escapeHtml(err.message)}</div>`;
  }
}

function renderDetachedBlobs(blobs) {
  const pill = document.getElementById("blobsCountPill");
  const grid = document.getElementById("danglingBlobsList");
  if (pill) pill.textContent = `${blobs.length} blobs`;
  if (!grid) return;

  if (!blobs.length) {
    grid.innerHTML = `<div style="color:var(--text-muted);font-size:13px;">0 detached unlinked blobs in remote packfiles.</div>`;
    return;
  }

  grid.innerHTML = blobs
    .map(
      (b) => `<div class="card" style="display:flex;flex-direction:column;justify-content:space-between;gap:10px;">
        <div>
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span class="code-chip">${escapeHtml(b.blob_hash.slice(0, 12))}</span>
            <span style="font-size:11.5px;color:var(--text-muted);" class="ltr-mono">${b.size || 0} B</span>
          </div>
          <pre style="margin-top:8px;font-family:var(--font-mono);font-size:11.5px;color:var(--text-secondary);white-space:pre-wrap;max-height:90px;overflow:hidden;" class="ltr-mono">${escapeHtml((b.redacted_content || "").slice(0, 220))}</pre>
        </div>
        <div style="display:flex;gap:6px;">
          <button class="btn btn-secondary btn-sm" onclick="inspectDetachedBlob('${escapeHtml(b.blob_hash)}')">Inspect</button>
        </div>
      </div>`
    )
    .join("");
}

async function inspectDetachedBlob(blobSha) {
  try {
    const includeRaw = Boolean((document.getElementById("includeRawToggle") || {}).checked);
    const resp = await apiFetch("/api/recover/file", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repo_path: activeRepoTarget,
        object_type: "blob",
        blob_hash: blobSha,
        include_raw: includeRaw,
      }),
    });
    const res = await resp.json();
    if (!resp.ok || res.error) throw new Error(res.error || "Blob fetch failed");
    activeModalContext = {
      type: "file",
      filename: res.filename || `blob_${blobSha.slice(0, 10)}.txt`,
      content: res.content || "",
      copyText: res.content || "",
    };
    document.getElementById("modalTitle").textContent = `אובייקט Git מנותק (Blob) ${blobSha.slice(0, 12)}`;
    document.getElementById("modalSubtitle").textContent = res.is_redacted ? "Strict Redaction Active" : "Raw Unmasked Blob";
    document.getElementById("modalTriageMeta").style.display = "none";
    renderDiffLines(document.getElementById("modalCodeView"), res.content || "");
    document.getElementById("modalVerifyBtn").style.display = "none";
    document.getElementById("modalCopyBtn").style.display = "inline-flex";
    document.getElementById("modalRecoverBtn").style.display = "inline-flex";
    document.getElementById("detailModal").classList.add("active");
  } catch (err) {
    showToast(`${err.message}`);
  }
}

/* ---- View 6: GitHub History Purge & Remediation ---- */
function renderRemediation(rem) {
  if (rem.rotation_warning) {
    document.getElementById("remediationRotationWarning").textContent = rem.rotation_warning;
  }
  const stepsBox = document.getElementById("remediationStepsList");
  const steps = rem.steps || [];
  if (stepsBox) {
    stepsBox.innerHTML = steps
      .map(
        (s, i) => `<div style="padding:11px 14px;margin-bottom:8px;border-radius:9px;background:var(--bg-card);border:1px solid var(--border);font-size:13px;">
          <div style="font-weight:800;color:var(--neon-green);margin-bottom:3px;">Step ${s.order || i + 1}: ${escapeHtml(s.title || "")}</div>
          <div style="color:var(--text-secondary);font-size:12.5px;">${escapeHtml(s.description || "")}</div>
        </div>`
      )
      .join("");
  }
  document.getElementById("remediationBashScript").textContent = rem.bash_script || "# No Bash script generated";
  document.getElementById("remediationPSScript").textContent = rem.powershell_script || "# No PowerShell script generated";
  document.getElementById("remediationSupportTicket").textContent =
    rem.github_support_ticket ||
    `Subject: Urgent Request to Purge Cached Commit SHAs on ${activeGithubHtmlUrl || "Repository"}\n\nHello GitHub Support,\n\nWe recently performed a history rewrite (git filter-repo + force push) on ${activeGithubHtmlUrl || "<owner/repo>"} to excise sensitive data. Please purge all unreachable/cached commit views and pull-request refs on GitHub's servers.\n\nThank you.`;
}

function switchScriptTab(lang) {
  activeScriptLang = lang;
  document.getElementById("btnScriptBash").classList.toggle("active", lang === "bash");
  document.getElementById("btnScriptPS").classList.toggle("active", lang === "ps");
  document.getElementById("bashScriptContainer").style.display = lang === "bash" ? "block" : "none";
  document.getElementById("psScriptContainer").style.display = lang === "ps" ? "block" : "none";
}

async function copyActiveScript() {
  const txt =
    activeScriptLang === "bash"
      ? document.getElementById("remediationBashScript").textContent
      : document.getElementById("remediationPSScript").textContent;
  await writeClipboardTextSafe(txt);
  showToast("Remediation script copied to clipboard");
}

async function saveActiveScriptAs() {
  const isBash = activeScriptLang === "bash";
  const txt = isBash
    ? document.getElementById("remediationBashScript").textContent
    : document.getElementById("remediationPSScript").textContent;
  await saveTextArtifact(isBash ? "purge_github_history.sh" : "purge_github_history.ps1", txt);
}

async function copySupportTicket() {
  const txt = document.getElementById("remediationSupportTicket").textContent;
  await writeClipboardTextSafe(txt);
  showToast("GitHub Support purge ticket copied");
}

/* ---- Modal Helpers & Artifact Saving ---- */
function closeModal() {
  document.getElementById("detailModal").classList.remove("active");
}

async function copyModalContent() {
  if (!activeModalContext) return;
  await writeClipboardTextSafe(activeModalContext.copyText || "");
  showToast("Copied to clipboard");
}

async function recoverFromActiveModal() {
  if (!activeModalContext) return;
  if (activeModalContext.type === "file") {
    await saveTextArtifact(activeModalContext.filename || "artifact.txt", activeModalContext.content || "");
    return;
  }
  if (activeModalContext.type === "finding") {
    const f = activeModalContext.finding;
    const includeRaw = Boolean((document.getElementById("includeRawToggle") || {}).checked);
    try {
      const resp = await apiFetch("/api/recover/file", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_path: activeRepoTarget,
          object_type: f.blob_hash && !f.commit_hash ? "blob" : "file",
          commit_hash: f.commit_hash || "",
          blob_hash: f.blob_hash || "",
          file_path: f.file_path || "",
          include_raw: includeRaw,
        }),
      });
      const res = await resp.json();
      if (!resp.ok || res.error) throw new Error(res.error || "Export failed");
      await saveTextArtifact(res.filename || "finding_artifact.txt", res.content || "");
    } catch (err) {
      showToast(`${err.message}`);
    }
  }
}

async function saveTextArtifact(defaultFilename, content) {
  if (window.unforceDesktop && typeof window.unforceDesktop.saveFileDialog === "function") {
    const res = await window.unforceDesktop.saveFileDialog({
      defaultPath: defaultFilename,
      content: String(content ?? ""),
      encoding: "utf8",
    });
    if (res && res.saved) {
      showToast(`Saved: ${res.filePath}`);
    }
    return;
  }
  const blob = new Blob([String(content ?? "")], { type: "text/plain;charset=utf-8" });
  triggerBrowserDownload(blob, defaultFilename);
  showToast(`Downloaded ${defaultFilename}`);
}

function triggerBrowserDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

/* ---- Top Toolbar Exports (ZIP Bundle, JSON, MD, SARIF) ---- */
async function downloadReport(fmt) {
  if (!currentScanData || !activeRepoTarget) {
    showToast(t("invalidGhUrl"));
    return;
  }
  try {
    const qRepo = encodeURIComponent(activeRepoTarget);
    const resp = await apiFetch(`/api/download/report?repo_path=${qRepo}&format=${encodeURIComponent(fmt)}`);
    if (!resp.ok) {
      const errJson = await resp.json().catch(() => ({}));
      throw new Error(errJson.error || `HTTP ${resp.status}`);
    }
    const text = await resp.text();
    const ext = fmt === "markdown" ? "md" : fmt === "sarif" ? "sarif" : "json";
    await saveTextArtifact(`unforce_audit_report.${ext}`, text);
  } catch (err) {
    showToast(`${err.message}`);
  }
}

function exportSARIF() {
  return downloadReport("sarif");
}

async function downloadRecoveryBundle() {
  if (!currentScanData || !activeRepoTarget) {
    showToast(t("invalidGhUrl"));
    return;
  }
  try {
    const includeRaw = Boolean((document.getElementById("includeRawToggle") || {}).checked);
    const qRepo = encodeURIComponent(activeRepoTarget);
    const resp = await apiFetch(`/api/download/bundle?repo_path=${qRepo}&include_raw=${includeRaw ? "true" : "false"}`);
    if (!resp.ok) {
      const errJson = await resp.json().catch(() => ({}));
      throw new Error(errJson.error || `HTTP ${resp.status}`);
    }
    const arrayBuf = await resp.arrayBuffer();
    const defaultName = "unforce_recovery_bundle.zip";

    if (window.unforceDesktop && typeof window.unforceDesktop.saveFileDialog === "function") {
      const bytes = new Uint8Array(arrayBuf);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
      const b64 = btoa(binary);
      const saved = await window.unforceDesktop.saveFileDialog({
        defaultPath: defaultName,
        content: b64,
        encoding: "base64",
      });
      if (saved && saved.saved) showToast(`Saved ZIP Bundle: ${saved.filePath}`);
      return;
    }
    triggerBrowserDownload(new Blob([arrayBuf], { type: "application/zip" }), defaultName);
    showToast(`Downloaded ${defaultName}`);
  } catch (err) {
    showToast(`${err.message}`);
  }
}

/* ---- Settings & Ephemeral In-Memory Credentials ---- */
function openSettingsModal() {
  document.getElementById("settingsModal").classList.add("active");
  updateAISettingsUI();
  refreshGHStatusUI();
}
function closeSettingsModal() {
  document.getElementById("settingsModal").classList.remove("active");
}

function updateAISettingsUI() {
  const prov = (document.getElementById("aiProviderSelect") || {}).value || "heuristic";
  const labelMap = {
    heuristic: "AI: Heuristic",
    auto: "AI: Auto",
    gemini: "AI: Gemini",
    openai: "AI: OpenAI",
    anthropic: "AI: Claude",
    ollama: "AI: Ollama",
    none: "AI: Off",
  };
  document.getElementById("aiStatusText").textContent = labelMap[prov] || "AI: Heuristic";
  const needsKey = ["gemini", "openai", "anthropic", "auto"].includes(prov);
  const hasKey = Boolean(ephemeralSession.aiKey);
  document.getElementById("aiKeyInputRow").style.display = needsKey && !hasKey ? "flex" : "none";
  document.getElementById("aiKeyConfiguredRow").style.display = hasKey ? "flex" : "none";
}

function saveAIKey() {
  const val = (document.getElementById("aiApiKeyInput").value || "").trim();
  if (!val) return;
  ephemeralSession.aiKey = val;
  document.getElementById("aiApiKeyInput").value = "";
  updateAISettingsUI();
  showToast("AI API Key held strictly in-memory");
}

function clearAIKey() {
  ephemeralSession.aiKey = "";
  updateAISettingsUI();
}

function saveGHToken() {
  const val = (document.getElementById("githubTokenInput").value || "").trim();
  if (!val) return;
  ephemeralSession.ghToken = val;
  document.getElementById("githubTokenInput").value = "";
  refreshGHStatusUI();
  showToast("GitHub Token held strictly in-memory");
}

function clearGHToken() {
  ephemeralSession.ghToken = "";
  refreshGHStatusUI();
}

function refreshGHStatusUI() {
  const inRow = document.getElementById("ghTokenInputRow");
  const okRow = document.getElementById("ghTokenConfiguredRow");
  const autoNote = document.getElementById("ghSystemAuthNotice");
  const ghText = document.getElementById("ghStatusText");
  const ghDot = document.getElementById("ghDot");
  const hasCustom = Boolean(ephemeralSession.ghToken);

  inRow.style.display = hasCustom ? "none" : "flex";
  okRow.style.display = hasCustom ? "flex" : "none";
  autoNote.style.display = ephemeralSession.ghAutoDetected ? "block" : "none";

  if (hasCustom) {
    ghText.textContent = "GH: Custom PAT";
    ghDot.className = "dot dot-green";
  } else if (ephemeralSession.ghAutoDetected) {
    ghText.textContent = "GH: Auto-Auth";
    ghDot.className = "dot dot-green";
  } else {
    ghText.textContent = "GH: Public";
    ghDot.className = "dot dot-cyan";
  }
}

function toggleRawRecoveryMode(enabled) {
  showToast(enabled ? "Raw unredacted file export enabled" : "Strict Redaction Active", enabled ? "warn" : "success");
}

/* ---- Command Palette (Ctrl+K) ---- */
function getPaletteCommands() {
  return [
    {
      label: "Paste Repository URL & Scan",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
      action: () => pasteAndScanGitHub()
    },
    {
      label: "Jump to Command HUD & Hygiene Score",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>',
      action: () => switchView("overview")
    },
    {
      label: "Jump to Commit & File-Tree Explorer",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><line x1="1.05" y1="12" x2="7" y2="12"/><line x1="17.01" y1="12" x2="22.96" y2="12"/></svg>',
      action: () => switchView("commits")
    },
    {
      label: "Jump to Discovered Secrets & AI Triage",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="7.5" cy="15.5" r="5.5"></circle><path d="m21 2-9.6 9.6"></path><path d="m15.5 7.5 3 3L22 7l-3-3"></path></svg>',
      action: () => switchView("findings")
    },
    {
      label: "Jump to .env & Config Time-Machine",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>',
      action: () => switchView("timemachine")
    },
    {
      label: "Jump to Deep Search & Detached Blobs",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
      action: () => switchView("searchblobs")
    },
    {
      label: "Jump to GitHub History Purge Playbook",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
      action: () => switchView("remediation")
    },
    {
      label: "Export Full Recovery Bundle (.ZIP)",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
      action: () => downloadRecoveryBundle()
    },
    {
      label: "Switch Language (עברית / English)",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>',
      action: () => toggleLanguage()
    },
    {
      label: "Open Settings & Credentials",
      iconSvg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>',
      action: () => openSettingsModal()
    },
  ];
}






  if (cmdSelectedIndex >= items.length) cmdSelectedIndex = 0;
  list.innerHTML = items
    .map(
      (item, idx) => `<button class="cmd-item ${idx === cmdSelectedIndex ? "selected" : ""}" onclick="runPaletteCommand(${idx})">
        <span class="cmd-item-icon">${item.iconSvg || ""}</span>
        <span>${escapeHtml(item.label)}</span>
      </button>`
    )
    .join("");
}



 else if (e.key === "ArrowDown") {
    e.preventDefault();
    cmdSelectedIndex = (cmdSelectedIndex + 1) % Math.max(items.length, 1);
    renderCmdPaletteItems();
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    cmdSelectedIndex = (cmdSelectedIndex - 1 + Math.max(items.length, 1)) % Math.max(items.length, 1);
    renderCmdPaletteItems();
  } else if (e.key === "Enter" && items.length) {
    e.preventDefault();
    runPaletteCommand(cmdSelectedIndex);
  }
}

/* ---- Boot Initialization ---- */
function applyEmbeddedLogo() {
  const uri = window.UNFORCE_LOGO_DATA_URI;
  if (!uri) return;
  const tbImg = document.getElementById("titlebarLogoImg");
  const tbSvg = document.getElementById("titlebarFallbackSvg");
  if (tbImg) {
    tbImg.src = uri;
    tbImg.style.display = "inline-block";
    if (tbSvg) tbSvg.style.display = "none";
  }
  const sbImg = document.getElementById("sidebarLogoImg");
  const sbSvg = document.getElementById("sidebarFallbackSvg");
  if (sbImg) {
    sbImg.src = uri;
    sbImg.style.display = "block";
    if (sbSvg) sbSvg.style.display = "none";
  }
}

async function initBackendTelemetry() {
  try {
    const resp = await apiFetch("/api/system/info");
    if (!resp.ok) return;
    const info = await resp.json();
    const gitText = document.getElementById("gitHealthText");
    if (gitText && info.git_version) {
      gitText.textContent = info.git_version.replace("git version ", "GIT ");
    }
    if (info.version) {
      document.getElementById("titlebarVerBadge").textContent = `v${info.version}`;
      document.getElementById("footerVersionText").textContent = `v${info.version}`;
    }
    ephemeralSession.ghAutoDetected = Boolean(info.github_auth_auto);
    refreshGHStatusUI();
    if (info.github_auth_auto) {
      logTerminal("AUTH", "Git Credential Manager detected -> Private & Public GitHub repos enabled automatically.", "ok");
    }
  } catch (_) {}
}

function initDragAndDrop() {
  const row = document.querySelector(".target-bar-row");
  window.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (row) row.classList.add("drag-over");
  });
  window.addEventListener("dragleave", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (row && e.relatedTarget === null) row.classList.remove("drag-over");
  });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (row) row.classList.remove("drag-over");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const filePath = file.path || file.name;
      if (filePath) {
        const input = document.getElementById("repoPathInput");
        if (input) {
          input.value = filePath;
          updateTargetTypeBadge();
          logTerminal("DROP", `Local repository dropped: ${filePath}`, "ok");
          startScan();
        }
      }
    }
  });
}

document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    // cmdPalette removed
  } else if (e.key === "Escape") {
    closeModal();
    closeSettingsModal();
    closeCmdPalette();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  if (!window.unforceDesktop || !window.unforceDesktop.isElectron) {
    const winControls = document.querySelector(".titlebar-controls");
    if (winControls) winControls.style.display = "none";
  }
  applyEmbeddedLogo();
  applyLanguage();
  initDragAndDrop();

  const params = new URLSearchParams(window.location.search);
  const initialRepo = params.get("repo");
  if (initialRepo && parseGitHubRepoInput(initialRepo)) {
    const input = document.getElementById("repoPathInput");
    input.value = parseGitHubRepoInput(initialRepo).cleanUrl;
    updateTargetTypeBadge();
    setTimeout(() => startScan(), 60);
  }

  initBackendTelemetry();
  setUiState("landing");
  checkAppVersion(false);
  setInterval(() => checkAppVersion(false), 10 * 60 * 1000);
  setInterval(syncLogsFromServer, 3500);
});
