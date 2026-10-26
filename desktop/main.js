"use strict";

const { app, BrowserWindow, clipboard, dialog, ipcMain, shell } = require("electron");
const { spawn, execFile } = require("child_process");
const fs = require("fs");
const http = require("http");
const path = require("path");

const isSmokeTest = process.argv.includes("--smoke-test");

// Speed up Chromium cold-start on Windows
app.commandLine.appendSwitch("disable-http-cache");
app.commandLine.appendSwitch("no-proxy-server");

let mainWindow = null;
let backendProcess = null;
let backendUrl = process.env.UNFORCE_SERVER_URL || "";
let backendReadyPromise = null;
let isQuitting = false;

function extractInitialGitHubUrlArg(argv) {
  for (let i = 1; i < argv.length; i++) {
    const arg = String(argv[i] || "").trim();
    if (arg === "--repo" && argv[i + 1]) {
      return String(argv[i + 1]).trim();
    }
    if (/^(https?:\/\/)?(www\.)?github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+/i.test(arg)) {
      return arg;
    }
  }
  return "";
}

function resolveBackendCommand() {
  const exeName = process.platform === "win32" ? "unforce-engine.exe" : "unforce-engine";

  if (app.isPackaged) {
    const packagedExe = path.join(process.resourcesPath, "backend", exeName);
    return { cmd: packagedExe, args: ["--daemon", "--port", "0"], cwd: process.resourcesPath };
  }

  const devBuiltExe = path.resolve(__dirname, "..", "build_backend", "unforce-engine", exeName);
  if (fs.existsSync(devBuiltExe)) {
    return {
      cmd: devBuiltExe,
      args: ["--daemon", "--port", "0"],
      cwd: path.dirname(devBuiltExe),
    };
  }

  const pyCmd = process.platform === "win32" ? "python" : "python3";
  return {
    cmd: pyCmd,
    args: ["-m", "gitghost", "--daemon", "--port", "0"],
    cwd: path.resolve(__dirname, ".."),
  };
}

function startBackendDaemon() {
  if (backendUrl) {
    return Promise.resolve(backendUrl);
  }
  if (backendReadyPromise) {
    return backendReadyPromise;
  }

  backendReadyPromise = new Promise((resolve, reject) => {
    const { cmd, args, cwd } = resolveBackendCommand();
    let settled = false;
    let stdoutBuf = "";
    let stderrBuf = "";

    try {
      backendProcess = spawn(cmd, args, {
        cwd,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, PYTHONIOENCODING: "utf-8", PYTHONDONTWRITEBYTECODE: "1" },
      });
    } catch (err) {
      return reject(err);
    }

    const startupTimeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(new Error("Timed out waiting for UnForce forensics engine.\n" + stderrBuf));
      }
    }, 15000);

    backendProcess.stdout.on("data", (chunk) => {
      stdoutBuf += chunk.toString("utf8");
      const lines = stdoutBuf.split(/\r?\n/);
      stdoutBuf = lines.pop() || "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("{")) continue;
        try {
          const parsed = JSON.parse(trimmed);
          if (parsed && parsed.event === "server_ready" && parsed.url && !settled) {
            settled = true;
            clearTimeout(startupTimeout);
            backendUrl = parsed.url;
            resolve(backendUrl);
          }
        } catch (_) {}
      }
    });

    backendProcess.stderr.on("data", (chunk) => {
      stderrBuf += chunk.toString("utf8");
    });

    backendProcess.on("error", (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(startupTimeout);
        reject(err);
      }
    });

    backendProcess.on("exit", (code) => {
      backendProcess = null;
      if (!settled) {
        settled = true;
        clearTimeout(startupTimeout);
        reject(new Error(`Backend engine exited prematurely (code ${code}).\n${stderrBuf}`));
      }
    });
  });

  return backendReadyPromise;
}

function stopBackendDaemon() {
  if (backendUrl && !process.env.UNFORCE_SERVER_URL) {
    try {
      const u = new URL("/api/shutdown", backendUrl);
      const req = http.request(
        {
          hostname: u.hostname,
          port: u.port,
          path: u.pathname,
          method: "POST",
          timeout: 500,
        },
        () => {}
      );
      req.on("error", () => {});
      req.end("{}");
    } catch (_) {}
  }

  if (backendProcess && backendProcess.pid) {
    const pid = backendProcess.pid;
    backendProcess = null;
    if (process.platform === "win32") {
      execFile("taskkill", ["/PID", String(pid), "/T", "/F"], { windowsHide: true }, () => {});
    } else {
      try {
        process.kill(pid, "SIGTERM");
      } catch (_) {}
    }
  }
}

function createMainWindow() {
  const iconFile =
    process.platform === "win32"
      ? path.join(__dirname, "assets", "icon.ico")
      : path.join(__dirname, "assets", "icon.png");

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 870,
    minWidth: 1020,
    minHeight: 660,
    frame: false,
    show: false,
    backgroundColor: "#03060d",
    icon: fs.existsSync(iconFile) ? iconFile : undefined,
    title: "UnForce (ForcePush-Breaker)",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      backgroundThrottling: false,
    },
  });

  mainWindow.setMenuBarVisibility(false);

