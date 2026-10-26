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

  if (!isSmokeTest) {
    mainWindow.once("ready-to-show", () => {
      if (mainWindow) mainWindow.show();
    });
  }

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url) && (!backendUrl || !url.startsWith(backendUrl))) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });

  return mainWindow;
}

// ---- IPC Handlers ----
ipcMain.handle("unforce:get-backend-url", async () => {
  if (backendUrl) return backendUrl;
  return await startBackendDaemon();
});

ipcMain.handle("unforce:read-clipboard", () => {
  try {
    return clipboard.readText() || "";
  } catch (_) {
    return "";
  }
});

ipcMain.handle("unforce:write-clipboard", (_event, text) => {
  try {
    clipboard.writeText(String(text ?? ""));
    return true;
  } catch (_) {
    return false;
  }
});

ipcMain.handle("unforce:save-file", async (_event, opts) => {
  if (!mainWindow || !opts) return { saved: false };
  const defaultPath = opts.defaultPath || "recovered_artifact.txt";
  const ext = path.extname(defaultPath).replace(".", "").toLowerCase();
  const filters = ext
    ? [
        { name: `${ext.toUpperCase()} File`, extensions: [ext] },
        { name: "All Files", extensions: ["*"] },
      ]
    : [{ name: "All Files", extensions: ["*"] }];

  const result = await dialog.showSaveDialog(mainWindow, {
    title: "Save Recovered Artifact / Report",
    defaultPath,
    filters,
  });

  if (result.canceled || !result.filePath) {
    return { saved: false };
  }

  const buf =
    opts.encoding === "base64"
      ? Buffer.from(opts.content || "", "base64")
      : Buffer.from(String(opts.content ?? ""), "utf8");

  fs.writeFileSync(result.filePath, buf);
  return { saved: true, filePath: result.filePath };
});

ipcMain.handle("unforce:open-external", async (_event, url) => {
  if (url && /^https?:\/\//i.test(url)) {
    await shell.openExternal(url);
    return true;
  }
  return false;
});

ipcMain.handle("unforce:app-info", () => ({
  version: app.getVersion(),
  isPackaged: app.isPackaged,
  platform: process.platform,
  backendUrl,
}));

ipcMain.on("unforce:win-minimize", () => {
  if (mainWindow) mainWindow.minimize();
});

ipcMain.on("unforce:win-maximize", () => {
  if (!mainWindow) return;
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow.maximize();
  }
});

ipcMain.on("unforce:win-close", () => {
  if (mainWindow) mainWindow.close();
});

// ---- Single Instance & Ultra-Fast Parallel Boot ----
const gotLock = isSmokeTest ? true : app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  // Kick off Python daemon immediately before even waiting for GPU/Window init!
  const daemonBoot = startBackendDaemon();
  daemonBoot.catch(() => {});

  app.on("second-instance", (_event, commandLine) => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
      const ghArg = extractInitialGitHubUrlArg(commandLine);
      if (ghArg) {
        mainWindow.webContents
          .executeJavaScript(`loadSampleGitHubUrl(${JSON.stringify(ghArg)})`)
          .catch(() => {});
      }
    }
  });

  app.whenReady().then(async () => {
    const win = createMainWindow();
    const initialRepo = extractInitialGitHubUrlArg(process.argv);
    const localBundle = path.join(__dirname, "ui_bundle.html");

    try {
      if (fs.existsSync(localBundle)) {
        const query = initialRepo ? { query: { repo: initialRepo } } : undefined;
        await win.loadFile(localBundle, query);
      } else {
        const url = await daemonBoot;
        const targetUrl = initialRepo ? `${url}/?repo=${encodeURIComponent(initialRepo)}` : `${url}/`;
        await win.loadURL(targetUrl);
      }

      if (isSmokeTest) {
        const url = await daemonBoot;
        const title = win.getTitle();
        const hasDom = await win.webContents.executeJavaScript(
          "Boolean(document.getElementById('repoPathInput') && window.unforceDesktop && window.unforceDesktop.isElectron)"
        );
        if (hasDom && url) {
          process.stdout.write(`SMOKE_TEST_OK title=${JSON.stringify(title)} url=${url}\n`);
          isQuitting = true;
          stopBackendDaemon();
          app.exit(0);
        } else {
          process.stderr.write("SMOKE_TEST_FAILED: DOM or backend bridge missing\n");
          isQuitting = true;
          stopBackendDaemon();
          app.exit(1);
        }
      } else {
        // Surface backend startup errors cleanly if daemon fails
        daemonBoot.catch((err) => {
          dialog.showErrorBox(
            "UnForce Engine Startup Error",
            `Could not start the local forensics backend:\n\n${err.message}`
          );
        });
      }
    } catch (err) {
      if (isSmokeTest) {
        process.stderr.write(`SMOKE_TEST_ERROR: ${err.message}\n`);
        stopBackendDaemon();
        app.exit(1);
        return;
      }
      dialog.showErrorBox(
        "UnForce Startup Error",
        `Could not initialize UnForce Studio:\n\n${err.message}`
      );
      app.quit();
    }
  });

  app.on("before-quit", () => {
    isQuitting = true;
    stopBackendDaemon();
  });

  app.on("window-all-closed", () => {
    if (!isQuitting) {
      stopBackendDaemon();
    }
    if (process.platform !== "darwin") {
      app.quit();
    }
  });
}
