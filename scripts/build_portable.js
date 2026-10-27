const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const nsiScript = path.join(root, "scripts", "package_portable.nsi");
const releaseDir = path.join(root, "release");
const desktopDist = path.join(root, "desktop", "dist");
const winUnpacked = path.join(desktopDist, "win-unpacked");

if (!fs.existsSync(releaseDir)) fs.mkdirSync(releaseDir, { recursive: true });

// Locate makensis
let makensisCmd = "makensis";
try {
  execSync("makensis /VERSION", { stdio: "ignore" });
} catch (_) {
  const standardPaths = [
    "C:\\Program Files (x86)\\NSIS\\makensis.exe",
    "C:\\Program Files\\NSIS\\makensis.exe",
    path.join(process.env["ProgramFiles(x86)"] || "", "NSIS", "makensis.exe"),
    path.join(process.env.ProgramFiles || "", "NSIS", "makensis.exe"),
  ];
  let foundStd = standardPaths.find((p) => p && fs.existsSync(p));
  if (foundStd) {
    makensisCmd = `"${foundStd}"`;
  } else {
    const localAppData = process.env.LOCALAPPDATA || "";
    const nsisCache = path.join(localAppData, "electron-builder", "cache", "nsis");
    if (fs.existsSync(nsisCache)) {
      const findMakensis = (dir) => {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const e of entries) {
          const full = path.join(dir, e.name);
          if (e.isDirectory()) {
            const res = findMakensis(full);
            if (res) return res;
          } else if (e.name.toLowerCase() === "makensis.exe") {
            return full;
          }
        }
        return null;
      };
      const found = findMakensis(nsisCache);
      if (found) makensisCmd = `"${found}"`;
    }
  }
}

let compiledPortable = false;
try {
  console.log(`[build_portable] Compiling portable package with ${makensisCmd}...`);
  execSync(`${makensisCmd} "/DSOURCE_DIR=${winUnpacked}" "${nsiScript}"`, {
    cwd: path.join(root, "scripts"),
    stdio: "inherit",
  });
  compiledPortable = true;
} catch (err) {
  console.warn(`[build_portable] Warning: makensis build failed (${err.message}). Using fallback executable packaging.`);
}

const builtExe = path.join(releaseDir, "UnForce-Portable.exe");
if (compiledPortable && fs.existsSync(builtExe)) {
  fs.copyFileSync(builtExe, path.join(desktopDist, "UnForce-Portable.exe"));
  console.log(`[build_portable] Copied UnForce-Portable.exe to ${desktopDist}`);
} else {
  const rawExe = path.join(winUnpacked, "UnForce.exe");
  if (fs.existsSync(rawExe)) {
    fs.copyFileSync(rawExe, path.join(desktopDist, "UnForce-Portable.exe"));
    console.log(`[build_portable] Fallback: Copied standalone UnForce.exe to ${path.join(desktopDist, "UnForce-Portable.exe")}`);
  }
}
