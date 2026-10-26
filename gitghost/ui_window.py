"""
Window Launcher for ForcePush-Breaker (UnForce) / GitGhost Desktop Dashboard.
Prioritizes bundled Electron Chromium shell, Chromium/Edge app-mode window, pywebview, or system browser fallback.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Optional

from rich.console import Console

from gitghost.ui_server import start_ui_server

console = Console()


def _find_chromium_binary() -> Optional[str]:
    """Locates an installed Chromium-based browser (Chrome, Edge, Brave) for native `--app=` windowing fallback."""
    candidates = []
    if sys.platform == "win32":
        pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
        local = os.environ.get("LOCALAPPDATA", "")
        candidates.extend([
            os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(local, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(pf, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
        ])
    elif sys.platform == "darwin":
        candidates.extend([
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ])
    else:
        for cmd in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"):
            found = shutil.which(cmd)
            if found:
                candidates.append(found)

    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _try_launch_electron_shell(url: str, initial_repo: str) -> bool:
    """Attempts to launch the Electron Chromium Desktop shell if present in the repository."""
    project_root = Path(__file__).resolve().parent.parent
    desktop_dir = project_root / "desktop"
    electron_bin = (
        desktop_dir / "node_modules" / ".bin" / ("electron.cmd" if sys.platform == "win32" else "electron")
    )
    if desktop_dir.is_dir() and electron_bin.exists():
        env = os.environ.copy()
        env["UNFORCE_SERVER_URL"] = url
        env["UNFORCE_INITIAL_REPO"] = initial_repo
        proc = subprocess.Popen(
            [str(electron_bin), str(desktop_dir)],
            cwd=str(desktop_dir),
            env=env,
        )
        proc.wait()
        return True
    return False


def launch_ui(
    repo_path: str = ".",
    port: int = 8765,
    web: bool = False,
    qt: bool = False,
) -> None:
    """Launches the ForcePush-Breaker (UnForce) interactive Chromium UI dashboard."""
    resolved_initial = repo_path
    if repo_path and repo_path != ".":
        try:
            p = Path(repo_path)
            if p.exists():
                resolved_initial = str(p.resolve())
        except Exception:
            pass
    elif repo_path == ".":
        try:
            if (Path.cwd() / ".git").exists():
                resolved_initial = str(Path.cwd().resolve())
            else:
                resolved_initial = ""
        except Exception:
            resolved_initial = ""

    server, active_port = start_ui_server(start_port=port)
    query = f"?repo={urllib.parse.quote(resolved_initial)}" if resolved_initial else ""
    url = f"http://127.0.0.1:{active_port}/{query}"

    console.print("\n[bold cyan][*] ForcePush-Breaker (UnForce) Dashboard launched![/bold cyan]")
    console.print(f"   Server URL: [link={url}]{url}[/link]")
    if resolved_initial:
        console.print(f"   Target Repo: {resolved_initial}\n")

    if web:
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[dim]Shutting down UI server.[/dim]")
            server.shutdown()
        return

    if qt:
        try:
            from PySide6.QtCore import QUrl
            from PySide6.QtWebEngineWidgets import QWebEngineView
            from PySide6.QtWidgets import QApplication

            app = QApplication.instance() or QApplication(sys.argv)
            view = QWebEngineView()
            view.setWindowTitle("ForcePush-Breaker (UnForce) - Git Commit Recovery & Secret Forensics")
            view.resize(1380, 880)
            view.load(QUrl(url))
            view.show()
            sys.exit(app.exec())
        except Exception as e:
            console.print(f"[bold yellow][Warning][/bold yellow] PySide6 QtWebEngine launch failed ({e}), falling back...")

    # 1. Preferred: Electron Chromium Desktop Shell
    try:
        if _try_launch_electron_shell(url, resolved_initial):
            server.shutdown()
            return
    except Exception:
        pass

    # 2. Secondary: Chromium/Chrome/Edge standalone `--app` window
    chromium_bin = _find_chromium_binary()
    if chromium_bin:
        try:
            subprocess.Popen(
                [chromium_bin, f"--app={url}", "--window-size=1380,880"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            console.print("[dim]Running in Chromium App Window. Press Ctrl+C in terminal to stop server.[/dim]")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                server.shutdown()
            return
        except Exception:
            pass

    # 3. Tertiary: pywebview
    try:
        import webview

        webview.create_window(
            title="ForcePush-Breaker (UnForce) - Git Commit Recovery & Secret Forensics",
            url=url,
            width=1380,
            height=880,
            min_size=(960, 620),
            text_select=True,
        )
        webview.start()
        server.shutdown()
        return
    except Exception:
        pass

    # 4. System default browser fallback
    webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Shutting down UI server.[/dim]")
        server.shutdown()
