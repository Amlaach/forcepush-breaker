"""
Window Launcher for GitGhost Desktop Dashboard.
Provides desktop UI via pywebview (Edge WebView2 on Windows), PySide6, or system browser fallback.
"""

from __future__ import annotations

import sys
import time
import webbrowser
from pathlib import Path

from gitghost.ui_server import start_ui_server


def launch_ui(
    repo_path: str = ".",
    port: int = 8765,
    web: bool = False,
    qt: bool = False,
) -> None:
    """Launches the GitGhost interactive UI dashboard."""
    server, active_port = start_ui_server(start_port=port)
    url = f"http://127.0.0.1:{active_port}/"

    print(f"\n[bold cyan]👻 GitGhost Dashboard launched![/bold cyan]")
    print(f"   Server URL: [link={url}]{url}[/link]")
    print(f"   Target Repo: {Path(repo_path).resolve()}\n")

    # If --web flag requested
    if web:
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down GitGhost UI server.")
            server.shutdown()
        return

    # If Qt requested specifically
    if qt:
        try:
            from PySide6.QtWidgets import QApplication
            from PySide6.QtWebEngineWidgets import QWebEngineView
            from PySide6.QtCore import QUrl

            app = QApplication.instance() or QApplication(sys.argv)
            view = QWebEngineView()
            view.setWindowTitle("GitGhost - Git Forensics & Secret Recovery")
            view.resize(1280, 850)
            view.load(QUrl(url))
            view.show()
            sys.exit(app.exec())
        except Exception as e:
            print(f"[Warning] PySide6 QtWebEngine launch failed ({e}), falling back...")

    # Default desktop window: pywebview (native Edge WebView2 on Windows)
    try:
        import webview
        window = webview.create_window(
            title="GitGhost - Git Forensics & Secret Recovery",
            url=url,
            width=1280,
            height=850,
            min_size=(920, 600),
            text_select=True,
        )
        webview.start()
        server.shutdown()
    except Exception as e:
        print(f"[Notice] Desktop window could not be opened directly ({e}). Opening system browser...")
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down GitGhost UI server.")
            server.shutdown()
