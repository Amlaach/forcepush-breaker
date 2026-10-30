"""
GitGhost / ForcePush-Breaker (UnForce) Main Entry Point.
Supports:
- Headless JSON-handshake daemon mode (`--daemon [--port PORT]`) for Electron Chromium Desktop shell
- Interactive Desktop UI launch when run with no arguments
- Full Rich CLI (`scan`, `recover`, `demo`, `ui`, `clean`, `install-hook`) when invoked with CLI arguments
"""

from __future__ import annotations

import json
import sys
import time

from gitghost import __version__


def _run_daemon_server() -> None:
    from gitghost.ui_server import start_ui_server

    port = 0
    args = sys.argv[1:]
    for idx, arg in enumerate(args):
        if arg == "--port" and idx + 1 < len(args):
            try:
                port = int(args[idx + 1])
            except ValueError:
                port = 0

    server, active_port = start_ui_server(host="127.0.0.1", start_port=port)
    ready_payload = {
        "event": "server_ready",
        "host": "127.0.0.1",
        "port": active_port,
        "url": f"http://127.0.0.1:{active_port}",
        "version": __version__,
    }
    if sys.stdout is not None:
        try:
            sys.stdout.write(json.dumps(ready_payload) + "\n")
            sys.stdout.flush()
        except Exception:
            pass

    try:
        while not getattr(server, "_shutdown_requested", False):
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass


def main() -> None:
    if "--daemon" in sys.argv:
        _run_daemon_server()
        return

    if "--mcp" in sys.argv or (len(sys.argv) > 1 and sys.argv[1] == "mcp"):
        from gitghost.mcp_server import run_mcp_server
        run_mcp_server()
        return

    if len(sys.argv) == 1:
        from gitghost.ui_window import launch_ui

        launch_ui()
    else:
        from gitghost.cli import app

        app()


if __name__ == "__main__":
    main()
