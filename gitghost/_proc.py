"""
Windows Windowless Subprocess Guard for UnForce (ForcePush-Breaker).
Prevents console child processes (such as `git.exe`) from flashing visible black
`conhost.exe` terminal windows when spawned from the Chromium Desktop GUI / PyInstaller `--noconsole` engine.
"""

from __future__ import annotations

import subprocess
import sys

_INSTALLED = False


def install_windowless_subprocess_patch() -> None:
    """Patches `subprocess.Popen` on Windows so child console commands never flash black windows."""
    global _INSTALLED
    if _INSTALLED or sys.platform != "win32":
        return

    CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    CREATE_NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010)
