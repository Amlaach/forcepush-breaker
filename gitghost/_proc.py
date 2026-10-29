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
    DETACHED_PROCESS = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
    STARTF_USESHOWWINDOW = getattr(subprocess, "STARTF_USESHOWWINDOW", 0x00000001)
    SW_HIDE = 0

    orig_init = subprocess.Popen.__init__

    def _windowless_popen_init(self, *args, **kwargs):
        flags = int(kwargs.get("creationflags", 0) or 0)
        if not (flags & (CREATE_NEW_CONSOLE | DETACHED_PROCESS)):
            kwargs["creationflags"] = flags | CREATE_NO_WINDOW

        si = kwargs.get("startupinfo")
        if si is None:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= STARTF_USESHOWWINDOW
            si.wShowWindow = SW_HIDE
            kwargs["startupinfo"] = si

        return orig_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _windowless_popen_init  # type: ignore[method-assign]
    _INSTALLED = True
