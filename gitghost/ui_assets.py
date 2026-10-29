"""
UI Assets composer for UnForce (ForcePush-Breaker) Cyber-Forensics Studio.
Composes the modular static assets (index.html, styles.css, logo_data.js, i18n.js, app.js) into a
zero-CDN self-contained HTML payload compatible with both source installs and PyInstaller bundles.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

_CACHED_HTML: Optional[str] = None


def _locate_static_dir() -> Path:
    candidates = [
        Path(__file__).resolve().parent / "static",
    ]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        base = Path(meipass)
        candidates.append(base / "gitghost" / "static")
        candidates.append(base / "static")

    for candidate in candidates:
        if (candidate / "index.html").is_file():
            return candidate

    raise FileNotFoundError(
        f"UnForce static UI assets directory not found. Checked: {[str(c) for c in candidates]}"
    )


def get_dashboard_html(force_reload: bool = False) -> str:
    """Composes and returns the complete, self-contained HTML page for the UnForce Studio UI."""
    global _CACHED_HTML
    if _CACHED_HTML is not None and not force_reload:
        return _CACHED_HTML

    static_dir = _locate_static_dir()
    html_template = (static_dir / "index.html").read_text(encoding="utf-8")
    css = (static_dir / "styles.css").read_text(encoding="utf-8")
    logo_js = (
        (static_dir / "logo_data.js").read_text(encoding="utf-8")
        if (static_dir / "logo_data.js").is_file()
        else ""
    )
    i18n_js = (static_dir / "i18n.js").read_text(encoding="utf-8")
    app_js = (static_dir / "app.js").read_text(encoding="utf-8")

    inline_css = f"<style>\n{css}\n</style>"
    scripts = []
    if logo_js:
        scripts.append(f"<script>\n{logo_js}\n</script>")
    scripts.append(f"<script>\n{i18n_js}\n</script>")
    scripts.append(f"<script>\n{app_js}\n</script>")
    inline_js = "\n".join(scripts)

    composed = html_template.replace("<!-- __UNFORCE_INLINE_CSS__ -->", inline_css, 1)
    composed = composed.replace("<!-- __UNFORCE_INLINE_JS__ -->", inline_js, 1)
    _CACHED_HTML = composed
    return composed


def __getattr__(name: str) -> Any:
    if name == "HTML_PAGE":
        return get_dashboard_html()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
