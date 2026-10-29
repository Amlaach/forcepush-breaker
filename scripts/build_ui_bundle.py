"""
Pre-renders the self-contained UnForce Cyber-Forensics HTML bundle (`desktop/ui_bundle.html`)
so the Electron Chromium shell can paint the complete interactive UI directly from local disk
in < 250ms while `unforce-engine` binds asynchronously in the background.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gitghost.ui_assets import get_dashboard_html  # noqa: E402


def main() -> None:
    html = get_dashboard_html(force_reload=True)
    out_path = ROOT / "desktop" / "ui_bundle.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    print(f"Built pre-rendered desktop UI bundle ({len(html):,} chars) -> {out_path}")


if __name__ == "__main__":
    main()
