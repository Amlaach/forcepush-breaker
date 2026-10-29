"""
Applies targeted UI updates to UnForce Studio:
1. Removes 'quick command' / navigation from the initial view, keeping only clean repo input + dedicated paste button.
2. Removes all emojis and replaces them with crisp inline SVG icons.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "gitghost" / "static"

SVG_CLOSE = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>'
SVG_LOGS = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-inline-end:5px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>'
SVG_REFRESH = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-inline-end:5px;"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>'
SVG_SETTINGS = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-inline-end:5px;"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>'
SVG_ROCKET = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--neon-green)" stroke-width="2"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"></path><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"></path><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"></path><path d="M12 9V4s3.03.55 4 2c1.08 1.62 0 5 0 5"></path></svg>'


def patch_index_html():
    p = STATIC / "index.html"
    text = p.read_text(encoding="utf-8")

    # 1. Remove cmd-trigger-btn from titlebar
    text = re.sub(
        r'<button class="cmd-trigger-btn" onclick="openCmdPalette\(\)"[^>]*>.*?</button>',
        '',
        text,
        flags=re.DOTALL
    )

    # 2. Update paste button text to "הדבק כתובת"
    text = text.replace(
        '<span data-i18n="pasteBtn">הדבק URL</span>',
        '<span data-i18n="pasteBtn">הדבק כתובת</span>'
    )
    text = text.replace(
        '<span data-i18n="pasteBtn">הדבק</span>',
        '<span data-i18n="pasteBtn">הדבק כתובת</span>'
    )

    # 3. Remove landing samples chips
    text = re.sub(
        r'<div class="landing-samples">.*?</div>\s*',
        '',
        text,
        flags=re.DOTALL
    )

    # 4. Remove emojis from footer
    text = text.replace(
        '📜 <span data-i18n="navLogs">לוגים</span>',
        f'{SVG_LOGS}<span data-i18n="navLogs">לוגים</span>'
    )
    text = text.replace(
        '🔄 <span data-i18n="updateCheckNow">בדוק עדכונים</span>',
        f'{SVG_REFRESH}<span data-i18n="updateCheckNow">בדוק עדכונים</span>'
    )
    text = text.replace(
        '⚙️ <span data-i18n="settingsBtn">הגדרות</span>',
        f'{SVG_SETTINGS}<span data-i18n="settingsBtn">הגדרות</span>'
    )

    # 5. Remove ✕ close buttons
    text = text.replace(
        '<button class="btn btn-secondary btn-sm" onclick="closeLogsConsole()">✕</button>',
        f'<button class="btn btn-secondary btn-sm" onclick="closeLogsConsole()">{SVG_CLOSE}</button>'
    )
    text = text.replace(
        '<button class="btn btn-secondary btn-sm" onclick="closeUpdateModal()">✕</button>',
        f'<button class="btn btn-secondary btn-sm" onclick="closeUpdateModal()">{SVG_CLOSE}</button>'
    )
    text = text.replace(
        '<button class="btn btn-secondary btn-sm" onclick="closeModal()">✕</button>',
        f'<button class="btn btn-secondary btn-sm" onclick="closeModal()">{SVG_CLOSE}</button>'
    )
    text = text.replace(
        '<button class="btn btn-secondary btn-sm" onclick="closeSettingsModal()">✕</button>',
        f'<button class="btn btn-secondary btn-sm" onclick="closeSettingsModal()">{SVG_CLOSE}</button>'
    )

    # 6. Rocket emoji in update modal
    text = text.replace(
        '<span style="font-size:22px;">🚀</span>',
        f'<span>{SVG_ROCKET}</span>'
    )

    # 7. Settings modal update button
    text = text.replace(
        '🔄 בדוק עדכונים כעת',
        f'{SVG_REFRESH}<span data-i18n="updateCheckNow">בדוק עדכונים כעת</span>'
    )

    # 8. Add icon slot to toast
    if '<span id="toastIcon"' not in text:
        text = text.replace(
            '<div id="toast" class="toast">\n    <span id="toastMessage">Ready</span>',
            '<div id="toast" class="toast">\n    <span id="toastIcon" class="toast-icon"></span>\n    <span id="toastMessage">Ready</span>'
        ).replace(
            '<div id="toast" class="toast">\r\n    <span id="toastMessage">Ready</span>',
            '<div id="toast" class="toast">\r\n    <span id="toastIcon" class="toast-icon"></span>\r\n    <span id="toastMessage">Ready</span>'
        )

    p.write_text(text, encoding="utf-8")
    print("Patched index.html successfully.")


def patch_i18n():
    p = STATIC / "i18n.js"
    text = p.read_text(encoding="utf-8")

    text = text.replace(
        'cmdPlaceholder: "פקודה מהירה או ניווט... (Ctrl+K)",',
        'cmdPlaceholder: "חיפוש פקודה... (Ctrl+K)",'
    )
    text = text.replace(
        'cmdPlaceholder: "Quick command or jump to... (Ctrl+K)",',
        'cmdPlaceholder: "Search command... (Ctrl+K)",'
    )
    text = text.replace(
        'pasteBtn: "הדבק",',
        'pasteBtn: "הדבק כתובת",'
    )
    text = text.replace(
        'pasteBtn: "הדבק URL",',
        'pasteBtn: "הדבק כתובת",'
    )
    text = text.replace(
        'pasteBtn: "Paste URL",',
        'pasteBtn: "Paste URL",'
    )

    # Add pastedSuccess if not present
    if "pastedSuccess:" not in text:
        text = text.replace(
            'clipboardEmpty: "לוח ההעתקה ריק',
            'pastedSuccess: "הכתובת הודבקה בהצלחה",\n    clipboardEmpty: "לוח ההעתקה ריק'
        )
        text = text.replace(
            'clipboardEmpty: "Clipboard is empty',
            'pastedSuccess: "Repository address pasted successfully",\n    clipboardEmpty: "Clipboard is empty'
        )

    p.write_text(text, encoding="utf-8")
    print("Patched i18n.js successfully.")


def patch_styles():
    p = STATIC / "styles.css"
    text = p.read_text(encoding="utf-8")

    extra_css = """
/* Toast Icon & Status Styles */
.toast {
  display: inline-flex !important;
  align-items: center !important;
  gap: 10px !important;
}
.toast-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.toast-icon svg {
  display: block;
}
.toast.toast-error {
  border-color: var(--crimson) !important;
}
.toast.toast-warn {
  border-color: var(--amber) !important;
}
.toast.toast-success {
  border-color: var(--neon-green) !important;
}

/* Command Palette SVG Items */
.cmd-item {
  display: flex !important;
  align-items: center !important;
  gap: 10px !important;
}
.cmd-item-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  color: var(--cyan);
}
"""
    if "Toast Icon & Status Styles" not in text:
        text += "\n" + extra_css
        p.write_text(text, encoding="utf-8")
        print("Patched styles.css successfully.")


def patch_app_js():
    p = STATIC / "app.js"
    text = p.read_text(encoding="utf-8")

    # Zero ghost commits icon
    text = re.sub(
        r'<div style="color:var\(--neon-green\);font-weight:800;margin-bottom:6px;">✓ 0 Force-Pushed Ghost Commits Exposed</div>',
        '<div style="color:var(--neon-green);font-weight:800;margin-bottom:6px;display:flex;align-items:center;justify-content:center;gap:6px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--neon-green)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg> 0 Force-Pushed Ghost Commits Exposed</div>',
        text
    )

    # File tree icon
    text = text.replace(
        ': `📄 `;\n',
        ': `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" style="vertical-align:middle;margin-inline-end:4px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>`;\n'
    ).replace(
        ': `📄 `;\r\n',
        ': `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" style="vertical-align:middle;margin-inline-end:4px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>`;\r\n'
    )

    # GC Purged badge icon
    text = text.replace(
        '<span class="badge-gc-purged" title="${t("gcPurgedDesc")}">⚠ GC_PURGED_REMOTE</span>',
        '<span class="badge-gc-purged" title="${t("gcPurgedDesc")}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-inline-end:3px;"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>GC_PURGED_REMOTE</span>'
    )

    # Convert all showToast calls with ✓, ✗, ⚠ to clean calls
    text = text.replace('showToast(`✓ ', 'showToast(`')
    text = text.replace('showToast("✓ ', 'showToast("')
    text = text.replace('showToast(`✗ ', 'showToast(`')
    text = text.replace('showToast("✗ ', 'showToast("')
    text = text.replace('showToast(`⚠ ', 'showToast(`')
    text = text.replace('showToast("⚠ ', 'showToast("')

    p.write_text(text, encoding="utf-8")
    print("Patched app.js successfully.")


if __name__ == "__main__":
    patch_index_html()
    patch_i18n()
    patch_styles()
    patch_app_js()
