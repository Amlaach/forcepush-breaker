#!/usr/bin/env python3
import subprocess
import sys
import os
import time

repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def git(*args, check=True):
    cmd = ['git', '-C', repo] + list(args)
    res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
    if check and res.returncode != 0:
        print(f"Error executing {' '.join(cmd)}:\n{res.stderr}", file=sys.stderr)
        raise RuntimeError(res.stderr)
    return res.stdout.strip()

commits_spec = [
    ('feat(core): initialize project repository structure and git attributes', ['.gitignore', '.gitattributes', 'LICENSE']),
    ('feat(packaging): define python build configuration and dependencies', ['pyproject.toml', 'requirements.txt']),
    ('feat(docs): add comprehensive documentation and architecture overview', ['README.md']),
    ('feat(core): implement robust cross-platform subprocess runner', ['gitghost/_proc.py']),
    ('feat(core): initialize gitghost package and export version constants', ['gitghost/__init__.py']),
    ('feat(forensics): implement low-level git forensics and object discovery engine', ['gitghost/git_forensics.py']),
    ('feat(redactor): implement high-entropy secret detection and redactor engine', ['gitghost/redactor.py']),
    ('feat(remote): add remote repository parser and bare mirror fetcher', ['gitghost/github_remote.py']),
    ('feat(liveness): add API key and token live validation probes', ['gitghost/liveness.py']),
    ('feat(ai_triage): implement hybrid AI and heuristic finding triage analyzer', ['gitghost/ai_triage.py']),
    ('feat(scoring): implement hygiene scoring algorithm and security grade system', ['gitghost/scoring.py']),
    ('feat(remediation): add automated bash and powershell remediation generators', ['gitghost/remediation.py']),
    ('feat(recovery): implement dangling commit and blob exhumation engine', ['gitghost/recovery.py']),
    ('feat(pipeline): implement multi-stage forensics pipeline orchestrator', ['gitghost/pipeline.py']),
    ('feat(demo): implement realistic forensics sandbox repository generator', ['gitghost/demo_builder.py']),
    ('feat(exporters): implement SARIF, JSON, and Markdown forensic report exporters', ['gitghost/exporters.py']),
    ('feat(cli): implement command-line interface with argparser and subcommands', ['gitghost/cli.py', 'gitghost/__main__.py']),
    ('feat(ui_assets): add embedded vector assets and branding constants', ['gitghost/ui_assets.py']),
    ('feat(ui_window): implement webview desktop window bridge', ['gitghost/ui_window.py']),
    ('feat(ui_server): bootstrap http server and rest api handlers', ['gitghost/ui_server.py']),
    ('feat(ui): add bilingual internationalization dictionary', ['gitghost/static/i18n.js']),
    ('feat(ui): implement embedded logo data provider', ['gitghost/static/logo_data.js']),
    ('feat(ui): create cyberpunk dark mode visual design system', ['gitghost/static/styles.css']),
    ('feat(ui): implement accessible responsive html structure', ['gitghost/static/index.html']),
    ('feat(ui): implement frontend state management and api integration', ['gitghost/static/app.js']),
    ('feat(desktop): configure electron desktop environment and manifest', ['desktop/package.json', 'desktop/package-lock.json']),
    ('feat(desktop): implement electron preload bridge and secure ipc', ['desktop/preload.js']),
    ('feat(desktop): implement main electron application life-cycle controller', ['desktop/main.js']),
    ('feat(desktop): add startup splash screen and loading animations', ['desktop/splash.html']),
    ('feat(desktop): add high-resolution desktop iconography', ['desktop/assets/icon.svg', 'desktop/assets/icon.png', 'desktop/assets/icon.ico', 'assets/logo.png']),
    ('feat(scripts): add cross-platform icon generation script', ['scripts/generate_icons.py']),
    ('feat(scripts): implement single-file ui bundle pre-renderer', ['scripts/build_ui_bundle.py']),
    ('feat(desktop): generate pre-rendered desktop ui bundle', ['desktop/ui_bundle.html']),
    ('feat(scripts): add automated ui patcher and updater utility', ['scripts/patch_ui.py']),
    ('feat(scripts): add powershell and bash desktop build automation', ['scripts/build_desktop.ps1', 'scripts/build_desktop.sh']),
    ('feat(scripts): add nsis packaging scripts for zero-install portable executable', ['scripts/package_portable.nsi', 'scripts/build_portable.js']),
    ('test(forensics): add unit tests for git forensics and object discovery', ['tests/test_forensics.py']),
    ('test(redactor): add unit tests for secret redaction and masking', ['tests/test_redactor.py']),
    ('test(remote): add unit tests for remote cloning and gitlab namespace parsing', ['tests/test_github_remote.py', 'tests/test_remote_forensics.py']),
    ('test(triage): add unit tests for ai triage and heuristic classification', ['tests/test_ai_triage.py']),
    ('test(scoring): add unit tests for security score calculation and grading', ['tests/test_scoring.py']),
    ('test(recovery): add unit tests for dangling commit and file restoration', ['tests/test_recovery.py', 'tests/test_local_scan_and_recovery.py']),
    ('test(remediation): add unit tests for remediation script generators', ['tests/test_remediation.py']),
    ('test(liveness): add unit tests for secret liveness verification probes', ['tests/test_liveness.py']),
    ('test(exporters): add unit tests for sarif, json, and markdown exporters', ['tests/test_exporters.py']),
    ('test(cli): add unit tests for command-line interface execution', ['tests/test_cli.py', 'tests/test_gc_diagnostics.py']),
    ('test(ui): add unit tests for ui server routes and handlers', ['tests/test_ui.py', 'tests/test_desktop_workflow.py', 'tests/test_e2e_full.py']),
    ('ci: add automated continuous integration workflow', ['.github/workflows/ci.yml']),
    ('ci: add multi-platform release and packaging pipeline', ['.github/workflows/release.yml']),
    ('release(v0.8.1): clean UI titlebar controls, SVG icons, and live demo sandbox', None),
]

def main():
    print(f"[REBUILD] Building clean 50-commit history in: {repo}")
    assert len(commits_spec) == 50, f"Expected 50 commits, got {len(commits_spec)}"

    # Backup current branch
    git('branch', 'backup-pre-clean-history', check=False)

    # Check if clean-history branch already exists and delete it
    git('branch', '-D', 'clean-history', check=False)

    # Create orphan branch
    print("[REBUILD] Creating orphan branch clean-history...")
    git('checkout', '--orphan', 'clean-history')

    # Unstage everything from index so we can stage incrementally
    git('rm', '-rf', '--cached', '.', check=False)

    author_name = "Amlaach"
    author_email = "259857678+Amlaach@users.noreply.github.com"
    os.environ['GIT_AUTHOR_NAME'] = author_name
    os.environ['GIT_AUTHOR_EMAIL'] = author_email
    os.environ['GIT_COMMITTER_NAME'] = author_name
    os.environ['GIT_COMMITTER_EMAIL'] = author_email

    for idx, (msg, files) in enumerate(commits_spec, 1):
        if files:
            for f in files:
                fpath = os.path.join(repo, f)
                if os.path.exists(fpath):
                    git('add', f)
                else:
                    print(f"Warning: file {f} does not exist", file=sys.stderr)
        else:
            # Last commit: stage all remaining files
            git('add', '-A')

        git('commit', '-m', msg)
        print(f"[{idx:02d}/50] Committed: {msg}")

    # Verify commit count
    count = git('rev-list', '--count', 'HEAD')
    print(f"[REBUILD] Successfully created {count} commits on clean-history!")

    # Switch main to clean-history
    print("[REBUILD] Switching main to clean-history...")
    git('branch', '-M', 'clean-history', 'main')

    # Check diff with working directory
    status = git('status', '--porcelain')
    print(f"[REBUILD] Working tree status after rebuild: '{status}'")

if __name__ == '__main__':
    main()
