"""
Tests for UnForce (ForcePush-Breaker) Desktop Studio workflows, practical Git
recovery endpoints (branch restore, cherry-pick, working-tree file restore,
commit tree browser, deep search, sandbox demo), daemon handshake, and bugfixes.
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from gitghost.redactor import SecretRedactor
from gitghost.remediation import RemediationGenerator
from gitghost.git_forensics import ForensicsScanResult
from gitghost.ui_server import start_ui_server


def _post_json(url: str, payload: dict, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


@pytest.fixture(scope="module")
def studio_server():
    server, port = start_ui_server(start_port=0)
    assert port > 0
    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    server.shutdown()


class TestDesktopStudioWorkflows:
    def test_system_info_and_bilingual_ui(self, studio_server: str):
        with urllib.request.urlopen(f"{studio_server}/api/system/info", timeout=5) as resp:
            info = json.loads(resp.read().decode("utf-8"))
            assert info["version"] == "1.0.0"
            assert info["git_available"] is True
            assert "git" in info["git_version"].lower()

        with urllib.request.urlopen(f"{studio_server}/", timeout=5) as resp:
            html = resp.read().decode("utf-8")
            assert "UnForce" in html
            assert "UNFORCE_I18N" in html
            assert "UNFORCE_LOGO_DATA_URI" in html
            assert "LIVE FORENSICS OPS CONSOLE" in html
            # Ensure GitHub-URL-only selection (no local folder browse or drag-drop overlay)
            assert "browseFolder(" not in html
            assert 'id="dropOverlay"' not in html
            # Ensure duplicate IDs bug from legacy UI is completely gone
            assert html.count('id="aiProviderSelect"') == 1
            assert html.count('id="githubTokenInput"') == 1
            assert html.count('id="entropyThreshold"') == 1

    def test_sandbox_demo_creation_and_deep_search(self, studio_server: str):
        demo_res = _post_json(f"{studio_server}/api/demo/create", {})
        assert demo_res["success"] is True
        demo_path = Path(demo_res["repo_path"])
        assert demo_path.exists()

        scan_res = _post_json(f"{studio_server}/api/scan", {"repo_path": str(demo_path)})
        assert len(scan_res["dangling_commits"]) >= 2
        assert len(scan_res["dangling_blobs"]) >= 1
        assert len(scan_res["reflog_entries"]) >= 2
        assert scan_res["repo_metadata"] is not None
        assert scan_res["repo_metadata"]["current_branch"] != ""
        # Ensure raw file_snapshots are never leaked in scan JSON
        assert "file_snapshots" not in json.dumps(scan_res)

        # Deep search across commits, blobs, and findings
        search_res = _post_json(
            f"{studio_server}/api/search",
            {"repo_path": str(demo_path), "query": "stripe"},
        )
        kinds = {m["kind"] for m in search_res["matches"]}
        assert "commit" in kinds or "finding" in kinds

    def test_commit_tree_preview_and_practical_git_recovery(self, studio_server: str, tmp_path: Path):
        subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Dev"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=str(tmp_path), check=True)

        (tmp_path / "app.py").write_text("def hello():\n    return 'v1'\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "commit", "-m", "feat: base app"], cwd=str(tmp_path), check=True)

        # Create a second commit with multi-line code + secret, then wipe via git reset --hard HEAD~1
        full_code = "\n".join([f"line_{i} = {i}" for i in range(1, 25)]) + "\n"
        (tmp_path / "feature_x.py").write_text(full_code, encoding="utf-8")
        subprocess.run(["git", "add", "feature_x.py"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "commit", "-m", "feat: lost feature X"], cwd=str(tmp_path), check=True)
        lost_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(tmp_path), text=True
        ).strip()

        subprocess.run(["git", "reset", "--hard", "HEAD~1"], cwd=str(tmp_path), check=True, capture_output=True)
        assert not (tmp_path / "feature_x.py").exists()

        # Scan repo
        _post_json(f"{studio_server}/api/scan", {"repo_path": str(tmp_path)})

        # 1. List commit tree files
        tree_res = _post_json(
            f"{studio_server}/api/commit/files",
            {"repo_path": str(tmp_path), "commit_hash": lost_sha},
        )
        assert tree_res["success"] is True
        paths = [f["path"] for f in tree_res["files"]]
        assert "feature_x.py" in paths
        assert "app.py" in paths

        # 2. Preview full file (all 24 lines, not truncated diff hunk!)
        prev_res = _post_json(
            f"{studio_server}/api/commit/file-preview",
            {"repo_path": str(tmp_path), "commit_hash": lost_sha, "file_path": "feature_x.py"},
        )
        assert prev_res["success"] is True
        assert "line_1 = 1" in prev_res["content"]
        assert "line_24 = 24" in prev_res["content"]

        # 3. Restore file directly to working tree (and verify backup creation on second restore)
        rest_file = _post_json(
            f"{studio_server}/api/git/restore-file",
            {
                "repo_path": str(tmp_path),
                "object_type": "file",
                "commit_hash": lost_sha,
                "file_path": "feature_x.py",
            },
        )
        assert rest_file["success"] is True
        assert (tmp_path / "feature_x.py").read_text(encoding="utf-8") == full_code

        # Modify existing file and restore again -> should create .bak backup
        (tmp_path / "feature_x.py").write_text("modified_locally\n", encoding="utf-8")
        rest_file_2 = _post_json(
            f"{studio_server}/api/git/restore-file",
            {
                "repo_path": str(tmp_path),
                "object_type": "file",
                "commit_hash": lost_sha,
                "file_path": "feature_x.py",
