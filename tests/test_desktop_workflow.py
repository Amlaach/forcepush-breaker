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

from gitghost import __version__
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
    import time
    server, port = start_ui_server(start_port=0)
    assert port > 0
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            with urllib.request.urlopen(f"{base_url}/api/system/info", timeout=2):
                break
        except Exception:
            time.sleep(0.1)
    yield base_url
    server.shutdown()


class TestDesktopStudioWorkflows:
    def test_system_info_and_bilingual_ui(self, studio_server: str):
        with urllib.request.urlopen(f"{studio_server}/api/system/info", timeout=15) as resp:
            info = json.loads(resp.read().decode("utf-8"))
            assert info["version"] == __version__
            assert info["git_available"] is True
            assert "git" in info["git_version"].lower()

        with urllib.request.urlopen(f"{studio_server}/", timeout=15) as resp:
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
                "create_backup": True,
            },
        )
        assert rest_file_2["backup_path"] is not None
        assert Path(rest_file_2["backup_path"]).exists()
        # Clean untracked files before branch/cherry-pick tests
        (tmp_path / "feature_x.py").unlink()
        Path(rest_file_2["backup_path"]).unlink()

        # 4. Path traversal attempt must fail with HTTP 400
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            _post_json(
                f"{studio_server}/api/git/restore-file",
                {
                    "repo_path": str(tmp_path),
                    "object_type": "file",
                    "commit_hash": lost_sha,
                    "file_path": "../outside.py",
                },
            )
        assert exc_info.value.code == 400

        # 5. Restore commit as new branch without switching HEAD
        branch_res = _post_json(
            f"{studio_server}/api/git/restore-branch",
            {
                "repo_path": str(tmp_path),
                "commit_hash": lost_sha,
                "branch_name": "recovered/feature-x",
                "checkout": False,
            },
        )
        assert branch_res["success"] is True
        branch_tip = subprocess.check_output(
            ["git", "rev-parse", "refs/heads/recovered/feature-x"],
            cwd=str(tmp_path),
            text=True,
        ).strip()
        assert branch_tip == lost_sha

        # 6. Cherry-pick commit onto current main/master branch
        cp_res = _post_json(
            f"{studio_server}/api/git/cherry-pick",
            {"repo_path": str(tmp_path), "commit_hash": lost_sha},
        )
        assert cp_res["success"] is True
        assert (tmp_path / "feature_x.py").exists()


class TestEngineFixesAndDaemon:
    def test_remote_url_not_corrupted_in_remediation_scripts(self):
        remote = "https://github.com/Amlaach/forcepush-breaker"
        plan = RemediationGenerator.generate_plan(remote, [], dangling_commits_count=1)
        assert remote in plan.bash_script
        assert remote in plan.powershell_script
        assert "C:\\" not in plan.bash_script

    def test_extended_secret_rules_and_multiline_private_key_line_number(self):
        redactor = SecretRedactor()
        # Construct tokens dynamically so static scanners don't flag test literals
        stripe_tok = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc99"
        pem_block = (
            "header_1 = true\n"
            "header_2 = true\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        res_pem = redactor.scan_and_redact(pem_block, file_path="id_ed25519")
        assert len(res_pem.findings) >= 1
        assert res_pem.findings[0].line_number == 3
        assert res_pem.findings[0].raw_value.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")

        res_stripe = redactor.scan_and_redact(f"STRIPE_KEY={stripe_tok}\n", file_path=".env")
        assert any("Stripe" in f.rule_name for f in res_stripe.findings)
        assert stripe_tok not in res_stripe.redacted_text

    def test_daemon_handshake_and_graceful_shutdown(self):
        gitghost_root = Path(__file__).resolve().parent.parent
        proc = subprocess.Popen(
            [sys.executable, "-m", "gitghost", "--daemon", "--port", "0"],
            cwd=str(gitghost_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout is not None
            ready_line = proc.stdout.readline().strip()
            payload = json.loads(ready_line)
            assert payload["event"] == "server_ready"
            url = payload["url"]

            with urllib.request.urlopen(f"{url}/api/status", timeout=5) as resp:
                st = json.loads(resp.read().decode("utf-8"))
                assert st["status"] == "ok"

            _post_json(f"{url}/api/shutdown", {})
            proc.wait(timeout=8)
            assert proc.returncode == 0
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_permissive_github_urls_and_deleted_env_timemachine(self, studio_server: str, tmp_path: Path):
        from gitghost.github_remote import parse_github_url

        parsed = parse_github_url("https://github.com/Amlaach/forcepush-breaker/tree/main?tab=readme-ov-file")
        assert parsed is not None
        assert parsed.owner == "Amlaach"
        assert parsed.repo == "forcepush-breaker"
        assert parsed.clone_url == "https://github.com/Amlaach/forcepush-breaker.git"

        # Create a repo where .env was committed and later removed via `git rm` (no force-push)
        subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "SecDev"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "config", "user.email", "sec@example.com"], cwd=str(tmp_path), check=True)
        (tmp_path / ".env").write_text("APP_MODE=production\nPORT=8080\n", encoding="utf-8")
        subprocess.run(["git", "add", ".env"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "commit", "-m", "chore: add env config"], cwd=str(tmp_path), check=True)

        subprocess.run(["git", "rm", ".env"], cwd=str(tmp_path), check=True, capture_output=True)
        (tmp_path / "main.py").write_text("print('clean')\n", encoding="utf-8")
        subprocess.run(["git", "add", "main.py"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "commit", "-m", "fix: remove env and add main"], cwd=str(tmp_path), check=True)

        scan_res = _post_json(f"{studio_server}/api/scan", {"repo_path": str(tmp_path)})
        assert len(scan_res["branch_commits"]) >= 2
        del_cfgs = scan_res["deleted_config_files"]
        env_entry = next((c for c in del_cfgs if c["file_path"] == ".env"), None)
        assert env_entry is not None

        # Recover the deleted .env from its pre-deletion parent commit!
        rec_res = _post_json(
            f"{studio_server}/api/recover/file",
            {
                "repo_path": str(tmp_path),
                "object_type": "file",
                "commit_hash": env_entry["commit_hash"],
                "file_path": ".env",
            },
        )
        assert rec_res["success"] is True
        assert "APP_MODE=production" in rec_res["content"]

        # On-demand commit diff for branch commit
        head_sha = scan_res["branch_commits"][0]["commit_hash"]
        diff_res = _post_json(
            f"{studio_server}/api/commit/diff",
            {"repo_path": str(tmp_path), "commit_hash": head_sha},
        )
        assert diff_res["success"] is True
        assert "main.py" in diff_res["diff"]
