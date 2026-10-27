"""
Integration tests for local repository scanning via ui_server.py
and branch restoration after local git reset --hard.
"""

from pathlib import Path
import json
import subprocess
import urllib.request
import pytest
from gitghost.ui_server import start_ui_server

@pytest.fixture(scope="module")
def local_test_server():
    server, port = start_ui_server(start_port=0)
    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    server.shutdown()

def test_local_scan_and_branch_restore(local_test_server: str, tmp_path: Path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), check=True)

    (tmp_path / "init.txt").write_text("initial commit", encoding="utf-8")
    subprocess.run(["git", "add", "init.txt"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "commit", "-m", "chore: init"], cwd=str(tmp_path), check=True)

    # Add secret file and commit
    (tmp_path / "secret.env").write_text("API_KEY=sk_live_1234567890abcdef", encoding="utf-8")
    subprocess.run(["git", "add", "secret.env"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "commit", "-m", "feat: leaked secret"], cwd=str(tmp_path), check=True)
    leaked_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(tmp_path), text=True).strip()

    # Reset hard to simulate lost commit
    subprocess.run(["git", "reset", "--hard", "HEAD~1"], cwd=str(tmp_path), check=True, capture_output=True)
    assert not (tmp_path / "secret.env").exists()

    # 1. Scan local path via UI Server endpoint
    req_body = json.dumps({"repo_path": str(tmp_path)}).encode("utf-8")
    req = urllib.request.Request(f"{local_test_server}/api/scan", data=req_body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        assert res["is_remote"] is False
        assert res["remote_platform"] == "local"
        dangling = [c["commit_hash"] for c in res["dangling_commits"]]
        assert leaked_sha in dangling

    # 2. Restore commit to a new local branch
    restore_body = json.dumps({
        "repo_path": str(tmp_path),
        "commit_hash": leaked_sha,
        "branch_name": "recovered/local-rescue",
        "checkout": False,
    }).encode("utf-8")
    req_restore = urllib.request.Request(f"{local_test_server}/api/git/restore-branch", data=restore_body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req_restore, timeout=15) as resp_rest:
        rest_res = json.loads(resp_rest.read().decode("utf-8"))
        assert rest_res["success"] is True
        assert rest_res["branch_name"] == "recovered/local-rescue"

    branch_sha = subprocess.check_output(["git", "rev-parse", "refs/heads/recovered/local-rescue"], cwd=str(tmp_path), text=True).strip()
    assert branch_sha == leaked_sha
