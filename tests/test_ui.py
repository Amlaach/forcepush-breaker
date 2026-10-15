"""
Tests for GitGhost Interactive UI Server and REST API endpoints.
"""

import json
import urllib.request
import subprocess
from pathlib import Path
import pytest
from gitghost.ui_server import start_ui_server


@pytest.fixture(scope="module")
def running_server():
    server, port = start_ui_server(start_port=8910)
    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    server.shutdown()


class TestUIServer:
    def test_root_serves_html_dashboard(self, running_server: str):
        with urllib.request.urlopen(f"{running_server}/", timeout=5) as resp:
            assert resp.status == 200
            assert "text/html" in resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8")
            assert "GitGhost" in body
            assert "Repo Hygiene Score" in body
            assert "Strict Redaction Active" in body

    def test_api_status_endpoint(self, running_server: str):
        with urllib.request.urlopen(f"{running_server}/api/status", timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data["app"] == "GitGhost"
            assert "version" in data

    def test_api_scan_endpoint_on_live_repo(self, running_server: str, tmp_path: Path):
        # Create a small live repo fixture for fast, deterministic testing
        subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Auditor"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "config", "user.email", "auditor@gitghost.io"], cwd=str(tmp_path), check=True)
        (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "commit", "-m", "feat: initial test commit"], cwd=str(tmp_path), check=True)

        payload = json.dumps({"repo_path": str(tmp_path), "ai_provider": "heuristic"}).encode("utf-8")
        req = urllib.request.Request(
            f"{running_server}/api/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "hygiene_score" in data
            assert "dangling_commits" in data
            assert "dangling_blobs" in data
            assert "findings" in data
            assert "remediation" in data
            assert "bash_script" in data["remediation"]
            assert "powershell_script" in data["remediation"]
            assert 0 <= data["hygiene_score"]["score"] <= 100

    def test_api_export_endpoint(self, running_server: str, tmp_path: Path):
        # Create a small live repo fixture
        subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Auditor"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "config", "user.email", "auditor@gitghost.io"], cwd=str(tmp_path), check=True)
        (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "commit", "-m", "feat: initial test commit"], cwd=str(tmp_path), check=True)

        for fmt in ["json", "sarif", "markdown"]:
            payload = json.dumps({"repo_path": str(tmp_path), "format": fmt}).encode("utf-8")
            req = urllib.request.Request(
                f"{running_server}/api/export",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                assert resp.status == 200
                res_data = json.loads(resp.read().decode("utf-8"))
                assert res_data["success"] is True
                assert Path(res_data["file_path"]).exists()
