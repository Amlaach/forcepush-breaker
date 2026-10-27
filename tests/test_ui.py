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

    def test_async_scan_start_and_status_polling(self, running_server: str, tmp_path: Path):
        import io
        import time
        import urllib.parse
        import zipfile

        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Auditor"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "config", "user.email", "auditor@gitghost.io"], cwd=str(tmp_path), check=True)
        (tmp_path / "README.md").write_text("# Base\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=str(tmp_path), check=True)

        # Create dangling commit with secret
        (tmp_path / "secrets.env").write_text(f"AWS_KEY={raw_secret}\n", encoding="utf-8")
        subprocess.run(["git", "add", "secrets.env"], cwd=str(tmp_path), check=True)
        subprocess.run(["git", "commit", "-m", "leak aws key"], cwd=str(tmp_path), check=True)
        dangling_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(tmp_path), text=True
        ).strip()
        subprocess.run(["git", "reset", "--hard", "HEAD~1"], cwd=str(tmp_path), check=True, capture_output=True)

        start_payload = json.dumps({"repo_path": str(tmp_path), "ai_provider": "heuristic"}).encode("utf-8")
        start_req = urllib.request.Request(
            f"{running_server}/api/scan/start",
            data=start_payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(start_req, timeout=5) as resp:
            assert resp.status == 200
            job_info = json.loads(resp.read().decode("utf-8"))
            job_id = job_info["job_id"]
            assert job_id

        # Poll /api/scan/status until completed
        status_data = None
        for _ in range(120):
            with urllib.request.urlopen(f"{running_server}/api/scan/status?job_id={job_id}", timeout=5) as resp:
                status_data = json.loads(resp.read().decode("utf-8"))
                if status_data["status"] in ("completed", "failed"):
                    break
            time.sleep(0.1)

        assert status_data is not None
        assert status_data["status"] == "completed"
        assert status_data["progress_pct"] == 100
        result = status_data["result"]
        assert raw_secret not in json.dumps(result)
        assert any(f["file_path"] == "secrets.env" and "diff_hunk" in f for f in result["findings"])
        assert any(c["commit_hash"] == dangling_sha and "redacted_diff" in c for c in result["dangling_commits"])

        # Test /api/recover/file redacted (default) vs raw
        rec_redacted_req = urllib.request.Request(
            f"{running_server}/api/recover/file",
            data=json.dumps({
                "repo_path": str(tmp_path),
                "object_type": "file",
                "commit_hash": dangling_sha,
                "file_path": "secrets.env",
                "include_raw": False,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(rec_redacted_req, timeout=5) as resp:
            rec_data = json.loads(resp.read().decode("utf-8"))
            assert rec_data["is_redacted"] is True
            assert raw_secret not in rec_data["content"]

        rec_raw_req = urllib.request.Request(
            f"{running_server}/api/recover/file",
            data=json.dumps({
                "repo_path": str(tmp_path),
                "object_type": "file",
                "commit_hash": dangling_sha,
                "file_path": "secrets.env",
                "include_raw": True,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(rec_raw_req, timeout=5) as resp:
            rec_raw_data = json.loads(resp.read().decode("utf-8"))
            assert rec_raw_data["is_redacted"] is False
            assert raw_secret in rec_raw_data["content"]

        # Test direct report download & bundle download
        q_repo = urllib.parse.quote(str(tmp_path))
        with urllib.request.urlopen(f"{running_server}/api/download/report?repo_path={q_repo}&format=json", timeout=5) as resp:
            assert resp.status == 200
            assert "attachment" in resp.headers.get("Content-Disposition", "")
            dl_body = resp.read().decode("utf-8")
            assert raw_secret not in dl_body

        with urllib.request.urlopen(f"{running_server}/api/download/bundle?repo_path={q_repo}&include_raw=false", timeout=5) as resp:
            assert resp.status == 200
            assert "application/zip" in resp.headers.get("Content-Type", "")
            zip_bytes = resp.read()
            with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                names = zf.namelist()
                assert "reports/gitghost_audit_report.json" in names
                for name in names:
                    assert raw_secret not in zf.read(name).decode("utf-8")

