"""
End-to-End (E2E) Verification Suite for GitGhost Target State.

Covers:
1. Remote GitHub URL submission (`https://github.com/owner/repo`) + ephemeral in-memory token.
2. Smart mirror cloning + GitHub Events API force-push detection + orphaned SHA fetching.
3. Guaranteed temporary workspace cleanup (`try/finally`).
4. Multi-file unified diff attribution + Shannon Entropy + Regex detection + multi-line redacted `diff_hunk`.
5. Asynchronous background scan job (`POST /api/scan/start`) + real-time progress polling (`GET /api/scan/status`).
6. Redacted (`include_raw=False` default) vs. Raw (`include_raw=True`) file recovery (`POST /api/recover/file`) and ZIP bundle download (`GET /api/download/bundle`).
"""

from __future__ import annotations

import io
import json
import subprocess
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import pytest

from gitghost.github_remote import GitHubAPIForensicsClient, HistoryOverwriteEvent
from gitghost.ui_server import start_ui_server


@pytest.fixture(scope="module")
def e2e_server():
    server, port = start_ui_server(start_port=8940)
    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    server.shutdown()


def test_full_end_to_end_remote_github_forensics_and_recovery(
    e2e_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    raw_aws_secret = "AKIAIOSFODNN7EXAMPLE"
    ephemeral_gh_token = "ghp_SecretUserAuthTokenForClone999"

    # 1. Create a simulated remote origin repository with a leaked secret in an overwritten commit
    remote_origin = tmp_path / "remote_origin_repo"
    remote_origin.mkdir()
    subprocess.run(["git", "init"], cwd=str(remote_origin), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "DevOps Engineer"], cwd=str(remote_origin), check=True)
    subprocess.run(["git", "config", "user.email", "devops@acme.io"], cwd=str(remote_origin), check=True)

    (remote_origin / "app.py").write_text("print('hello world')\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=str(remote_origin), check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(remote_origin), check=True)

    # Commit multi-file change containing secret in config/prod.env
    (remote_origin / "config").mkdir()
    (remote_origin / "config" / "prod.env").write_text(
        f"NODE_ENV=production\nAWS_ACCESS_KEY_ID={raw_aws_secret}\nPORT=8080\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "config/prod.env"], cwd=str(remote_origin), check=True)
    subprocess.run(["git", "commit", "-m", "chore: add prod env config"], cwd=str(remote_origin), check=True)
    orphaned_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=str(remote_origin), text=True
    ).strip()

    # Force-reset HEAD~1 so the commit is unreachable from main branch
    subprocess.run(
        ["git", "reset", "--hard", "HEAD~1"],
        cwd=str(remote_origin),
        check=True,
        capture_output=True,
    )
    active_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=str(remote_origin), text=True
    ).strip()

    # Attach simulated GitHub Events API force-push overwrite event to SmartGitCloner.acquire
    from gitghost.github_remote import SmartGitCloner

    orig_acquire = SmartGitCloner.acquire

    @classmethod
    def acquire_with_mock_events(cls, target, *args, **kwargs):
        acq = orig_acquire(
            target=target,
            *args,
            **kwargs,
        )
        acq.history_events.append(
            HistoryOverwriteEvent(
                event_id="evt-999",
                event_type="force_push",
                ref="refs/heads/main",
                before_sha=orphaned_sha,
                after_sha=active_sha,
                actor="devops-user",
                created_at="2026-10-16T10:00:00Z",
                description=f"Force-push or non-FF update on refs/heads/main (orphaned {orphaned_sha[:10]})",
            )
        )
        return acq

    monkeypatch.setattr(SmartGitCloner, "acquire", acquire_with_mock_events)

    remote_url = "https://github.com/acme/payments-service"

    # 2. Start asynchronous scan via POST /api/scan/start
    start_req = urllib.request.Request(
        f"{e2e_server}/api/scan/start",
        data=json.dumps({
            "repo_path": remote_url,
            "ai_provider": "heuristic",
            "github_token": ephemeral_gh_token,
            "clone_source_override": str(remote_origin),
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(start_req, timeout=10) as resp:
        assert resp.status == 200
        start_data = json.loads(resp.read().decode("utf-8"))
        job_id = start_data["job_id"]

    # 3. Poll GET /api/scan/status until completed
    final_status = None
    for _ in range(150):
        with urllib.request.urlopen(f"{e2e_server}/api/scan/status?job_id={job_id}", timeout=10) as resp:
            final_status = json.loads(resp.read().decode("utf-8"))
            if final_status["status"] in ("completed", "failed"):
                break
        time.sleep(0.1)

    assert final_status is not None
    assert final_status["status"] == "completed", f"Scan failed: {final_status.get('error')}"
    assert final_status["progress_pct"] == 100

    payload_str = json.dumps(final_status)
    # Zero leak guarantee: neither the raw AWS secret nor the user's GitHub token may appear in output
    assert raw_aws_secret not in payload_str
    assert ephemeral_gh_token not in payload_str

    result = final_status["result"]
    assert result["is_remote"] is True
    assert len(result["history_events"]) == 1
    assert result["history_events"][0]["before_sha"] == orphaned_sha

    # Verify finding attribution and multi-line redacted diff hunk
    prod_findings = [
        f for f in result["findings"]
        if f["file_path"] == "config/prod.env" and "AWS" in f["rule_name"]
    ]
    assert len(prod_findings) >= 1
    finding = prod_findings[0]
    assert finding["line_number"] == 2
    assert "diff_hunk" in finding and "\n" in finding["diff_hunk"]
    assert raw_aws_secret not in finding["diff_hunk"]

    # Verify .env & Sensitive Config Time-Machine detection
    assert "deleted_config_files" in result
    env_configs = [c for c in result["deleted_config_files"] if c["file_path"] == "config/prod.env"]
    assert len(env_configs) >= 1
    assert env_configs[0]["commit_hash"] == orphaned_sha
    assert env_configs[0]["file_type"] in ("env", "config")

    # Verify Remediation & GitHub Support Ticket Generator
    assert "remediation" in result
    assert "github_support_ticket" in result["remediation"]
    ticket = result["remediation"]["github_support_ticket"]
    assert remote_url in ticket
    assert orphaned_sha in ticket
    assert "Cache Purge" in ticket or "Purge Request" in ticket or "GitGhost" in ticket

    # Verify Safe Passive Key Liveness probe endpoint
    verify_req = urllib.request.Request(
        f"{e2e_server}/api/verify/key",
        data=json.dumps({
            "finding_id": finding["finding_id"],
            "repo_path": remote_url,
            "rule_name": finding["rule_name"],
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(verify_req, timeout=10) as resp:
        assert resp.status == 200
        liveness_data = json.loads(resp.read().decode("utf-8"))
        assert "status" in liveness_data
        assert liveness_data["status"] in ("ACTIVE", "UNKNOWN", "FORMAT_VALID", "UNVERIFIABLE")
        assert liveness_data.get("provider") == "AWS"

    # 4. Recover single file: Redacted (default include_raw=False) vs Raw (include_raw=True)
    rec_redacted_req = urllib.request.Request(
        f"{e2e_server}/api/recover/file",
        data=json.dumps({
            "repo_path": remote_url,
            "object_type": "file",
            "commit_hash": orphaned_sha,
            "file_path": "config/prod.env",
            "include_raw": False,
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(rec_redacted_req, timeout=10) as resp:
        rec_red = json.loads(resp.read().decode("utf-8"))
        assert rec_red["is_redacted"] is True
        assert raw_aws_secret not in rec_red["content"]
        assert "NODE_ENV=production" in rec_red["content"]

    rec_raw_req = urllib.request.Request(
        f"{e2e_server}/api/recover/file",
        data=json.dumps({
            "repo_path": remote_url,
            "object_type": "file",
            "commit_hash": orphaned_sha,
            "file_path": "config/prod.env",
            "include_raw": True,
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(rec_raw_req, timeout=10) as resp:
        rec_raw = json.loads(resp.read().decode("utf-8"))
        assert rec_raw["is_redacted"] is False
        assert raw_aws_secret in rec_raw["content"]

    # 5. Download full Recovery ZIP Bundle (strictly redacted by default)
    q_url = urllib.parse.quote(remote_url, safe="")
    with urllib.request.urlopen(
        f"{e2e_server}/api/download/bundle?repo_path={q_url}&include_raw=false", timeout=10
    ) as resp:
        assert resp.status == 200
        zip_bytes = resp.read()
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            names = zf.namelist()
            assert "reports/gitghost_audit_report.json" in names
            assert "reports/gitghost_audit_report.md" in names
            assert "reports/gitghost_audit_report.sarif" in names
            assert any(n.startswith("commits/") for n in names)
            assert any(n.startswith("recovered_files/") for n in names)
            for name in names:
                content_text = zf.read(name).decode("utf-8")
                assert raw_aws_secret not in content_text
                assert ephemeral_gh_token not in content_text
