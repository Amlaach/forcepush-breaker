"""
Unit tests for GitGhost CLI commands and DemoBuilder.
"""

from pathlib import Path
import pytest
from typer.testing import CliRunner

from gitghost.cli import app
from gitghost.demo_builder import DemoBuilder

runner = CliRunner()


class TestDemoBuilder:
    def test_demo_repository_lifecycle(self):
        info = DemoBuilder.create_demo_repository()
        try:
            assert info.repo_path.exists()
            assert (info.repo_path / ".git").exists()
            assert info.leaked_filename == ".env"
            assert "temporary test" in info.dangling_commit_subject
        finally:
            DemoBuilder.cleanup(info.repo_path)
            assert not info.repo_path.exists()


class TestCliCommands:
    def test_version_command(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "GitGhost version" in result.output

    def test_clean_dry_run(self, tmp_path: Path):
        (tmp_path / ".git").mkdir()
        result = runner.invoke(app, ["clean", str(tmp_path), "--dry-run"])
        assert result.exit_code == 0
        assert "Dry Run:" in result.output
        assert "git reflog expire" in result.output

    def test_demo_command(self):
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "Initializing GitGhost Interactive Sandbox Demo" in result.output
        assert "Sandbox demo completed successfully" in result.output

    def test_scan_invalid_path(self):
        result = runner.invoke(app, ["scan", "/non/existent/path/123456"])
        assert result.exit_code == 1
        assert "Target path does not exist" in result.output

    def test_scan_with_recover_zip_bundle(self, tmp_path: Path):
        import zipfile

        info = DemoBuilder.create_demo_repository()
        zip_out = tmp_path / "recovery_bundle.zip"
        try:
            result = runner.invoke(
                app,
                ["scan", str(info.repo_path), "--no-ai", "--recover-zip", str(zip_out)],
            )
            assert result.exit_code == 0
            assert zip_out.exists()
            with zipfile.ZipFile(zip_out, "r") as zf:
                names = zf.namelist()
                assert "reports/gitghost_audit_report.json" in names
                assert any(n.startswith("commits/") for n in names)
        finally:
            DemoBuilder.cleanup(info.repo_path)

    def test_scan_remote_url_token_sanitized_on_error(self, monkeypatch):
        fake_token = "ghp_SuperSecretTokenValue999999"

        def _failing_pipeline(**kwargs):
            raise RuntimeError(f"Clone failed for https://{fake_token}@github.com/octocat/Hello-World.git")

        monkeypatch.setattr("gitghost.cli.run_scan_pipeline", _failing_pipeline)
        result = runner.invoke(
            app,
            ["scan", "https://github.com/octocat/Hello-World", "--github-token", fake_token],
        )
        assert result.exit_code == 1
        assert fake_token not in result.output
        assert "[REDACTED_GITHUB_TOKEN]" in result.output

