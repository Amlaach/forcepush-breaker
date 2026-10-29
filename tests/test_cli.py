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

    def test_recover_missing_arguments(self):
        result = runner.invoke(app, ["recover", "."])
        assert result.exit_code == 1
        assert "Must specify either --commit" in result.output

    def test_recover_command_flow(self, tmp_path: Path):
        info = DemoBuilder.create_demo_repository()
        try:
            # 1. Recover commit diff in redacted mode
            res_redacted = runner.invoke(
                app,
                ["recover", str(info.repo_path), "--commit", info.dangling_commit_sha],
            )
            assert res_redacted.exit_code == 0
            assert "Recovered Artifact" in res_redacted.output
            assert "STRICTLY REDACTED" in res_redacted.output
            assert "AKIAIOSFODNN7EXAMPLE" not in res_redacted.output

            # 2. Raw mode without --yes prompts confirmation; declining aborts
            res_declined = runner.invoke(
                app,
                ["recover", str(info.repo_path), "--commit", info.dangling_commit_sha, "--raw"],
                input="n\n",
            )
            assert res_declined.exit_code != 0

            # 3. Raw mode with --yes recovers unmasked secret
            out_file = tmp_path / "recovered_diff.patch"
            res_raw = runner.invoke(
                app,
                [
                    "recover",
                    str(info.repo_path),
                    "--commit",
                    info.dangling_commit_sha,
                    "--raw",
                    "--yes",
                    "--output",
                    str(out_file),
                ],
            )
            assert res_raw.exit_code == 0
            assert out_file.exists()
            content = out_file.read_text(encoding="utf-8")
            assert "AKIAIOSFODNN7EXAMPLE" in content
            assert "UNREDACTED (RAW)" in res_raw.output
        finally:
            DemoBuilder.cleanup(info.repo_path)

    def test_scan_configs_only(self):
        info = DemoBuilder.create_demo_repository()
        try:
            res = runner.invoke(app, ["scan", str(info.repo_path), "--configs-only", "--no-ai"])
            assert res.exit_code == 0
            assert "[TIME-MACHINE]" in res.output
            assert ".env" in res.output
        finally:
            DemoBuilder.cleanup(info.repo_path)



