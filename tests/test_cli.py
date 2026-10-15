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
