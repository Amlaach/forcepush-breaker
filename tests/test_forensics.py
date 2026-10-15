"""
Tests for live GitForensics object-store analysis on a live Git repository.
"""

import subprocess
from pathlib import Path
import pytest
from gitghost.git_forensics import GitForensics
from gitghost.redactor import SecretRedactor


class TestLiveGitForensics:
    @pytest.fixture
    def live_ghost_repo(self, tmp_path: Path):
        """Create a real local Git repository containing a real dangling commit and unreachable blob."""
        def run_git(*args):
            subprocess.run(
                ["git"] + list(args),
                cwd=str(tmp_path),
                check=True,
                capture_output=True,
                text=True,
            )

        run_git("init")
        run_git("config", "user.name", "Live Forensics Tester")
        run_git("config", "user.email", "tester@gitghost.internal")
        run_git("config", "commit.gpgsign", "false")

        # Initial commit (reachable)
        readme = tmp_path / "README.md"
        readme.write_text("# Production Service\n", encoding="utf-8")
        run_git("add", "README.md")
        run_git("commit", "-m", "feat: initial service setup")

        # Second commit with sensitive configuration (to be orphaned)
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgres://admin:SuperSecretPass123!@db.internal:5432/core\n", encoding="utf-8")
        run_git("add", ".env")
        run_git("commit", "-m", "chore: temporary test of db credentials")

        # Perform hard reset to orphan the sensitive commit into a live dangling object
        run_git("reset", "--hard", "HEAD~1")

        return tmp_path

    def test_live_dangling_commit_detection(self, live_ghost_repo: Path):
        forensics = GitForensics(live_ghost_repo)
