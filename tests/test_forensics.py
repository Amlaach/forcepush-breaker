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
        assert forensics.is_valid_repo() is True

        scan_result = forensics.scan()
        assert scan_result.is_git_repo is True
        assert len(scan_result.dangling_commits) >= 1

        dangling = scan_result.dangling_commits[0]
        assert "temporary test of db credentials" in dangling.message
        assert ".env" in dangling.changed_files
        assert "postgres://admin:" in dangling.diff_content

        # Verify live secret redaction works on the discovered dangling commit
        redactor = SecretRedactor()
        redaction = redactor.scan_and_redact(dangling.diff_content, file_path=".env", commit_hash=dangling.commit_hash)
        assert len(redaction.findings) >= 1
        assert "SuperSecretPass123!" not in redaction.redacted_text
        assert "[REDACTED_DB_PASSWORD]" in redaction.redacted_text

    def test_bare_mirror_repository_forensics_scan(self, live_ghost_repo: Path, tmp_path: Path):
        mirror_dir = tmp_path / "mirror_clone.git"
        subprocess.run(
            ["git", "clone", "--mirror", str(live_ghost_repo), str(mirror_dir)],
            check=True,
            capture_output=True,
            text=True,
        )
        # Create a new commit in live_ghost_repo, fetch its SHA into mirror_dir without updating a ref
        leaked_file = live_ghost_repo / "aws.env"
        leaked_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
        subprocess.run(["git", "add", "aws.env"], cwd=str(live_ghost_repo), check=True)
        subprocess.run(["git", "commit", "-m", "chore: orphan aws key in mirror"], cwd=str(live_ghost_repo), check=True)
        sha_out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(live_ghost_repo), check=True, capture_output=True, text=True
        ).stdout.strip()
        subprocess.run(["git", "fetch", "origin", sha_out], cwd=str(mirror_dir), check=True, capture_output=True)

        mirror_forensics = GitForensics(mirror_dir)
        assert mirror_forensics.is_valid_repo() is True
        res = mirror_forensics.scan()
        assert res.is_git_repo is True
        assert any(c.commit_hash == sha_out for c in res.dangling_commits)

