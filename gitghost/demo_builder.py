"""
Interactive Demonstration Repository Builder.

Creates an ephemeral Git sandbox repository that simulates an accidental credential commit
followed by 'git reset --hard HEAD~1' to showcase GitGhost forensics in real-time.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DemoRepoInfo:
    repo_path: Path
    dangling_commit_subject: str
    leaked_filename: str
    description: str
    dangling_commit_sha: str = ""


class DemoBuilder:
    @classmethod
    def create_demo_repository(cls) -> DemoRepoInfo:
        """Constructs a temporary Git sandbox repository containing real orphaned credentials."""
        temp_dir = Path(tempfile.mkdtemp(prefix="gitghost_demo_")).resolve()

        def _git(args: list[str]) -> str:
            res = subprocess.run(
                ["git"] + args,
                cwd=str(temp_dir),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=True,
            )
            return res.stdout.strip()

        _git(["init"])
        _git(["config", "user.name", "DevGhost Auditor"])
        _git(["config", "user.email", "auditor@gitghost.io"])
        _git(["config", "commit.gpgsign", "false"])

        # Commit 1: Initial project baseline
        (temp_dir / "README.md").write_text(
            "# Payment Gateway Microservice\n\nProduction payment processing engine.\n",
            encoding="utf-8",
        )
        (temp_dir / "main.py").write_text(
            "def handle_checkout(cart):\n    return {'status': 'processed'}\n",
            encoding="utf-8",
        )
        _git(["add", "."])
        _git(["commit", "-m", "feat: initial clean microservice architecture"])

        # Commit 2: Accidental leak of live database & cloud credentials
        env_content = (
            "# Production Environment Configuration - DO NOT COMMIT\n"
            "DATABASE_URL=postgresql://prod_admin:SuperSecretPass123!@db-prod.internal.corp:5432/core_finances\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "SLACK_BOT_TOKEN=xoxb-987654321012-9876543210123-abcdef1234567890abcdef12\n"
            "STRIPE_API_KEY=sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz1234567890\n"
        )
        (temp_dir / ".env").write_text(env_content, encoding="utf-8")
        _git(["add", ".env"])
        _git(["commit", "-m", "chore: temporary test of db credentials and s3 backup"])
        dangling_sha = _git(["rev-parse", "HEAD"])

        # Developer panics and attempts to 'delete' the secret using git reset --hard
        _git(["reset", "--hard", "HEAD~1"])

        # Commit 3: Follow-up legitimate development
        (temp_dir / "service.py").write_text(
            "class PaymentProcessor:\n    def process(self): pass\n",
            encoding="utf-8",
        )
        _git(["add", "service.py"])
        _git(["commit", "-m", "feat: add payment processor business logic"])

        return DemoRepoInfo(
            repo_path=temp_dir,
            dangling_commit_subject="chore: temporary test of db credentials and s3 backup",
            leaked_filename=".env",
            description="Simulated repository with accidental secret commit followed by git reset --hard.",
            dangling_commit_sha=dangling_sha,
        )

    @classmethod
    def cleanup(cls, repo_path: Path) -> None:
        """Safely removes the demo directory, handling Windows readonly permissions."""
        if not repo_path.exists():
            return

        def _handle_remove_readonly(func, path, exc_info):
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass

        try:
            shutil.rmtree(repo_path, onerror=_handle_remove_readonly)
        except Exception:
            shutil.rmtree(repo_path, ignore_errors=True)
