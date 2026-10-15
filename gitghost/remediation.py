"""
Remediation and History Purification Engine.

Generates precise, actionable git commands and executable automation scripts
to permanently expunge orphaned objects, purge sensitive paths, and reclaim disk space.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set, Optional
from gitghost.redactor import SecretFinding


@dataclass
class RemediationStep:
    order: int
    title: str
    description: str
    commands: List[str]
    is_destructive: bool = False


@dataclass
class RemediationPlan:
    repo_path: str
    affected_paths: List[str]
    steps: List[RemediationStep] = field(default_factory=list)
    bash_script: str = ""
    powershell_script: str = ""
    rotation_warning: str = ""


class RemediationGenerator:
    ROTATION_NOTICE = (
        "CRITICAL SECURITY NOTICE:\n"
        "Purging objects from Git history ONLY prevents future exposure.\n"
        "Any token, password, or key that was ever committed MUST be treated as compromised\n"
        "and immediately rotated/revoked in your cloud provider or service console!"
    )

    @classmethod
    def generate_plan(
        cls,
        repo_path: str,
        findings: List[SecretFinding],
        dangling_commits_count: int = 0,
        dangling_blobs_count: int = 0,
    ) -> RemediationPlan:
        steps: List[RemediationStep] = []
        clean_path = str(Path(repo_path).resolve())
        backup_path = f"{clean_path}_safety_backup.git"
        affected_files: Set[str] = set()
        for f in findings:
            if f.file_path and f.file_path not in ("Unknown", "N/A"):
                affected_files.add(f.file_path)

        sorted_files = sorted(list(affected_files))

        steps.append(RemediationStep(
            order=1, title="Create Safety Mirror Backup",
            description="Before rewriting Git history, clone a safety mirror of your repository.",
            commands=[f'git clone --mirror "{clean_path}" "{backup_path}"'],
            is_destructive=False,
        ))

        if sorted_files:
            file_args = " ".join([f"--path '{p}'" for p in sorted_files])
            steps.append(RemediationStep(
                order=2, title="Purge Sensitive Files from Entire History",
                description="Use the official, ultra-fast `git-filter-repo` tool to purge affected paths across all branches and tags.",
                commands=[
                    "# Install git-filter-repo if not already present: pip install git-filter-repo",
                    f"git filter-repo --invert-paths {file_args} --force"
                ],
                is_destructive=True,
            ))

        steps.append(RemediationStep(
            order=3, title="Expire All Reflogs Immediately",
            description="Invalidate reference logs so that orphaned commits are completely detached from local pointer heads.",
            commands=["git reflog expire --expire=now --expire-unreachable=now --all"],
            is_destructive=False,
        ))

        steps.append(RemediationStep(
            order=4, title="Aggressive Physical Garbage Collection & Object Excision",
            description="Permanently eradicate unreferenced objects and dangling packfiles from disk (.git/objects).",
            commands=["git fsck --unreachable", "git gc --prune=now --aggressive"],
            is_destructive=True,
        ))

        steps.append(RemediationStep(
            order=5, title="Synchronize Upstream Remote (Coordinate with Team)",
            description="Force-push the cleansed history to remote repositories. Ensure teammates re-clone rather than pulling.",
            commands=["git push origin --force --all", "git push origin --force --tags"],
            is_destructive=True,
        ))

        bash_script = cls._build_bash_script(clean_path, steps, sorted_files)
        ps_script = cls._build_powershell_script(steps, sorted_files)

        return RemediationPlan(
            repo_path=repo_path, affected_paths=sorted_files, steps=steps,
            bash_script=bash_script, powershell_script=ps_script, rotation_warning=cls.ROTATION_NOTICE,
        )

    @classmethod
    def _build_bash_script(
        cls, repo_path: str, steps: List[RemediationStep], affected_files: List[str]
    ) -> str:
        clean_path = str(Path(repo_path).resolve())
        backup_path = f"{clean_path}_safety_backup.git"
        lines = [
            "#!/usr/bin/env bash",
            "# GitGhost Automated History Remediation Script (Bash)",
            f"# Generated for: {clean_path}",
            "set -euo pipefail",
            "",
            'echo "====================================================="',
            'echo "  GitGhost History Remediation Playbook (Bash)"',
            'echo "====================================================="',
            'echo "CRITICAL: Purging Git history only prevents future exposure."',
            'echo "Any exposed credentials must be revoked immediately in production!"',
            'echo ""',
            "",
            'echo "==> [Step 1] Creating safety mirror backup..."',
            f'git clone --mirror "{clean_path}" "{backup_path}"',
            "",
        ]

        if affected_files:
            file_args = " ".join([f'--path "{p}"' for p in affected_files])
            lines.extend([
                'echo "==> [Step 2] Purging sensitive files with git-filter-repo..."',
                "if ! command -v git-filter-repo >/dev/null 2>&1; then",
                '    echo "ERROR: git-filter-repo is required. Install via: pip install git-filter-repo"',
                "    exit 1",
                "fi",
                f"git filter-repo --invert-paths {file_args} --force",
                "",
            ])
        else:
            lines.extend([
                'echo "==> [Step 2] No named file paths detected; skipping git-filter-repo."',
                "",
            ])

        lines.extend([
            'echo "==> [Step 3] Expiring reflog entries across all references..."',
            "git reflog expire --expire=now --expire-unreachable=now --all",
            "",
            'echo "==> [Step 4] Running aggressive garbage collection and pruning..."',
            "git gc --prune=now --aggressive",
            "",
            'echo "==> [Step 5] History remediation complete!"',
            'echo "Run 'gitghost scan .' to verify clean repository hygiene."',
        ])

        return "\n".join(lines)


    @classmethod
    def _build_powershell_script(cls, steps: List[RemediationStep], affected_files: List[str]) -> str:
        return """# PowerShell Excision Script
$ErrorActionPreference = 'Stop'
Write-Host "==> Expiring reflogs..." -ForegroundColor Green
git reflog expire --expire=now --expire-unreachable=now --all
Write-Host "==> Pruning unreachable objects..." -ForegroundColor Green
git gc --prune=now --aggressive
Write-Host "Done!" -ForegroundColor Green
"""
