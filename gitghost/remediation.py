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
        affected_files: Set[str] = set()
        for f in findings:
            if f.file_path and f.file_path not in ("Unknown", "N/A"):
                affected_files.add(f.file_path)

        sorted_files = sorted(list(affected_files))

        steps.append(RemediationStep(
            order=1, title="Create Safety Mirror Backup",
            description="Before rewriting Git history, clone a safety mirror of your repository.",
            commands=[f"git clone --mirror {repo_path} {repo_path}_safety_backup.git"],
            is_destructive=False,
        ))
