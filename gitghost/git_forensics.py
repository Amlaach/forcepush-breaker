"""
Git Object Database Forensics Engine.

Discovers dangling commits, unreachable trees, and orphaned blobs in local .git repositories.
Recovers commit metadata (author, timestamp, commit message) and reconstructed file diffs.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Set


@dataclass
class DanglingCommit:
    commit_hash: str
    author: str
    date: str
    message: str
    parents: List[str] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)
    diff_content: str = ""
    is_dangling: bool = True


@dataclass
class DanglingBlob:
    blob_hash: str
    size: int
    content: str
    is_binary: bool = False
    associated_path: Optional[str] = None


@dataclass
class ForensicsScanResult:
    repo_path: str
    is_git_repo: bool
    dangling_commits: List[DanglingCommit] = field(default_factory=list)
    dangling_blobs: List[DanglingBlob] = field(default_factory=list)
    unreachable_trees: List[str] = field(default_factory=list)
    unreachable_tags: List[str] = field(default_factory=list)
    total_objects_scanned: int = 0
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    errors: List[str] = field(default_factory=list)


class GitForensics:
    MAX_BLOB_SIZE_BYTES = 512 * 1024

    def __init__(self, repo_path: str | Path = "."):
        self.repo_path = Path(repo_path).resolve()

    def is_valid_repo(self) -> bool:
        git_dir = self.repo_path / ".git"
        if git_dir.exists() and (git_dir.is_dir() or git_dir.is_file()):
            return True
        res = self._run_git(["rev-parse", "--is-inside-work-tree"], check=False)
        return res.returncode == 0 and res.stdout.strip() == "true"

    def scan(self) -> ForensicsScanResult:
        if not self.is_valid_repo():
            return ForensicsScanResult(
                repo_path=str(self.repo_path),
                is_git_repo=False,
                errors=["Specified path is not a valid Git repository."]
