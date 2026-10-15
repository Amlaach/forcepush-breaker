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
            )

        result = ForensicsScanResult(repo_path=str(self.repo_path), is_git_repo=True)
        unreachable_objects: Dict[str, Set[str]] = {
            "commit": set(), "blob": set(), "tree": set(), "tag": set(),
        }

        fsck_res = self._run_git(["fsck", "--full", "--no-reflogs", "--unreachable", "--lost-found"], check=False)
        self._parse_fsck_output(fsck_res.stdout + "\n" + fsck_res.stderr, unreachable_objects)

        dangling_res = self._run_git(["fsck", "--full", "--no-reflogs", "--dangling"], check=False)
        self._parse_fsck_output(dangling_res.stdout + "\n" + dangling_res.stderr, unreachable_objects)

        lost_found_dir = self.repo_path / ".git" / "lost-found"
        if lost_found_dir.exists():
            commit_dir = lost_found_dir / "commit"
            if commit_dir.exists() and commit_dir.is_dir():
                for f in commit_dir.iterdir():
                    if len(f.name) in (40, 64):
                        unreachable_objects["commit"].add(f.name)
            other_dir = lost_found_dir / "other"
            if other_dir.exists() and other_dir.is_dir():
                for f in other_dir.iterdir():
                    if len(f.name) in (40, 64):
                        obj_type = self._get_object_type(f.name)
                        if obj_type in unreachable_objects:
                            unreachable_objects[obj_type].add(f.name)

        result.unreachable_trees = list(unreachable_objects["tree"])
        result.unreachable_tags = list(unreachable_objects["tag"])

        blob_path_map = self._map_tree_blobs(unreachable_objects["tree"], unreachable_objects["commit"])

        for commit_hash in unreachable_objects["commit"]:
            commit_obj = self._reconstruct_commit(commit_hash)
            if commit_obj:
                result.dangling_commits.append(commit_obj)

        result.dangling_commits.sort(key=lambda c: c.date, reverse=True)

