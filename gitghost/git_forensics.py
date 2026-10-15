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
