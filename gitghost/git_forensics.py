"""
Git Object Database Forensics Engine.

Discovers dangling commits, unreachable trees, and orphaned blobs in local .git repositories.
Recovers commit metadata (author, timestamp, commit message) and reconstructed file diffs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple


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
        if not shutil.which("git"):
            return False
        git_dir = self.repo_path / ".git"
        if git_dir.exists() and (git_dir.is_dir() or git_dir.is_file()):
            return True
        res = self._run_git(["rev-parse", "--is-inside-work-tree"], check=False)
        return res.returncode == 0 and res.stdout.strip() == "true"

    def scan(self) -> ForensicsScanResult:
        if not shutil.which("git"):
            raise RuntimeError(
                "Git executable was not found on the system PATH. "
                "Git is required to perform GitGhost forensics."
            )
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

        for blob_hash in unreachable_objects["blob"]:
            blob_obj = self._extract_blob(blob_hash, associated_path=blob_path_map.get(blob_hash))
            if blob_obj:
                result.dangling_blobs.append(blob_obj)

        result.total_objects_scanned = (
            len(result.dangling_commits) + len(result.dangling_blobs) +
            len(result.unreachable_trees) + len(result.unreachable_tags)
        )
        return result

    def _batch_check(self, oids: List[str]) -> Dict[str, Tuple[str, int]]:
        """Uses git cat-file --batch-check to query object types and sizes in bulk."""
        if not oids:
            return {}

        results: Dict[str, Tuple[str, int]] = {}
        batch_input = "\n".join(oids).encode("utf-8")

        try:
            proc = subprocess.run(
                ["git", "cat-file", "--batch-check"],
                cwd=str(self.repo_path),
                input=batch_input,
                capture_output=True,
                check=False,
            )
            if proc.returncode == 0:
                for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        oid = parts[0]
                        obj_type = parts[1]
                        try:
                            size = int(parts[2])
                        except ValueError:
                            size = 0
                        results[oid] = (obj_type, size)
                    elif len(parts) == 2 and parts[1] == "missing":
                        results[parts[0]] = ("missing", 0)
        except Exception:
            pass

        return results

    def _parse_fsck_output(self, output: str, bucket: Dict[str, Set[str]]) -> None:
        for line in output.splitlines():
            line = line.strip()
            if not line: continue
            parts = line.split()
            if len(parts) >= 3 and parts[0] in ("unreachable", "dangling"):
                obj_type = parts[1].lower()
                obj_hash = parts[2]
                if obj_type in bucket:
                    bucket[obj_type].add(obj_hash)

    def _get_object_type(self, obj_hash: str) -> Optional[str]:
        res = self._run_git(["cat-file", "-t", obj_hash], check=False)
        return res.stdout.strip() if res.returncode == 0 else None

    def _map_tree_blobs(self, trees: Set[str], commits: Set[str]) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        all_trees = set(trees)
        for commit_hash in commits:
            res = self._run_git(["show", "-s", "--format=%T", commit_hash], check=False)
            if res.returncode == 0 and res.stdout.strip():
                all_trees.add(res.stdout.strip())

        for tree_hash in all_trees:
            res = self._run_git(["ls-tree", "-r", tree_hash], check=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.strip().split(None, 3)
                    if len(parts) >= 4 and parts[1] == "blob":
                        b_hash = parts[2]
                        path_parts = line.split("\t", 1)
                        if len(path_parts) == 2:
                            mapping[b_hash] = path_parts[1].strip()
        return mapping

    def _reconstruct_commit(self, commit_hash: str) -> Optional[DanglingCommit]:
        type_res = self._run_git(["cat-file", "-t", commit_hash], check=False)
        if type_res.returncode != 0 or type_res.stdout.strip() != "commit":
            return None

        meta_res = self._run_git(["show", "-s", "--format=%an <%ae>%x1f%aI%x1f%P", commit_hash], check=False)
        author, date_str, parents_str = "Unknown", datetime.now(timezone.utc).isoformat(), ""
        if meta_res.returncode == 0 and meta_res.stdout.strip():
            fields = meta_res.stdout.strip().split("\x1f")
            if len(fields) >= 1 and fields[0]: author = fields[0]
            if len(fields) >= 2 and fields[1]: date_str = fields[1]
            if len(fields) >= 3 and fields[2]: parents_str = fields[2]

        parents = parents_str.split() if parents_str else []
        msg_res = self._run_git(["show", "-s", "--format=%B", commit_hash], check=False)
        message = msg_res.stdout.strip() if msg_res.returncode == 0 else ""

        files_res = self._run_git(["diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash], check=False)
        changed_files = [f.strip() for f in files_res.stdout.splitlines() if f.strip()]

        diff_res = self._run_git(["diff-tree", "-p", "--root", commit_hash], check=False)
        diff_content = diff_res.stdout if diff_res.returncode == 0 else ""

        return DanglingCommit(
            commit_hash=commit_hash, author=author, date=date_str, message=message,
            parents=parents, changed_files=changed_files, diff_content=diff_content, is_dangling=True
        )

    def _extract_blob(self, blob_hash: str, associated_path: Optional[str] = None) -> Optional[DanglingBlob]:
        size_res = self._run_git(["cat-file", "-s", blob_hash], check=False)
        if size_res.returncode != 0: return None
        try: size = int(size_res.stdout.strip())
        except ValueError: size = 0

        if size > self.MAX_BLOB_SIZE_BYTES:
            return DanglingBlob(
                blob_hash=blob_hash, size=size,
                content="[Binary or oversized file content omitted - size: %d bytes]" % size,
                is_binary=True, associated_path=associated_path
            )

        cmd = ["git", "cat-file", "-p", blob_hash]
        try:
            raw = subprocess.check_output(cmd, cwd=str(self.repo_path), stderr=subprocess.DEVNULL)
            is_binary = b"\x00" in raw[:8000]
            content = "[Binary blob data (%d bytes)]" % size if is_binary else raw.decode("utf-8", errors="replace")
            return DanglingBlob(blob_hash=blob_hash, size=size, content=content, is_binary=is_binary, associated_path=associated_path)
        except Exception: return None

    def _run_git(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        full_cmd = ["git"] + args
        try:
            return subprocess.run(
                full_cmd, cwd=str(self.repo_path), capture_output=True, text=True,
                encoding="utf-8", errors="replace", check=check
            )
        except subprocess.CalledProcessError as e:
            if check: raise
            return subprocess.CompletedProcess(args=full_cmd, returncode=e.returncode, stdout=e.stdout or "", stderr=e.stderr or "")
        except FileNotFoundError:
            return subprocess.CompletedProcess(args=full_cmd, returncode=127, stdout="", stderr="git not found")
