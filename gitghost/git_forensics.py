"""
Git Object Database Forensics Engine.

Discovers dangling commits, unreachable trees, and orphaned blobs in local .git repositories.
Recovers commit metadata (author, timestamp, commit message) and reconstructed file diffs
using high-performance batch stream processing.
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class DanglingCommit:
    commit_hash: str
    author: str
    date: str
    message: str
    parents: List[str] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)
    diff_content: str = ""
    redacted_diff: str = ""
    redacted_message: str = ""
    is_dangling: bool = True


@dataclass
class DanglingBlob:
    blob_hash: str
    size: int
    content: str
    redacted_content: str = ""
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
    MAX_TEXT_SCAN_BYTES = 10 * 1024 * 1024
    GIT_CMD_TIMEOUT_SECONDS = 60

    def __init__(self, repo_path: str | Path = "."):
        self.repo_path = Path(repo_path).resolve()

    def is_valid_repo(self) -> bool:
        if not shutil.which("git"):
            return False
        if not self.repo_path.exists():
            return False
        git_dir = self.repo_path / ".git"
        if git_dir.exists() and (git_dir.is_dir() or git_dir.is_file()):
            return True
        if (self.repo_path / "HEAD").is_file() and (self.repo_path / "objects").is_dir():
            return True
        res = self._run_git(["rev-parse", "--is-inside-work-tree"], check=False)
        if res.returncode == 0 and res.stdout.strip() == "true":
            return True
        bare_res = self._run_git(["rev-parse", "--is-bare-repository"], check=False)
        return bare_res.returncode == 0 and bare_res.stdout.strip() == "true"

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
                errors=["Specified path is not a valid Git repository."],
            )

        result = ForensicsScanResult(repo_path=str(self.repo_path), is_git_repo=True)
        unreachable_objects: Dict[str, Set[str]] = {
            "commit": set(),
            "blob": set(),
            "tree": set(),
            "tag": set(),
        }

        # Step 1: Collect candidates via git fsck
        candidate_hashes: Set[str] = set()

        fsck_res = self._run_git(
            ["fsck", "--full", "--no-reflogs", "--unreachable", "--lost-found"],
            check=False,
        )
        self._parse_fsck_output(
            fsck_res.stdout + "\n" + fsck_res.stderr,
            unreachable_objects,
            candidate_hashes,
        )

        dangling_res = self._run_git(
            ["fsck", "--full", "--no-reflogs", "--dangling"],
            check=False,
        )
        self._parse_fsck_output(
            dangling_res.stdout + "\n" + dangling_res.stderr,
            unreachable_objects,
            candidate_hashes,
        )

        # Inspect .git/lost-found or bare lost-found if present
        for lost_found_dir in (self.repo_path / ".git" / "lost-found", self.repo_path / "lost-found"):
            if lost_found_dir.exists():
                commit_dir = lost_found_dir / "commit"
                if commit_dir.exists() and commit_dir.is_dir():
                    for f in commit_dir.iterdir():
                        if len(f.name) in (40, 64):
                            candidate_hashes.add(f.name)
                            unreachable_objects["commit"].add(f.name)
                other_dir = lost_found_dir / "other"
                if other_dir.exists() and other_dir.is_dir():
                    for f in other_dir.iterdir():
                        if len(f.name) in (40, 64):
                            candidate_hashes.add(f.name)

        if not candidate_hashes:
            return result

        # Step 2: Batch check all candidate objects to identify exact types & sizes in ONE call
        type_and_sizes = self._batch_check(candidate_hashes)
        for obj_hash, (obj_type, size) in type_and_sizes.items():
            if obj_type in unreachable_objects:
                unreachable_objects[obj_type].add(obj_hash)

        result.unreachable_trees = sorted(list(unreachable_objects["tree"]))
        result.unreachable_tags = sorted(list(unreachable_objects["tag"]))

        # Step 3: Reconstruct commits in high-performance batch
        commit_hashes = sorted(list(unreachable_objects["commit"]))
        if commit_hashes:
            result.dangling_commits = self._batch_reconstruct_commits(commit_hashes)
            result.dangling_commits.sort(key=lambda c: c.date, reverse=True)

        # Step 4: Map blob paths from commit trees and unreachable trees
        blob_path_map = self._map_tree_blobs_batch(commit_hashes, unreachable_objects["tree"])

        # Step 5: Read dangling blobs in batch
        blob_hashes = sorted(list(unreachable_objects["blob"]))
        if blob_hashes:
            result.dangling_blobs = self._batch_extract_blobs(
                blob_hashes, type_and_sizes, blob_path_map
            )

        result.total_objects_scanned = (
            len(result.dangling_commits)
            + len(result.dangling_blobs)
            + len(result.unreachable_trees)
            + len(result.unreachable_tags)
        )
        return result

    def _parse_fsck_output(
        self, output: str, bucket: Dict[str, Set[str]], candidate_set: Set[str]
    ) -> None:
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[0] in ("unreachable", "dangling"):
                obj_type = parts[1].lower()
                obj_hash = parts[2]
                candidate_set.add(obj_hash)
                if obj_type in bucket:
                    bucket[obj_type].add(obj_hash)

    def _batch_check(self, hashes: Set[str]) -> Dict[str, Tuple[str, int]]:
        """Invokes 'git cat-file --batch-check' in a single call for all hashes."""
        if not hashes:
            return {}
        p = subprocess.Popen(
            ["git", "cat-file", "--batch-check"],
            cwd=str(self.repo_path),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        stdout, _ = p.communicate("\n".join(hashes) + "\n")
        mapping: Dict[str, Tuple[str, int]] = {}
        for line in stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3:
                obj_hash, obj_type, size_str = parts[0], parts[1].lower(), parts[2]
                try:
                    mapping[obj_hash] = (obj_type, int(size_str))
                except ValueError:
                    mapping[obj_hash] = (obj_type, 0)
        return mapping

    def _batch_reconstruct_commits(self, commit_hashes: List[str]) -> List[DanglingCommit]:
        """Reconstructs commit metadata and diffs using batch log and diff-tree streams."""
        if not commit_hashes:
            return []

        # 1. Batch metadata via git log
        meta_p = subprocess.Popen(
            [
                "git",
                "log",
                "--no-walk",
                "--stdin",
                "--format=%H%x1f%an <%ae>%x1f%aI%x1f%P%x1f%B%x1e",
            ],
            cwd=str(self.repo_path),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        meta_out, _ = meta_p.communicate("\n".join(commit_hashes) + "\n")

        commit_meta: Dict[str, Dict[str, any]] = {}
        for record in meta_out.split("\x1e"):
            rec = record.strip()
            if not rec:
                continue
            fields = rec.split("\x1f")
            h = fields[0].strip()
            commit_meta[h] = {
                "author": fields[1].strip() if len(fields) > 1 and fields[1] else "Unknown",
                "date": fields[2].strip() if len(fields) > 2 and fields[2] else datetime.now(timezone.utc).isoformat(),
                "parents": fields[3].strip().split() if len(fields) > 3 and fields[3] else [],
                "message": fields[4].strip() if len(fields) > 4 else "",
            }

        # 2. Batch diffs via git diff-tree
        diff_p = subprocess.Popen(
            ["git", "diff-tree", "-p", "--root", "--stdin"],
            cwd=str(self.repo_path),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        diff_out, _ = diff_p.communicate("\n".join(commit_hashes) + "\n")

        commit_hashes_set = set(commit_hashes)
        commit_diffs: Dict[str, str] = {}
        commit_files: Dict[str, List[str]] = {}

        current_commit: Optional[str] = None
        cur_lines: List[str] = []
        cur_files: List[str] = []

        for line in diff_out.splitlines():
            s = line.strip()
            if s in commit_hashes_set:
                if current_commit:
                    commit_diffs[current_commit] = "\n".join(cur_lines)
                    commit_files[current_commit] = list(dict.fromkeys(cur_files))
                current_commit = s
                cur_lines = []
                cur_files = []
            elif current_commit:
                cur_lines.append(line)
                if line.startswith("diff --git a/"):
                    m = re.match(r"^diff --git a/.*? b/(.*)$", line)
                    if m:
                        cur_files.append(m.group(1))

        if current_commit:
            commit_diffs[current_commit] = "\n".join(cur_lines)
            commit_files[current_commit] = list(dict.fromkeys(cur_files))

        reconstructed: List[DanglingCommit] = []
        for ch in commit_hashes:
            meta = commit_meta.get(
                ch,
                {
                    "author": "Unknown",
                    "date": datetime.now(timezone.utc).isoformat(),
                    "parents": [],
                    "message": "",
                },
            )
            reconstructed.append(
                DanglingCommit(
                    commit_hash=ch,
                    author=meta["author"],
                    date=meta["date"],
                    message=meta["message"],
                    parents=meta["parents"],
                    changed_files=commit_files.get(ch, []),
                    diff_content=commit_diffs.get(ch, ""),
                    is_dangling=True,
                )
            )

        return reconstructed

    def _map_tree_blobs_batch(
        self, commit_hashes: List[str], unreachable_trees: Set[str]
    ) -> Dict[str, str]:
        """Maps blob hashes to their file paths in batch from commit trees and standalone trees."""
        import binascii
        blob_path_map: Dict[str, str] = {}

        if commit_hashes:
            p = subprocess.Popen(
                ["git", "diff-tree", "-r", "--root", "--stdin"],
                cwd=str(self.repo_path),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            tree_out, _ = p.communicate("\n".join(commit_hashes) + "\n")
            for line in tree_out.splitlines():
                if "\t" in line:
                    left, path = line.split("\t", 1)
                    parts = left.split()
                    if len(parts) >= 4:
                        b_hash = parts[3]
                        if len(b_hash) in (40, 64) and b_hash != "0" * len(b_hash):
                            blob_path_map[b_hash] = path.strip()

        trees_to_read = [t for t in unreachable_trees if t]
        if trees_to_read:
            p = subprocess.Popen(
                ["git", "cat-file", "--batch"],
                cwd=str(self.repo_path),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            raw_input = "\n".join(trees_to_read).encode("ascii") + b"\n"
            raw_output, _ = p.communicate(raw_input)
            stream = io.BytesIO(raw_output)
            while True:
                header_line = stream.readline()
                if not header_line:
                    break
                header_parts = header_line.decode("utf-8", errors="replace").strip().split()
                if len(header_parts) >= 3:
                    try:
                        size = int(header_parts[2])
                    except ValueError:
                        break
                    tree_bytes = stream.read(size)
                    stream.read(1)
                    idx = 0
                    while idx < len(tree_bytes):
                        space_idx = tree_bytes.find(b" ", idx)
                        null_idx = tree_bytes.find(b"\x00", space_idx)
                        if space_idx == -1 or null_idx == -1 or null_idx + 21 > len(tree_bytes):
                            break
                        mode = tree_bytes[idx:space_idx].decode(errors="replace")
                        name = tree_bytes[space_idx + 1:null_idx].decode(errors="replace")
                        sha = binascii.hexlify(tree_bytes[null_idx + 1:null_idx + 21]).decode("ascii")
                        if not mode.startswith("40000"):
                            blob_path_map[sha] = name
                        idx = null_idx + 21
                elif len(header_parts) == 2 and header_parts[1] == "missing":
                    continue
                else:
                    break

        return blob_path_map

    def _batch_extract_blobs(
        self,
        blob_hashes: List[str],
        type_and_sizes: Dict[str, Tuple[str, int]],
        blob_path_map: Dict[str, str],
    ) -> List[DanglingBlob]:
        """Extracts blob contents using a single streamed 'git cat-file --batch' process."""
        blobs: List[DanglingBlob] = []
        readable_hashes: List[str] = []

        for b_hash in blob_hashes:
            size = type_and_sizes.get(b_hash, ("blob", 0))[1]
            path = blob_path_map.get(b_hash)
            if size > self.MAX_BLOB_SIZE_BYTES:
                blobs.append(
                    DanglingBlob(
                        blob_hash=b_hash,
                        size=size,
                        content="[Binary or oversized file content omitted - size: %d bytes]" % size,
                        is_binary=True,
                        associated_path=path,
                    )
                )
            else:
                readable_hashes.append(b_hash)

        if readable_hashes:
            p = subprocess.Popen(
                ["git", "cat-file", "--batch"],
                cwd=str(self.repo_path),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            raw_input = b"\n".join(h.encode("ascii") for h in readable_hashes) + b"\n"
            raw_output, _ = p.communicate(raw_input)

            stream = io.BytesIO(raw_output)
            while True:
                header_line = stream.readline()
                if not header_line:
                    break
                header_parts = header_line.decode("utf-8", errors="replace").strip().split()
                if len(header_parts) >= 3:
                    obj_hash, _, size_str = header_parts[0], header_parts[1], header_parts[2]
                    try:
                        size = int(size_str)
                    except ValueError:
                        break
                    raw_data = stream.read(size)
                    stream.read(1)  # trailing newline from git cat-file
                    is_binary = b"\x00" in raw_data[:8000]
                    content = (
                        "[Binary blob data (%d bytes)]" % size
                        if is_binary
                        else raw_data.decode("utf-8", errors="replace")
                    )
                    blobs.append(
                        DanglingBlob(
                            blob_hash=obj_hash,
                            size=size,
                            content=content,
                            is_binary=is_binary,
                            associated_path=blob_path_map.get(obj_hash),
                        )
                    )
                elif len(header_parts) == 2 and header_parts[1] == "missing":
                    continue
                else:
                    break

        return blobs

    def _run_git(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        full_cmd = ["git"] + args
        try:
            return subprocess.run(
                full_cmd,
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.GIT_CMD_TIMEOUT_SECONDS,
                check=check,
            )
        except subprocess.TimeoutExpired:
            if check:
                raise RuntimeError(f"Git command timed out after {self.GIT_CMD_TIMEOUT_SECONDS}s: {' '.join(args)}")
            return subprocess.CompletedProcess(
                args=full_cmd,
                returncode=124,
                stdout="",
                stderr="git command timed out",
            )
        except subprocess.CalledProcessError as e:
            if check:
                raise
            return subprocess.CompletedProcess(
                args=full_cmd,
                returncode=e.returncode,
                stdout=e.stdout or "",
                stderr=e.stderr or "",
            )
        except FileNotFoundError:
            return subprocess.CompletedProcess(
                args=full_cmd,
                returncode=127,
                stdout="",
                stderr="git not found",
            )

