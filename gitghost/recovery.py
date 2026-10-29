"""
Safe File and Commit Recovery Engine for GitGhost.

Supports recovering orphaned files, detached blobs, and unified commit diffs
with strict cryptographic secret redaction by default (include_raw=False),
while allowing explicit unredacted recovery (include_raw=True) when authorized by the user.
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from gitghost.exporters import ReportExporter
from gitghost.git_forensics import DanglingBlob, DanglingCommit, GitForensics
from gitghost.pipeline import PipelineResult
from gitghost.redactor import SecretRedactor

_DIFF_HEADER_RE = re.compile(r"^diff --git a/.*? b/(.+)$")


@dataclass
class RecoveredArtifact:
    filename: str
    content: str
    is_redacted: bool
    source_type: str  # "commit_file" | "commit_diff" | "blob"
    object_hash: str
    file_path: Optional[str] = None


class ObjectRecoveryEngine:
    """Recovers files and diffs from dangling commits and detached blobs."""

    @classmethod
    def recover_blob(
        cls,
        pipeline_res: PipelineResult,
        blob_hash: str,
        include_raw: bool = False,
    ) -> RecoveredArtifact:
        target_hash = (blob_hash or "").strip()
        blob: Optional[DanglingBlob] = next(
            (
                b
                for b in pipeline_res.scan_result.dangling_blobs
                if b.blob_hash == target_hash or b.blob_hash.startswith(target_hash)
            ),
            None,
        )
        if blob is None:
            raise ValueError(f"Dangling blob not found: {target_hash}")

        raw_text = blob.content
        redacted_text = blob.redacted_content or SecretRedactor().scan_and_redact(raw_text).redacted_text
        chosen_text = raw_text if include_raw else redacted_text

        base_name = Path(blob.associated_path).name if blob.associated_path else f"blob_{blob.blob_hash[:10]}.txt"
        suffix_tag = "raw" if include_raw else "redacted"
        safe_filename = f"{blob.blob_hash[:8]}_{suffix_tag}_{base_name}"

        return RecoveredArtifact(
            filename=safe_filename,
            content=chosen_text,
            is_redacted=not include_raw,
            source_type="blob",
            object_hash=blob.blob_hash,
            file_path=blob.associated_path,
        )

    @classmethod
    def recover_commit_diff(
        cls,
        pipeline_res: PipelineResult,
        commit_hash: str,
        include_raw: bool = False,
    ) -> RecoveredArtifact:
        target_hash = (commit_hash or "").strip()
        commit: Optional[DanglingCommit] = next(
            (
                c
                for c in pipeline_res.scan_result.dangling_commits
                if c.commit_hash == target_hash or c.commit_hash.startswith(target_hash)
            ),
            None,
        )
        if commit is None:
            raise ValueError(f"Dangling commit not found: {target_hash}")

        raw_diff = commit.diff_content
        redacted_diff = commit.redacted_diff or SecretRedactor().scan_and_redact(raw_diff).redacted_text
        chosen_diff = raw_diff if include_raw else redacted_diff
        suffix_tag = "raw" if include_raw else "redacted"

        header = (
            f"Commit: {commit.commit_hash}\n"
            f"Author: {commit.author}\n"
            f"Date:   {commit.date}\n"
            f"Mode:   {'UNREDACTED (RAW)' if include_raw else 'STRICTLY REDACTED'}\n\n"
            f"    {(commit.message if include_raw else (commit.redacted_message or commit.message))}\n\n"
        )
        return RecoveredArtifact(
            filename=f"commit_{commit.commit_hash[:10]}_{suffix_tag}.patch",
            content=header + chosen_diff,
            is_redacted=not include_raw,
            source_type="commit_diff",
            object_hash=commit.commit_hash,
            file_path=None,
        )

    @classmethod
    def recover_commit_file(
        cls,
        pipeline_res: PipelineResult,
        commit_hash: str,
        file_path: Optional[str] = None,
        include_raw: bool = False,
    ) -> RecoveredArtifact:
        target_hash = (commit_hash or "").strip()
        commit: Optional[DanglingCommit] = next(
            (
                c
                for c in pipeline_res.scan_result.dangling_commits
                if c.commit_hash == target_hash or c.commit_hash.startswith(target_hash)
            ),
            None,
        )
        if commit is None:
            raise ValueError(f"Dangling commit not found: {target_hash}")

        target_file = (file_path or "").strip()
        if not target_file:
            target_file = commit.changed_files[0] if commit.changed_files else ""

        if not target_file:
            return cls.recover_commit_diff(pipeline_res, commit.commit_hash, include_raw=include_raw)

        # 0. Check pre-extracted full file snapshot on DanglingCommit (works for both local & remote clones!)
        raw_file_content: Optional[str] = None
        if getattr(commit, "file_snapshots", None) and target_file in commit.file_snapshots:
            raw_file_content = commit.file_snapshots[target_file]

        # 1. Try extracting full file snapshot from local Git repository if available on disk
        local_repo = Path(pipeline_res.repo_path)
        if raw_file_content is None and not pipeline_res.is_remote and local_repo.exists():
            try:
                res = subprocess.run(
                    ["git", "show", f"{commit.commit_hash}:{target_file}"],
                    cwd=str(local_repo),
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                if res.returncode == 0 and len(res.stdout) <= GitForensics.MAX_TEXT_SCAN_BYTES:
                    if b"\x00" not in res.stdout[:8000]:
                        raw_file_content = res.stdout.decode("utf-8", errors="replace")
            except Exception:
                pass

        # 2. Check if a matching DanglingBlob has the exact file path
        if raw_file_content is None:
            matching_blob = next(
                (
                    b
                    for b in pipeline_res.scan_result.dangling_blobs
                    if b.associated_path == target_file and not b.is_binary
                ),
                None,
            )
            if matching_blob is not None:
                raw_file_content = matching_blob.content

        # 3. Reconstruct file content from commit unified diff section
        if raw_file_content is None:
            raw_file_content = cls._reconstruct_file_from_diff(commit.diff_content, target_file)

        if include_raw:
            final_content = raw_file_content
        else:
            final_content = SecretRedactor().scan_and_redact(
                raw_file_content,
                file_path=target_file,
                commit_hash=commit.commit_hash,
            ).redacted_text

        suffix_tag = "raw" if include_raw else "redacted"
        clean_name = Path(target_file).name or "recovered_file.txt"
        return RecoveredArtifact(
            filename=f"{commit.commit_hash[:8]}_{suffix_tag}_{clean_name}",
            content=final_content,
            is_redacted=not include_raw,
            source_type="commit_file",
            object_hash=commit.commit_hash,
            file_path=target_file,
        )

    @classmethod
    def _reconstruct_file_from_diff(cls, diff_content: str, target_file: str) -> str:
        """Reconstructs file lines from a unified diff section when only the patch is available."""
        if not diff_content:
            return ""
        lines = diff_content.splitlines()
        in_target = False
        extracted: List[str] = []

        for line in lines:
            m = _DIFF_HEADER_RE.match(line)
            if m:
                in_target = m.group(1).strip() == target_file
                continue
            if in_target:
                if line.startswith(("index ", "--- ", "+++ ", "@@ ")):
                    continue
                if line.startswith("+"):
                    extracted.append(line[1:])
                elif line.startswith(" "):
                    extracted.append(line[1:])

        if extracted:
            return "\n".join(extracted) + "\n"
        return diff_content

    @classmethod
    def build_recovery_zip_bundle(
        cls,
        pipeline_res: PipelineResult,
        include_raw: bool = False,
    ) -> bytes:
        """Generates an in-memory ZIP archive with reports, commit patches, and recovered files."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 1. Reports (always strictly redacted)
            md_report = ReportExporter.to_markdown(
                pipeline_res.scan_result,
                pipeline_res.findings,
                pipeline_res.triage_map,
                pipeline_res.hygiene,
                pipeline_res.remediation,
            )
            json_report = ReportExporter.to_json(
                pipeline_res.scan_result,
                pipeline_res.findings,
                pipeline_res.triage_map,
                pipeline_res.hygiene,
                pipeline_res.remediation,
            )
            sarif_report = ReportExporter.to_sarif(
                pipeline_res.scan_result,
                pipeline_res.findings,
                pipeline_res.triage_map,
            )
            zf.writestr("reports/gitghost_audit_report.md", md_report)
            zf.writestr("reports/gitghost_audit_report.json", json_report)
            zf.writestr("reports/gitghost_audit_report.sarif", sarif_report)
            zf.writestr("reports/forcepush_breaker_audit_report.md", md_report)
            zf.writestr("reports/forcepush_breaker_audit_report.json", json_report)
            zf.writestr("reports/forcepush_breaker_audit_report.sarif", sarif_report)

            if include_raw:
                warning_notice = (
                    "====================================================================\n"
                    "SECURITY WARNING: UNREDACTED (RAW) RECOVERY BUNDLE\n"
                    "====================================================================\n\n"
                    "This recovery bundle was generated with include_raw=True.\n"
                    "The recovered files, patches, and detached blobs in this archive\n"
                    "contain UNMASKED secrets and credentials recovered from overwritten Git history.\n\n"
                    "OPERATIONAL SAFETY GUIDELINES:\n"
                    "1. Store this archive in a secure, encrypted location.\n"
                    "2. Rotate all exposed credentials immediately.\n"
                    "3. Do NOT commit or push recovered files to public repositories.\n"
                    "4. Permanently delete this bundle once secret rotation is complete.\n"
                )
                zf.writestr("UNREDACTED_SECURITY_WARNING.txt", warning_notice)

            # 2. Dangling commit patches & recovered files
            for commit in pipeline_res.scan_result.dangling_commits:
                diff_art = cls.recover_commit_diff(
                    pipeline_res, commit.commit_hash, include_raw=include_raw
                )
                zf.writestr(f"commits/{diff_art.filename}", diff_art.content)

                for fpath in commit.changed_files[:25]:
                    try:
                        file_art = cls.recover_commit_file(
                            pipeline_res,
                            commit.commit_hash,
                            file_path=fpath,
                            include_raw=include_raw,
                        )
                        zf.writestr(f"recovered_files/{file_art.filename}", file_art.content)
                    except Exception:
                        pass

            # 3. Detached non-binary blobs
            for blob in pipeline_res.scan_result.dangling_blobs[:50]:
                if not blob.is_binary:
                    try:
                        blob_art = cls.recover_blob(
                            pipeline_res, blob.blob_hash, include_raw=include_raw
                        )
                        zf.writestr(f"recovered_blobs/{blob_art.filename}", blob_art.content)
                    except Exception:
                        pass

        return buf.getvalue()

    @classmethod
    def restore_commit_as_branch(
        cls,
        repo_path: str | Path,
        commit_hash: str,
        branch_name: str,
        checkout: bool = False,
    ) -> Dict[str, object]:
        """Safely restores an orphaned/dangling commit to a new local Git branch."""
        repo_dir = Path(repo_path).resolve()
        if not GitForensics(repo_dir).is_valid_repo():
            raise ValueError(f"Not a valid local Git repository: {repo_dir}")

        clean_sha = (commit_hash or "").strip()
        if not re.match(r"^[0-9a-fA-F]{7,64}$", clean_sha):
            raise ValueError("Invalid commit SHA format.")

        clean_branch = (branch_name or "").strip()
        if (
            not clean_branch
            or clean_branch.startswith(("-", "."))
            or not re.match(r"^[A-Za-z0-9._/\-]+$", clean_branch)
            or ".." in clean_branch
        ):
            raise ValueError("Invalid branch name. Must not start with '-' or '.' and cannot contain '..'.")

        # Verify commit object exists in repo
        verify_res = subprocess.run(
            ["git", "cat-file", "-t", "--", clean_sha],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if verify_res.returncode != 0 or verify_res.stdout.strip() != "commit":
            raise ValueError(f"Commit object '{clean_sha}' does not exist in local repository.")

        # Ensure branch does not already exist
        exists_res = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{clean_branch}"],
            cwd=str(repo_dir),
            check=False,
        )
        if exists_res.returncode == 0:
            raise ValueError(f"Branch '{clean_branch}' already exists. Choose a unique branch name.")

        # Create the branch pointing at the dangling commit
        create_res = subprocess.run(
            ["git", "branch", "--", clean_branch, clean_sha],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if create_res.returncode != 0:
            raise RuntimeError(f"Failed to create branch: {(create_res.stderr or create_res.stdout).strip()}")

        checked_out = False
        notice = f"Branch '{clean_branch}' created pointing to {clean_sha[:10]}."
        if checkout:
            co_res = subprocess.run(
                ["git", "checkout", "--", clean_branch],
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if co_res.returncode == 0:
                checked_out = True
                notice = f"Branch '{clean_branch}' created and checked out!"
            else:
                notice += f" (Created safely, but checkout skipped due to uncommitted changes: {(co_res.stderr or '').strip()})"

        return {
            "success": True,
            "branch_name": clean_branch,
            "commit_hash": clean_sha,
            "checked_out": checked_out,
            "message": notice,
        }

    @classmethod
    def cherry_pick_commit(
        cls,
        repo_path: str | Path,
        commit_hash: str,
        no_commit: bool = False,
    ) -> Dict[str, object]:
        """Safely cherry-picks a dangling commit onto the active branch (aborts cleanly on conflict)."""
        repo_dir = Path(repo_path).resolve()
        if not GitForensics(repo_dir).is_valid_repo():
            raise ValueError(f"Not a valid local Git repository: {repo_dir}")

        clean_sha = (commit_hash or "").strip()
        if not re.match(r"^[0-9a-fA-F]{7,64}$", clean_sha):
            raise ValueError("Invalid commit SHA format.")

        cmd = ["git", "cherry-pick"]
        if no_commit:
            cmd.append("--no-commit")
        cmd.extend(["--", clean_sha])

        res = subprocess.run(
            cmd,
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if res.returncode != 0:
            err_detail = (res.stderr or res.stdout or "").strip()
            # Abort any partial cherry-pick so the user's repo stays clean
            subprocess.run(
                ["git", "cherry-pick", "--abort"],
                cwd=str(repo_dir),
                capture_output=True,
                check=False,
            )
            raise RuntimeError(
                f"Cherry-pick could not be applied cleanly (aborted safely to keep working tree intact): {err_detail}"
            )

        return {
            "success": True,
            "commit_hash": clean_sha,
            "staged_only": no_commit,
            "message": (
                f"Changes from {clean_sha[:10]} staged into working tree (--no-commit)."
                if no_commit
                else f"Commit {clean_sha[:10]} cherry-picked onto current branch!"
            ),
        }

    @classmethod
    def restore_file_to_disk(
        cls,
        pipeline_res: PipelineResult,
        object_type: str,
        commit_hash: str = "",
        blob_hash: str = "",
        file_path: str = "",
        destination_path: Optional[str] = None,
        include_raw: bool = True,
        create_backup: bool = True,
    ) -> Dict[str, object]:
        """Restores a recovered file directly into the repository working tree or an explicit destination path."""
        if object_type == "blob" or (blob_hash and not commit_hash):
            artifact = cls.recover_blob(pipeline_res, blob_hash, include_raw=include_raw)
            rel_default = artifact.file_path or artifact.filename
        else:
            artifact = cls.recover_commit_file(
                pipeline_res,
                commit_hash,
                file_path=file_path or None,
                include_raw=include_raw,
            )
            rel_default = artifact.file_path or file_path or artifact.filename

        if destination_path:
            dest = Path(destination_path).resolve()
            if not pipeline_res.is_remote:
                repo_root = Path(pipeline_res.repo_path).resolve()
                if repo_root not in dest.parents and dest != repo_root:
                    raise ValueError(f"destination_path cannot write outside of repository root: {destination_path}")
        else:
            if pipeline_res.is_remote:
                raise ValueError("Remote repository has no local working tree; specify destination_path.")
            repo_root = Path(pipeline_res.repo_path).resolve()
            clean_rel = rel_default.lstrip("/\\")
            dest = (repo_root / clean_rel).resolve()
            # Guard against path traversal outside repo_root
            if repo_root not in dest.parents and dest != repo_root:
                raise ValueError(f"Unsafe relative file path blocked: {rel_default}")

        backup_created: Optional[str] = None
        if dest.exists() and create_backup:
            bak_path = dest.with_name(dest.name + ".unforce.bak")
            shutil.copy2(dest, bak_path)
            backup_created = str(bak_path)

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(artifact.content, encoding="utf-8")

        return {
            "success": True,
            "saved_path": str(dest),
            "is_redacted": artifact.is_redacted,
            "backup_path": backup_created,
            "message": f"Restored file to {dest}",
        }
