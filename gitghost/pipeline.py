"""
Unified Forensics & Security Scan Pipeline for GitGhost.

Orchestrates live git forensics, entropy analysis, secret detection & redaction,
AI-powered context triage, repository hygiene scoring, and remediation planning.
Used identically across CLI, Web UI, and CI/CD runners.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from gitghost.ai_triage import AITriage, AITriageResult
from gitghost.git_forensics import ForensicsScanResult, GitForensics, detect_ai_agent
from gitghost.github_remote import (
    ForkForensicsTarget,
    HistoryOverwriteEvent,
    RemoteAcquisitionResult,
    SmartGitCloner,
    parse_github_url,
)
from gitghost.redactor import RedactionResult, SecretFinding, SecretRedactor
from gitghost.remediation import RemediationGenerator, RemediationPlan
from gitghost.scoring import HygieneScoreReport, HygieneScorer

_DIFF_HEADER_RE = re.compile(r"^diff --git a/.*? b/(.+)$")
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _scan_unified_diff_by_file(
    redactor: SecretRedactor,
    diff_content: str,
    fallback_file: str,
    commit_hash: str,
) -> RedactionResult:
    """Splits a unified diff by file headers, scanning each file chunk with accurate file_path and line numbers."""
    if not diff_content:
        return RedactionResult(redacted_text="", findings=[])

    if len(diff_content.encode("utf-8", errors="replace")) > GitForensics.MAX_TEXT_SCAN_BYTES:
        return RedactionResult(
            redacted_text="[Oversized diff omitted from text scan (>10MB)]",
            findings=[],
        )

    lines = diff_content.splitlines(keepends=True)
    sections: List[Tuple[str, List[str]]] = []
    current_file = fallback_file
    current_lines: List[str] = []

    for line in lines:
        m = _DIFF_HEADER_RE.match(line.rstrip("\r\n"))
        if m:
            if current_lines:
                sections.append((current_file, current_lines))
            current_file = m.group(1).strip()
            current_lines = [line]
        else:
            current_lines.append(line)

    if current_lines:
        sections.append((current_file, current_lines))

    redacted_chunks: List[str] = []
    all_findings: List[SecretFinding] = []

    for file_path, sec_lines in sections:
        sec_text = "".join(sec_lines)
        if "Binary files " in sec_text and " differ" in sec_text:
            redacted_chunks.append(sec_text)
            continue

        # Map relative section line index (1-based) to actual file line number from @@ hunk headers
        line_map: Dict[int, int] = {}
        real_line: Optional[int] = None
        for idx, raw_ln in enumerate(sec_lines, start=1):
            stripped = raw_ln.rstrip("\r\n")
            hm = _HUNK_HEADER_RE.match(stripped)
            if hm:
                real_line = int(hm.group(1))
                line_map[idx] = real_line
            elif real_line is not None:
                if stripped.startswith("---") or stripped.startswith("+++"):
                    line_map[idx] = real_line
                elif stripped.startswith("-"):
                    line_map[idx] = real_line
                else:
                    line_map[idx] = real_line
                    real_line += 1

        sec_res = redactor.scan_and_redact(
            sec_text,
            file_path=file_path,
            commit_hash=commit_hash,
        )
        for f in sec_res.findings:
            if f.line_number in line_map:
                f.line_number = line_map[f.line_number]
            all_findings.append(f)
        redacted_chunks.append(sec_res.redacted_text)

    return RedactionResult(redacted_text="".join(redacted_chunks), findings=all_findings)


@dataclass
class PipelineResult:
    repo_path: str
    scan_result: ForensicsScanResult
    findings: List[SecretFinding]
    triage_map: Dict[str, AITriageResult]
    hygiene: HygieneScoreReport
    remediation: RemediationPlan
    is_remote: bool = False
    remote_url: Optional[str] = None
    local_mirror_path: Optional[Path] = None
    history_events: List[HistoryOverwriteEvent] = field(default_factory=list)
    discovered_forks: List[ForkForensicsTarget] = field(default_factory=list)


def run_scan_pipeline(
    repo_path: str | Path = ".",
    ai_provider: str = "none",
    ai_api_key: Optional[str] = None,
    model: Optional[str] = None,
    entropy_threshold: float = SecretRedactor.ENTROPY_THRESHOLD,
    github_token: Optional[str] = None,
    clone_source_override: Optional[str] = None,
    scan_forks: bool = True,
    keep_remote_workspace: bool = False,
    on_forensics_done: Optional[Callable[[ForensicsScanResult], None]] = None,
    on_item_scanned: Optional[Callable[[int, int], None]] = None,
    on_phase: Optional[Callable[[str, int], None]] = None,
) -> PipelineResult:
    """Executes the complete GitGhost forensics and security audit pipeline.

    Supports both local Git repositories and remote GitHub URLs (with smart mirror cloning,
    GitHub API force-push/overwrite discovery, public fork auditing, and guaranteed temporary directory cleanup).
    """
    raw_target = str(repo_path).strip() or "."
    gh_target = parse_github_url(raw_target)
    remote_acq: Optional[RemoteAcquisitionResult] = None

    try:
        if gh_target is not None:
            remote_acq = SmartGitCloner.acquire(
                target=gh_target,
                github_token=github_token,
                clone_source_override=clone_source_override,
                scan_forks=scan_forks,
                on_phase=on_phase,
            )
            working_repo_path = remote_acq.local_clone_path
            display_repo_label = gh_target.clone_url

        else:
            working_repo_path = Path(raw_target).resolve()
            display_repo_label = str(working_repo_path)

        if on_phase:
            on_phase("Running git fsck & object database forensics...", 50)

        forensics = GitForensics(working_repo_path)
        scan_result = forensics.scan()
        scan_result.repo_path = display_repo_label

        if remote_acq is not None:
            existing_hashes = {c.commit_hash for c in scan_result.dangling_commits}
            missing_local_shas = [
                sha
                for sha in remote_acq.discovered_orphan_shas
                if sha not in existing_hashes and SmartGitCloner._object_exists(working_repo_path, sha)
            ]
            if missing_local_shas:
                extra_local_commits = forensics._batch_reconstruct_commits(missing_local_shas)
                for ec in extra_local_commits:
                    if ec.commit_hash not in existing_hashes:
                        scan_result.dangling_commits.append(ec)
                        existing_hashes.add(ec.commit_hash)

            for api_c in remote_acq.api_recovered_commits:
