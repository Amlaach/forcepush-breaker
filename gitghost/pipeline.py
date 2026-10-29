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
    ParsedRemoteTarget,
    RemoteAcquisitionResult,
    SmartGitCloner,
    parse_github_url,
    parse_remote_url,
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
    remote_target = parse_remote_url(raw_target)
    remote_acq: Optional[RemoteAcquisitionResult] = None

    try:
        if remote_target is not None:
            remote_acq = SmartGitCloner.acquire(
                target=remote_target,
                github_token=github_token,
                clone_source_override=clone_source_override,
                scan_forks=scan_forks,
                on_phase=on_phase,
            )
            working_repo_path = remote_acq.local_clone_path
            display_repo_label = remote_target.clone_url

        else:
            working_repo_path = Path(raw_target).resolve()
            display_repo_label = str(working_repo_path)

        if on_phase:
            on_phase("Running git fsck & object database forensics...", 50)

        forensics = GitForensics(working_repo_path)
        scan_result = forensics.scan()
        scan_result.repo_path = display_repo_label
        # Ensure local reflogs and dangling objects are preserved for downstream triage

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
                if api_c.commit_hash not in existing_hashes:
                    scan_result.dangling_commits.append(api_c)
                    existing_hashes.add(api_c.commit_hash)

            scan_result.total_objects_scanned = (
                len(scan_result.dangling_commits)
                + len(scan_result.dangling_blobs)
                + len(scan_result.unreachable_trees)
                + len(scan_result.unreachable_tags)
            )

        if on_forensics_done:
            on_forensics_done(scan_result)

        if on_phase:
            on_phase("Scanning objects with Shannon entropy & Regex redactor...", 65)

        redactor = SecretRedactor(entropy_threshold=entropy_threshold)
        findings: List[SecretFinding] = []

        total_items = len(scan_result.dangling_commits) + len(scan_result.dangling_blobs)
        scanned_counter = 0

        for commit in scan_result.dangling_commits:
            if commit.ai_agent is None:
                commit.ai_agent = detect_ai_agent(
                    author=commit.author,
                    message=commit.message,
                    diff_content=commit.diff_content,
                )

            msg_res: RedactionResult = redactor.scan_and_redact(
                commit.message,
                file_path="[Commit Message]",
                commit_hash=commit.commit_hash,
            )
            commit.redacted_message = msg_res.redacted_text
            for f in msg_res.findings:
                if commit.ai_agent and commit.ai_agent.is_ai_agent:
                    f.is_ai_agent = True
                    f.ai_agent_name = commit.ai_agent.agent_name
                    f.ai_agent_evidence = list(commit.ai_agent.evidence)
            findings.extend(msg_res.findings)

            primary_file = commit.changed_files[0] if commit.changed_files else "Diff"
            diff_res: RedactionResult = _scan_unified_diff_by_file(
                redactor=redactor,
                diff_content=commit.diff_content,
                fallback_file=primary_file,
                commit_hash=commit.commit_hash,
            )
            commit.redacted_diff = diff_res.redacted_text
            for f in diff_res.findings:
                if commit.ai_agent and commit.ai_agent.is_ai_agent:
                    f.is_ai_agent = True
                    f.ai_agent_name = commit.ai_agent.agent_name
                    f.ai_agent_evidence = list(commit.ai_agent.evidence)
            findings.extend(diff_res.findings)

            scanned_counter += 1
            if on_item_scanned:
                on_item_scanned(scanned_counter, total_items)

        for blob in scan_result.dangling_blobs:
            if not blob.is_binary and blob.size <= GitForensics.MAX_TEXT_SCAN_BYTES:
                blob_path = blob.associated_path or "Detached Blob"
                blob_res: RedactionResult = redactor.scan_and_redact(
                    blob.content,
                    file_path=blob_path,
                    blob_hash=blob.blob_hash,
                )
                blob.redacted_content = blob_res.redacted_text
                findings.extend(blob_res.findings)
            else:
                blob.redacted_content = blob.content

            scanned_counter += 1
            if on_item_scanned:
                on_item_scanned(scanned_counter, total_items)

        # Redact branch_commits messages; for live remote GitHub scans, also audit recent historical commit diffs
        dangling_sha_set = {c.commit_hash for c in scan_result.dangling_commits}
        for idx_bc, bc in enumerate(scan_result.branch_commits):
            bc_msg_res = redactor.scan_and_redact(
                bc.message,
                file_path="[Branch Commit Message]",
                commit_hash=bc.commit_hash,
            )
            bc.redacted_message = bc_msg_res.redacted_text
            if remote_target is not None and not clone_source_override and bc.commit_hash not in dangling_sha_set:
                findings.extend(bc_msg_res.findings)
                if idx_bc < 25:
                    raw_bc_diff = forensics.read_commit_diff(bc.commit_hash)
                    if raw_bc_diff:
                        bc.diff_content = raw_bc_diff
                        fb_file = bc.changed_files[0] if bc.changed_files else "Diff"
                        bc_diff_res = _scan_unified_diff_by_file(
                            redactor=redactor,
                            diff_content=raw_bc_diff,
                            fallback_file=fb_file,
                            commit_hash=bc.commit_hash,
                        )
                        bc.redacted_diff = bc_diff_res.redacted_text
                        for f in bc_diff_res.findings:
                            if bc.ai_agent and bc.ai_agent.is_ai_agent:
                                f.is_ai_agent = True
                                f.ai_agent_name = bc.ai_agent.agent_name
                                f.ai_agent_evidence = list(bc.ai_agent.evidence)
                        findings.extend(bc_diff_res.findings)

        for idx, f in enumerate(findings, start=1):
            prefix = f.finding_id.split("-")[0] if "-" in f.finding_id else "SEC"
            f.finding_id = f"{prefix}-{idx:04d}"

        triage_map: Dict[str, AITriageResult] = {}
        effective_provider = (ai_provider or "none").lower()
        if effective_provider == "none" and ai_api_key:
            effective_provider = "auto"

        if effective_provider != "none" and findings:
            if on_phase:
                on_phase("Performing AI context triage on redacted findings...", 85)
            triage_engine = AITriage(provider=effective_provider, model=model, api_key=ai_api_key)
            for f in findings:
                matched_commit = next(
                    (c for c in scan_result.dangling_commits if c.commit_hash == f.commit_hash),
                    None,
                )
                verdict = triage_engine.triage_finding(
                    finding_rule=f.rule_name,
                    masked_snippet=f.masked_value,
                    context_line=f.context_line,
                    commit_message=(matched_commit.redacted_message or matched_commit.message) if matched_commit else None,
                    author=matched_commit.author if matched_commit else None,
                    file_path=f.file_path,
                )
                triage_map[f.finding_id] = verdict

        if on_phase:
            on_phase("Computing hygiene scorecard & remediation playbook...", 95)

        commit_dates = [c.date for c in scan_result.dangling_commits if c.date]
        hygiene = HygieneScorer.calculate(
            dangling_commits_count=len(scan_result.dangling_commits),
            dangling_blobs_count=len(scan_result.dangling_blobs),
            findings=findings,
            triage_results=triage_map,
            commit_dates=commit_dates,
        )

        orphaned_shas = [c.commit_hash for c in scan_result.dangling_commits]
        remediation = RemediationGenerator.generate_plan(
            repo_path=display_repo_label,
            findings=findings,
            dangling_commits_count=len(scan_result.dangling_commits),
            dangling_blobs_count=len(scan_result.dangling_blobs),
            orphaned_commit_shas=orphaned_shas,
        )

        if on_phase:
            on_phase("Scan complete.", 100)

        retained_mirror: Optional[Path] = None
        if remote_acq is not None and keep_remote_workspace:
            remote_acq.is_temporary = False
            retained_mirror = remote_acq.local_clone_path

        return PipelineResult(
            repo_path=display_repo_label,
            scan_result=scan_result,
            findings=findings,
            triage_map=triage_map,
            hygiene=hygiene,
            remediation=remediation,
            is_remote=remote_target is not None,
            remote_url=remote_target.clone_url if remote_target else None,
            local_mirror_path=retained_mirror,
            history_events=remote_acq.history_events if remote_acq else [],
            discovered_forks=remote_acq.discovered_forks if remote_acq else [],
        )
    finally:
        if remote_acq is not None and remote_acq.is_temporary:
            SmartGitCloner.cleanup_workspace(remote_acq.local_clone_path)

