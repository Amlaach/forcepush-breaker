"""
Unified Forensics & Security Scan Pipeline for GitGhost.

Orchestrates live git forensics, entropy analysis, secret detection & redaction,
AI-powered context triage, repository hygiene scoring, and remediation planning.
Used identically across CLI, Web UI, and CI/CD runners.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from gitghost.ai_triage import AITriage, AITriageResult
from gitghost.git_forensics import ForensicsScanResult, GitForensics
from gitghost.redactor import RedactionResult, SecretFinding, SecretRedactor
from gitghost.remediation import RemediationGenerator, RemediationPlan
from gitghost.scoring import HygieneScoreReport, HygieneScorer


@dataclass
class PipelineResult:
    repo_path: str
    scan_result: ForensicsScanResult
    findings: List[SecretFinding]
    triage_map: Dict[str, AITriageResult]
    hygiene: HygieneScoreReport
    remediation: RemediationPlan


def run_scan_pipeline(
    repo_path: str | Path = ".",
    ai_provider: str = "none",
    model: Optional[str] = None,
    entropy_threshold: float = SecretRedactor.ENTROPY_THRESHOLD,
    on_forensics_done: Optional[Callable[[ForensicsScanResult], None]] = None,
    on_item_scanned: Optional[Callable[[int, int], None]] = None,
) -> PipelineResult:
    """Executes the complete GitGhost forensics and security audit pipeline.

    Scans commit messages, reconstructed diffs, and detached blob content,
    applies strict cryptographic redaction, computes hygiene score, and creates
    the remediation playbook.
    """
    resolved_path = Path(repo_path).resolve()
    forensics = GitForensics(resolved_path)
    scan_result = forensics.scan()

    if on_forensics_done:
        on_forensics_done(scan_result)

    redactor = SecretRedactor(entropy_threshold=entropy_threshold)
    findings: List[SecretFinding] = []

    total_items = len(scan_result.dangling_commits) + len(scan_result.dangling_blobs)
    scanned_counter = 0

    for commit in scan_result.dangling_commits:
        msg_res: RedactionResult = redactor.scan_and_redact(
            commit.message,
            file_path="[Commit Message]",
            commit_hash=commit.commit_hash,
        )
        findings.extend(msg_res.findings)

        primary_file = commit.changed_files[0] if commit.changed_files else "Diff"
        diff_res: RedactionResult = redactor.scan_and_redact(
            commit.diff_content,
            file_path=primary_file,
            commit_hash=commit.commit_hash,
        )
        findings.extend(diff_res.findings)

        scanned_counter += 1
        if on_item_scanned:
            on_item_scanned(scanned_counter, total_items)

    for blob in scan_result.dangling_blobs:
        if not blob.is_binary:
            blob_path = blob.associated_path or "Detached Blob"
            blob_res: RedactionResult = redactor.scan_and_redact(
                blob.content,
                file_path=blob_path,
                blob_hash=blob.blob_hash,
            )
            findings.extend(blob_res.findings)

        scanned_counter += 1
        if on_item_scanned:
            on_item_scanned(scanned_counter, total_items)

    triage_map: Dict[str, AITriageResult] = {}
    effective_provider = (ai_provider or "none").lower()

    if effective_provider != "none" and findings:
        triage_engine = AITriage(provider=effective_provider, model=model)
        for f in findings:
            matched_commit = next(
                (c for c in scan_result.dangling_commits if c.commit_hash == f.commit_hash),
                None,
            )
            verdict = triage_engine.triage_finding(
                finding_rule=f.rule_name,
                masked_snippet=f.masked_value,
                context_line=f.context_line,
                commit_message=matched_commit.message if matched_commit else None,
                author=matched_commit.author if matched_commit else None,
                file_path=f.file_path,
            )
            triage_map[f.finding_id] = verdict

    commit_dates = [c.date for c in scan_result.dangling_commits if c.date]
    hygiene = HygieneScorer.calculate(
        dangling_commits_count=len(scan_result.dangling_commits),
        dangling_blobs_count=len(scan_result.dangling_blobs),
        findings=findings,
        triage_results=triage_map,
        commit_dates=commit_dates,
    )

    remediation = RemediationGenerator.generate_plan(
        repo_path=str(resolved_path),
        findings=findings,
        dangling_commits_count=len(scan_result.dangling_commits),
        dangling_blobs_count=len(scan_result.dangling_blobs),
    )

    return PipelineResult(
        repo_path=str(resolved_path),
        scan_result=scan_result,
        findings=findings,
        triage_map=triage_map,
        hygiene=hygiene,
        remediation=remediation,
    )
