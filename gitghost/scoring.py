"""
Repository Hygiene Score Calculator.

Computes a holistic 0-100 hygiene rating evaluating dangling objects,
history bloat, commit recency, and discovered credential risks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from gitghost.redactor import SecretFinding
from gitghost.ai_triage import AITriageResult


@dataclass
class DeductionItem:
    category: str
    reason: str
    points: int


@dataclass
class HygieneScoreReport:
    score: int
    grade: str
    color: str
    summary: str
    dangling_commits_count: int
    dangling_blobs_count: int
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    low_findings_count: int
    false_positives_count: int
    deductions: List[DeductionItem] = field(default_factory=list)


class HygieneScorer:
    @classmethod
    def calculate(
        cls,
        dangling_commits_count: int,
        dangling_blobs_count: int,
        findings: List[SecretFinding],
        triage_results: Optional[Dict[str, AITriageResult]] = None,
        commit_dates: Optional[List[str]] = None,
    ) -> HygieneScoreReport:
        base_score = 100
        deductions: List[DeductionItem] = []

        if dangling_commits_count > 15:
            deductions.append(DeductionItem("Dangling Commits", f"Severe repository history fragmentation ({dangling_commits_count} dangling commits)", 20))
        elif dangling_commits_count >= 6:
            deductions.append(DeductionItem("Dangling Commits", f"Moderate history fragmentation ({dangling_commits_count} dangling commits)", 12))
        elif dangling_commits_count >= 3:
            deductions.append(DeductionItem("Dangling Commits", f"Minor history fragmentation ({dangling_commits_count} dangling commits)", 6))
        elif dangling_commits_count >= 1:
            deductions.append(DeductionItem("Dangling Commits", f"Presence of orphaned commits ({dangling_commits_count} dangling commit)", 2))

        if dangling_blobs_count > 20:
            deductions.append(DeductionItem("Dangling Blobs", f"Heavy unreferenced blob debris ({dangling_blobs_count} blobs)", 15))
        elif dangling_blobs_count >= 6:
            deductions.append(DeductionItem("Dangling Blobs", f"Unreferenced blob clutter ({dangling_blobs_count} blobs)", 7))
        elif dangling_blobs_count >= 1:
            deductions.append(DeductionItem("Dangling Blobs", f"Orphaned file blobs present ({dangling_blobs_count} blobs)", 2))

        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        fp_count = 0

        triage_map = triage_results or {}
