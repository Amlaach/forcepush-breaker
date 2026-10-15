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
