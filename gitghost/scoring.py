"""
Repository Hygiene Score Calculator.

Computes a holistic 0-100 hygiene rating evaluating dangling objects,
history bloat, commit recency, and discovered credential risks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
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
        for f in findings:
            triage = triage_map.get(f.finding_id)
            if triage and triage.is_false_positive:
                fp_count += 1
                continue
            sev = triage.severity if triage else f.severity_estimate
            if sev == "Critical": crit_count += 1
            elif sev == "High": high_count += 1
            elif sev == "Medium": med_count += 1
            else: low_count += 1

        if crit_count > 0:
            deductions.append(DeductionItem("Critical Secrets", f"{crit_count} Critical credential(s) detected in unreachable objects", min(crit_count * 25, 100)))
        if high_count > 0:
            deductions.append(DeductionItem("High Risk Secrets", f"{high_count} High-risk credential(s) detected", min(high_count * 15, 45)))
        if med_count > 0:
            deductions.append(DeductionItem("Medium Risk Findings", f"{med_count} Suspicious token(s) or connection string(s)", min(med_count * 8, 25)))
        if low_count > 0:
            deductions.append(DeductionItem("Low Risk Findings", f"{low_count} Low-severity credential finding(s)", min(low_count * 3, 10)))

        fresh_commits_with_secrets = 0
        if commit_dates and (crit_count > 0 or high_count > 0):
            now = datetime.now(timezone.utc)
            for d_str in commit_dates:
                try:
                    c_date = datetime.fromisoformat(d_str.replace("Z", "+00:00"))
                    if (now - c_date).total_seconds() / 86400 <= 7:
                        fresh_commits_with_secrets += 1
                except Exception: pass

        if fresh_commits_with_secrets > 0:
            deductions.append(DeductionItem("Active Threat Recency", "Leaked credentials were reset recently (< 7 days ago); secrets likely active in production", min(fresh_commits_with_secrets * 10, 20)))

        total_deduction = sum(d.points for d in deductions)
        final_score = max(0, min(100, base_score - total_deduction))

        if final_score >= 90:
            grade, color, summary = "A+ (Pristine)", "green", "Repository history is clean, with minimal or no unreachable secrets."
        elif final_score >= 75:
            grade, color, summary = "B (Good)", "bright_green", "Good hygiene with minor unreferenced history debris. No critical secrets exposed."
        elif final_score >= 60:
            grade, color, summary = "C (Fair)", "yellow", "Moderate history debt or suspicious tokens lingering in dangling objects."
        elif final_score >= 40:
            grade, color, summary = "D (Warning)", "bright_red", "High risk: Sensitive credentials found in unreachable commits. Pruning required."
        else:
            grade, color, summary = "F (Critical Danger)", "bold red", "Active critical secrets exposed in orphaned git history! Immediate remediation required."

        return HygieneScoreReport(
            score=final_score, grade=grade, color=color, summary=summary,
            dangling_commits_count=dangling_commits_count, dangling_blobs_count=dangling_blobs_count,
            critical_findings_count=crit_count, high_findings_count=high_count,
            medium_findings_count=med_count, low_findings_count=low_count,
            false_positives_count=fp_count, deductions=deductions,
        )
