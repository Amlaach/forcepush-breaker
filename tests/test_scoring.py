"""
Unit tests for HygieneScorer and score calculations.
"""

from datetime import datetime, timezone, timedelta
import pytest
from gitghost.scoring import HygieneScorer
from gitghost.redactor import SecretFinding
from gitghost.ai_triage import AITriageResult


def make_finding(finding_id: str, severity: str) -> SecretFinding:
    return SecretFinding(
        finding_id=finding_id,
        rule_name="Test Rule",
        match_type="pattern",
        severity_estimate=severity,
        masked_value="AKIA************MPLE",
        line_number=10,
        context_line="AWS_KEY=AKIA************MPLE",
        entropy=4.5,
        file_path="src/config.py",
        commit_hash="abc1234567890",
    )


class TestHygieneScorer:
    def test_pristine_repository_score(self):
        report = HygieneScorer.calculate(
            dangling_commits_count=0,
            dangling_blobs_count=0,
            findings=[],
        )
        assert report.score == 100
        assert "A+" in report.grade
        assert len(report.deductions) == 0

    def test_dangling_objects_penalty(self):
        report = HygieneScorer.calculate(
            dangling_commits_count=4,
            dangling_blobs_count=8,
            findings=[],
        )
        assert report.score < 100
        assert report.score == 87
        assert "B" in report.grade
        assert len(report.deductions) == 2

    def test_critical_secret_penalty(self):
        finding = make_finding("SEC-0001", "Critical")
        report = HygieneScorer.calculate(
            dangling_commits_count=1,
            dangling_blobs_count=0,
            findings=[finding],
        )
        assert report.score == 73
        assert report.critical_findings_count == 1
        assert any(d.category == "Critical Secrets" for d in report.deductions)

    def test_false_positive_filtered_out(self):
        finding = make_finding("SEC-0001", "Critical")
        triage = {
            "SEC-0001": AITriageResult(
                severity="Low",
                is_false_positive=True,
                risk_score=1.5,
                technical_explanation="Test mock fixture",
                recommended_action="None",
                provider_used="Test",
            )
        }
        report = HygieneScorer.calculate(
            dangling_commits_count=0,
            dangling_blobs_count=0,
            findings=[finding],
            triage_results=triage,
        )
        assert report.critical_findings_count == 0
        assert report.false_positives_count == 1
        assert report.score == 100

    def test_score_clamping_at_zero(self):
        findings = [make_finding(f"SEC-{i}", "Critical") for i in range(10)]
        report = HygieneScorer.calculate(
            dangling_commits_count=50,
            dangling_blobs_count=100,
            findings=findings,
        )
        assert report.score == 0
        assert "F" in report.grade

    def test_recent_commit_recency_penalty(self):
        finding = make_finding("SEC-0001", "Critical")
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        report = HygieneScorer.calculate(
            dangling_commits_count=1,
            dangling_blobs_count=0,
            findings=[finding],
            commit_dates=[yesterday],
        )
        assert any(d.category == "Active Threat Recency" for d in report.deductions)
