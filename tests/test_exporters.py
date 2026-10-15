import json
import pytest
from gitghost.git_forensics import ForensicsScanResult, DanglingCommit
from gitghost.redactor import SecretFinding
from gitghost.ai_triage import AITriageResult
from gitghost.scoring import HygieneScoreReport
from gitghost.remediation import RemediationGenerator
from gitghost.exporters import ReportExporter

@pytest.fixture
def sample_audit_data():
    scan = ForensicsScanResult(
        repo_path="/test/repo", is_git_repo=True,
        dangling_commits=[
            DanglingCommit(
                commit_hash="deadbeef1234567890deadbeef1234567890", author="Alice <alice@corp.internal>",
                date="2026-10-15T12:00:00Z", message="chore: quick test of db credentials",
                changed_files=[".env"], diff_content="+ DATABASE_URL=postgres://admin:P@ss123@db:5432/db",
            )
        ],
        dangling_blobs=[], unreachable_trees=[],
    )
    finding = SecretFinding(
        finding_id="SEC-0001", rule_name="Database Connection URI with Password",
        match_type="pattern", severity_estimate="Critical",
        masked_value="postgres://admin:[REDACTED_DB_PASSWORD]@db:5432/db",
        line_number=1, context_line="DATABASE_URL=postgres://admin:[REDACTED_DB_PASSWORD]@db:5432/db",
        entropy=4.7, file_path=".env", commit_hash="deadbeef1234567890deadbeef1234567890",
    )
    triage = {
        "SEC-0001": AITriageResult(
            severity="Critical", is_false_positive=False, risk_score=9.5,
            technical_explanation="Database credentials committed directly.",
            recommended_action="Rotate password immediately.", provider_used="Heuristic",
        )
    }
    hygiene = HygieneScoreReport(
        score=73, grade="C (Fair)", color="yellow", summary="Sensitive credentials found in unreachable commits.",
        dangling_commits_count=1, dangling_blobs_count=0, critical_findings_count=1,
        high_findings_count=0, medium_findings_count=0, low_findings_count=0, false_positives_count=0,
    )
    remediation = RemediationGenerator.generate_plan("/test/repo", [finding], 1, 0)
    return scan, [finding], triage, hygiene, remediation

class TestReportExporter:
    def test_json_export_structure(self, sample_audit_data):
        scan, findings, triage, hygiene, remediation = sample_audit_data
        json_str = ReportExporter.to_json(scan, findings, triage, hygiene, remediation)
        data = json.loads(json_str)
        assert data["tool"] == "GitGhost"
        assert data["hygiene_score"]["score"] == 73

    def test_markdown_export(self, sample_audit_data):
        scan, findings, triage, hygiene, remediation = sample_audit_data
        md_str = ReportExporter.to_markdown(scan, findings, triage, hygiene, remediation)
        assert "GitGhost Security & Forensics" in md_str
        assert "Hygiene Score: 73/100" in md_str

    def test_sarif_export(self, sample_audit_data):
        scan, findings, triage, hygiene, remediation = sample_audit_data
        sarif_str = ReportExporter.to_sarif(scan, findings, triage)
        sarif = json.loads(sarif_str)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
