"""
Unit tests for ObjectRecoveryEngine (Redacted vs. Raw recovery and ZIP bundle generation).
"""

import io
import zipfile
import pytest
from gitghost.ai_triage import AITriageResult
from gitghost.git_forensics import DanglingBlob, DanglingCommit, ForensicsScanResult
from gitghost.pipeline import PipelineResult
from gitghost.recovery import ObjectRecoveryEngine
from gitghost.redactor import SecretFinding, SecretRedactor
from gitghost.remediation import RemediationGenerator
from gitghost.scoring import HygieneScorer


@pytest.fixture
def sample_pipeline_result():
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    raw_diff = (
        "diff --git a/.env b/.env\n"
        "--- a/.env\n"
        "+++ b/.env\n"
        "@@ -0,0 +1,2 @@\n"
        "+PORT=8080\n"
        f"+AWS_ACCESS_KEY_ID={raw_secret}\n"
    )
    redactor = SecretRedactor()
    diff_res = redactor.scan_and_redact(raw_diff, file_path=".env", commit_hash="deadbeef12345678")

    commit = DanglingCommit(
        commit_hash="deadbeef1234567890abcdef1234567890abcdef",
        author="Dev <dev@acme.io>",
        date="2026-10-16T10:00:00Z",
        message="chore: accidental commit of aws key",
        changed_files=[".env"],
        diff_content=raw_diff,
        redacted_diff=diff_res.redacted_text,
        redacted_message="chore: accidental commit of aws key",
    )

    blob_raw = f"SLACK_TOKEN=xoxb-123456789012-1234567890123-abcdef1234567890abcdef12\n"
    blob_red = redactor.scan_and_redact(blob_raw, file_path="slack.env", blob_hash="cafebabe12345678").redacted_text
    blob = DanglingBlob(
        blob_hash="cafebabe1234567890abcdef1234567890abcdef",
        size=len(blob_raw),
        content=blob_raw,
        redacted_content=blob_red,
        is_binary=False,
        associated_path="slack.env",
    )

    scan = ForensicsScanResult(
        repo_path="https://github.com/acme/repo.git",
        is_git_repo=True,
        dangling_commits=[commit],
        dangling_blobs=[blob],
        total_objects_scanned=2,
    )
    hygiene = HygieneScorer.calculate(1, 1, diff_res.findings)
    rem = RemediationGenerator.generate_plan("https://github.com/acme/repo.git", diff_res.findings, 1, 1)

    return PipelineResult(
        repo_path="https://github.com/acme/repo.git",
        scan_result=scan,
        findings=diff_res.findings,
        triage_map={},
        hygiene=hygiene,
        remediation=rem,
        is_remote=True,
        remote_url="https://github.com/acme/repo.git",
    )


class TestObjectRecoveryEngine:
    def test_recover_commit_file_redacted_by_default_vs_raw(self, sample_pipeline_result: PipelineResult):
        # Default (include_raw=False) must strictly redact the secret
        redacted_art = ObjectRecoveryEngine.recover_commit_file(
            sample_pipeline_result,
            commit_hash="deadbeef1234",
            file_path=".env",
            include_raw=False,
        )
        assert redacted_art.is_redacted is True
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted_art.content
        assert "PORT=8080" in redacted_art.content
        assert "redacted" in redacted_art.filename

        # Explicit raw mode (include_raw=True) restores the original unredacted file
        raw_art = ObjectRecoveryEngine.recover_commit_file(
            sample_pipeline_result,
            commit_hash="deadbeef1234",
            file_path=".env",
            include_raw=True,
        )
        assert raw_art.is_redacted is False
        assert "AKIAIOSFODNN7EXAMPLE" in raw_art.content
        assert "raw" in raw_art.filename

    def test_recover_blob_redacted_vs_raw(self, sample_pipeline_result: PipelineResult):
        red_blob = ObjectRecoveryEngine.recover_blob(
            sample_pipeline_result, "cafebabe1234", include_raw=False
        )
        assert red_blob.is_redacted is True
        assert "1234567890123-abcdef" not in red_blob.content

        raw_blob = ObjectRecoveryEngine.recover_blob(
            sample_pipeline_result, "cafebabe1234", include_raw=True
        )
        assert raw_blob.is_redacted is False
        assert "1234567890123-abcdef" in raw_blob.content

    def test_build_recovery_zip_bundle(self, sample_pipeline_result: PipelineResult):
        zip_bytes = ObjectRecoveryEngine.build_recovery_zip_bundle(
            sample_pipeline_result, include_raw=False
        )
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            names = zf.namelist()
            assert "reports/gitghost_audit_report.md" in names
            assert "reports/gitghost_audit_report.json" in names
            assert "reports/gitghost_audit_report.sarif" in names
            assert any(n.startswith("commits/") for n in names)
            assert any(n.startswith("recovered_files/") for n in names)
            assert any(n.startswith("recovered_blobs/") for n in names)

            for name in names:
                text = zf.read(name).decode("utf-8")
                assert "AKIAIOSFODNN7EXAMPLE" not in text
