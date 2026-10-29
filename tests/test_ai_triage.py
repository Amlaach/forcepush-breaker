import os
import unittest
from unittest.mock import patch, MagicMock

from gitghost.ai_triage import AITriage, AITriageResult
from gitghost.pipeline import run_scan_pipeline
from gitghost.ui_server import ScanJobManager


class TestAITriage(unittest.TestCase):
    def test_provider_prefix_auto_resolution(self):
        t_anthropic = AITriage(api_key="sk-ant-api03-abcdef123456789")
        self.assertEqual(t_anthropic._resolve_provider(), "anthropic")

        t_gemini = AITriage(api_key="AIzaSyB1234567890abcdef")
        self.assertEqual(t_gemini._resolve_provider(), "gemini")

        t_openai = AITriage(api_key="sk-proj-1234567890abcdef")
        self.assertEqual(t_openai._resolve_provider(), "openai")

    def test_explicit_provider_overrides_prefix(self):
        t = AITriage(provider="ollama", api_key="sk-ant-somekey")
        self.assertEqual(t._resolve_provider(), "ollama")

    def test_token_scrubbing_on_call_exception(self):
        leaked_secret_key = "sk-ant-api03-super-secret-triage-key"
        triage = AITriage(api_key=leaked_secret_key)

        with patch.object(triage, "_call_anthropic", side_effect=RuntimeError(f"HTTP 401: Unauthorized with key {leaked_secret_key}")):
            result = triage.triage_finding(
                finding_rule="Generic Secret",
                masked_snippet="AKIA****",
                context_line="export AWS_KEY=AKIA****",
                commit_message="Test commit",
                file_path="config.py",
            )

            self.assertIsInstance(result, AITriageResult)
            # Ensure the raw secret key was scrubbed from technical_explanation
            self.assertNotIn(leaked_secret_key, result.technical_explanation)
            self.assertIn("[REDACTED_API_KEY]", result.technical_explanation)

    def test_heuristic_fallback(self):
        triage = AITriage(provider="heuristic")
        res = triage.triage_finding(
            finding_rule="AWS Access Key",
            masked_snippet="AKIA****",
            context_line="export AWS_SECRET=AKIA****",
            commit_message="WIP: mock aws creds",
            file_path="tests/test_auth.py",
        )
        self.assertTrue(res.is_false_positive)
        self.assertIn("test", res.technical_explanation.lower())

    def test_scan_job_manager_ephemeral_ai_key(self):
        secret_ai_key = "AIzaSyTestEphemeralKey12345"
        job = ScanJobManager.start_job(
            repo_target=".",
            ai_provider="none",
            ai_api_key=secret_ai_key,
        )
        self.assertIsNotNone(job.job_id)
        # ScanJob object itself must never have an ai_api_key attribute
        self.assertFalse(hasattr(job, "ai_api_key"))


if __name__ == "__main__":
    unittest.main()
