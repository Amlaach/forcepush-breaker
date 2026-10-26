"""
Unit tests for SecretRedactor and Shannon Entropy detection.
"""

import pytest
from gitghost.redactor import SecretRedactor, shannon_entropy, mask_credential


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_repeated_char(self):
        assert shannon_entropy("aaaaaaaaaaaa") == 0.0

    def test_low_entropy_english_word(self):
        entropy = shannon_entropy("hello world")
        assert entropy < 3.5

    def test_high_entropy_random_tokens(self):
        entropy = shannon_entropy("c2VjdXJlX3Rva2VuX3JhbmRvbV85ODcyMzkxMzg=")
        assert entropy > 4.2


class TestMaskCredential:
    def test_short_string(self):
        assert mask_credential("secret") == "******"

    def test_preserve_edges(self):
        masked = mask_credential("AKIAIOSFODNN7EXAMPLE", 4, 4)
        assert masked.startswith("AKIA")
        assert masked.endswith("MPLE")
        assert "IOSFODNN7EXA" not in masked
        assert "*" in masked


class TestSecretRedactor:
    @pytest.fixture
    def redactor(self):
        return SecretRedactor()

    def test_aws_access_key_detection(self, redactor):
        raw_diff = "+ AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        result = redactor.scan_and_redact(raw_diff, file_path="config.py")

        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.rule_name == "AWS Access Key ID"
        assert finding.severity_estimate == "Critical"
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert "AKIA" in result.redacted_text
        assert "****" in result.redacted_text

    def test_database_url_redaction(self, redactor):
        raw_diff = 'DATABASE_URL="postgres://admin:SuperSecretPass123!@db.internal:5432/core"'
        result = redactor.scan_and_redact(raw_diff, file_path=".env")

        assert len(result.findings) >= 1
        finding = next(f for f in result.findings if "Database" in f.rule_name)
        assert finding.severity_estimate == "Critical"
        assert "SuperSecretPass123!" not in result.redacted_text
        assert "[REDACTED_DB_PASSWORD]" in result.redacted_text
        assert "postgres://admin:[REDACTED_DB_PASSWORD]@db.internal:5432/core" in result.redacted_text

    def test_private_key_redaction(self, redactor):
        raw_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0YqL9M1V4r8N+XYZABC1234567890abcdef\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        result = redactor.scan_and_redact(raw_key, file_path="id_rsa")

        assert len(result.findings) >= 1
        finding = next(f for f in result.findings if "Private Key" in f.rule_name)
        assert finding.severity_estimate == "Critical"
        assert "MIIEowIBAAKCAQEA0YqL9M1V4r8N+XYZABC1234567890abcdef" not in result.redacted_text
        assert "[REDACTED_PRIVATE_KEY_BLOCK]" in result.redacted_text

    def test_slack_token_detection(self, redactor):
        raw_diff = "SLACK_TOKEN = 'xoxb-123456789012-1234567890123-abcdef1234567890abcdef12'\n"
        result = redactor.scan_and_redact(raw_diff)

        assert len(result.findings) >= 1
        finding = next(f for f in result.findings if "Slack" in f.rule_name)
        assert finding.severity_estimate == "High"
        assert "1234567890123-abcdef" not in result.redacted_text

    def test_false_positive_filtering(self, redactor):
        raw_diff = "API_KEY = 'your_api_key_here_placeholder'\n"
        result = redactor.scan_and_redact(raw_diff)
        assert len(result.findings) == 0

    def test_raw_secret_never_exposed(self, redactor):
        raw_secret = "ghp_AbCdEf1234567890AbCdEf1234567890AbCd"
        input_text = f"const githubToken = '{raw_secret}';\n"
        result = redactor.scan_and_redact(input_text)

        assert raw_secret not in result.redacted_text
        for finding in result.findings:
            assert raw_secret not in finding.masked_value
            assert raw_secret not in finding.context_line

    def test_multiple_secrets_on_same_line(self, redactor):
        raw_aws = "AKIAIOSFODNN7EXAMPLE"
        raw_slack = "xoxb-123456789012-1234567890123-abcdef1234567890abcdef12"
        line = f"export AWS_KEY={raw_aws} SLACK_TOKEN={raw_slack}\n"

        result = redactor.scan_and_redact(line, file_path="deploy.sh")
        assert len(result.findings) >= 2

        # Verify that NEITHER raw secret appears in the redacted text
        assert raw_aws not in result.redacted_text
        assert raw_slack not in result.redacted_text

        # Verify that for EVERY finding on this line, ALL raw secrets are masked in context_line
        for finding in result.findings:
            assert raw_aws not in finding.context_line
            assert raw_slack not in finding.context_line
            assert finding.context_line.count("AKIA") > 0 or "REDACTED" in finding.context_line
            assert "****" in finding.context_line or "REDACTED" in finding.context_line

    def test_private_key_real_shannon_entropy(self, redactor):
        raw_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0YqL9M1V4r8N+XYZABC1234567890abcdef\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        result = redactor.scan_and_redact(raw_key, file_path="id_rsa")
        pk_finding = next(f for f in result.findings if "Private Key" in f.rule_name)

        # Entropy should be calculated accurately from data, not hardcoded to fixed 5.0
        assert pk_finding.entropy != 5.0
        assert pk_finding.entropy > 4.5

    def test_multiline_redacted_diff_hunk_generation(self, redactor):
        raw_secret = "ghp_AbCdEf1234567890AbCdEf1234567890AbCd"
        diff_text = (
            "@@ -10,4 +10,5 @@\n"
            " import os\n"
            "-TOKEN = None\n"
            f"+TOKEN = '{raw_secret}'\n"
            " def connect():\n"
            "     return True\n"
        )
        result = redactor.scan_and_redact(diff_text, file_path="client.py")
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert f.diff_hunk != ""
        assert "@@ -10,4 +10,5 @@" in f.diff_hunk
        assert "-TOKEN = None" in f.diff_hunk
        assert "def connect():" in f.diff_hunk
        assert raw_secret not in f.diff_hunk

