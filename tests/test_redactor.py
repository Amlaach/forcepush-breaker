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
