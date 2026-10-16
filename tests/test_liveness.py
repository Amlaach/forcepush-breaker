"""
Unit tests for SafeKeyLivenessChecker passive read-only vendor probes.
"""

import urllib.error
from unittest.mock import MagicMock
import pytest

from gitghost.liveness import KeyLivenessResult, SafeKeyLivenessChecker


class TestSafeKeyLivenessChecker:
    def test_empty_or_blank_token(self):
        res = SafeKeyLivenessChecker.check("", "generic")
        assert res.status == "UNVERIFIABLE"
        assert res.provider == "None"

    def test_aws_key_passive_guard(self):
        res = SafeKeyLivenessChecker.check("AKIAIOSFODNN7EXAMPLE", "AWS Access Key")
        assert res.status == "UNVERIFIABLE"
        assert res.provider == "AWS"
        assert "Rotate immediately" in res.details

    def test_github_token_active(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"rate": {"limit": 5000, "remaining": 4990}}'
        mock_resp.__enter__.return_value = mock_resp

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: mock_resp)

        res = SafeKeyLivenessChecker.check("ghp_ValidTokenTest1234567890", "GitHub Personal Access Token")
        assert res.status == "ACTIVE"
        assert res.provider == "GitHub"
        assert "4990/5000" in res.details

    def test_github_token_revoked_401(self, monkeypatch):
        def _mock_urlopen(req, timeout):
            raise urllib.error.HTTPError(
                url="https://api.github.com/rate_limit",
                code=401,
                msg="Unauthorized",
                hdrs={},
                fp=None,
            )

        monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen)

        res = SafeKeyLivenessChecker.check("ghp_RevokedTokenTest999999", "GitHub Personal Access Token")
        assert res.status == "REVOKED"
        assert res.provider == "GitHub"
        assert "REVOKED or expired" in res.details

    def test_slack_token_active(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok": true, "team": "Acme Corp", "user": "U12345"}'
        mock_resp.__enter__.return_value = mock_resp

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: mock_resp)

        res = SafeKeyLivenessChecker.check("xoxb-1234-5678-abcdef", "Slack Bot Token")
        assert res.status == "ACTIVE"
        assert res.provider == "Slack"
        assert "Acme Corp" in res.details

    def test_slack_token_revoked(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok": false, "error": "invalid_auth"}'
        mock_resp.__enter__.return_value = mock_resp

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: mock_resp)

        res = SafeKeyLivenessChecker.check("xoxb-0000-0000-deadbeef", "Slack Bot Token")
        assert res.status == "REVOKED"
        assert res.provider == "Slack"
        assert "invalid_auth" in res.details

    def test_stripe_key_active_and_revoked(self, monkeypatch):
        # 1. Active (HTTP 200)
        mock_200 = MagicMock()
        mock_200.status = 200
        mock_200.__enter__.return_value = mock_200
        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: mock_200)

        res_active = SafeKeyLivenessChecker.check("sk_live_StripeKeyActive12345", "Stripe Secret Key")
        assert res_active.status == "ACTIVE"
        assert res_active.provider == "Stripe"

        # 2. Revoked (HTTP 401)
        def _mock_401(req, timeout):
            raise urllib.error.HTTPError(
                url="https://api.stripe.com/v1/balance",
                code=401,
                msg="Unauthorized",
                hdrs={},
                fp=None,
            )

        monkeypatch.setattr("urllib.request.urlopen", _mock_401)
        res_revoked = SafeKeyLivenessChecker.check("sk_live_StripeKeyRevoked9999", "Stripe Secret Key")
        assert res_revoked.status == "REVOKED"
        assert res_revoked.provider == "Stripe"

    def test_gitlab_token_active_and_revoked(self, monkeypatch):
        # 1. Active
        mock_active = MagicMock()
        mock_active.status = 200
        mock_active.read.return_value = b'{"name": "deploy-token", "revoked": false, "active": true}'
        mock_active.__enter__.return_value = mock_active
        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: mock_active)

        res_active = SafeKeyLivenessChecker.check("glpat-ActiveToken12345678", "GitLab Personal Token")
        assert res_active.status == "ACTIVE"
        assert res_active.provider == "GitLab"

        # 2. Revoked
        mock_revoked = MagicMock()
        mock_revoked.status = 200
        mock_revoked.read.return_value = b'{"name": "deploy-token", "revoked": true, "active": false}'
        mock_revoked.__enter__.return_value = mock_revoked
        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: mock_revoked)

        res_revoked = SafeKeyLivenessChecker.check("glpat-RevokedToken9876543", "GitLab Personal Token")
        assert res_revoked.status == "REVOKED"
        assert res_revoked.provider == "GitLab"
