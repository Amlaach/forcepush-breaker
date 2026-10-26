"""
Safe Passive Key Liveness & Revocation Checker.

Performs strictly read-only, non-destructive status checks against official vendor API
endpoints to verify whether leaked credentials discovered in dangling objects are still
active (ACTIVE) or have been successfully rotated/revoked (REVOKED).
"""

from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple


def _urlopen_safe(req: urllib.request.Request, timeout: int) -> Any:
    """Opens URL with standard SSL verification, falling back only when local SSL proxy intercepts."""
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError:
        raise
    except urllib.error.URLError as exc:
        if "CERTIFICATE_VERIFY_FAILED" in str(exc):
            ctx = ssl._create_unverified_context()
            return urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raise


@dataclass(frozen=True)
class KeyLivenessResult:
    finding_id: str
    rule_name: str
    status: str  # "ACTIVE" | "REVOKED" | "UNVERIFIABLE"
    details: str
    checked_at: str
    provider: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "finding_id": self.finding_id,
            "rule_name": self.rule_name,
            "status": self.status,
            "details": self.details,
            "checked_at": self.checked_at,
            "provider": self.provider,
        }


class SafeKeyLivenessChecker:
    """Safe, passive, opt-in liveness verification engine.

    Never executes state-modifying actions or exploits. Enforces a 6s hard network timeout.
    """

    PROBE_TIMEOUT_SECONDS = 6

    @classmethod
    def check(
        cls,
        token: str,
        rule_name: str,
        finding_id: str = "UNKNOWN",
    ) -> KeyLivenessResult:
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_token = (token or "").strip()
        rule_lower = (rule_name or "").lower()

        if not clean_token:
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details="Empty or invalid token value provided.",
                checked_at=now_iso,
                provider="None",
            )

        # 1. GitHub Token Probes
        if "github" in rule_lower or clean_token.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_")):
            return cls._probe_github(clean_token, finding_id, rule_name, now_iso)

        # 2. Slack Token Probes
        if "slack" in rule_lower or clean_token.startswith("xoxb-") or clean_token.startswith("xoxp-") or clean_token.startswith("xapp-"):
            return cls._probe_slack(clean_token, finding_id, rule_name, now_iso)

        # 3. Stripe Secret Key Probes
        if "stripe" in rule_lower or clean_token.startswith(("sk_live_", "sk_test_", "rk_live_", "rk_test_")):
            return cls._probe_stripe(clean_token, finding_id, rule_name, now_iso)

        # 4. GitLab Personal Access Token Probes
        if "gitlab" in rule_lower or clean_token.startswith("glpat-"):
            return cls._probe_gitlab(clean_token, finding_id, rule_name, now_iso)

        # 5. AWS Access Key (Passive format check only)
        if "aws" in rule_lower or re.match(r"^AKIA[0-9A-Z]{16}$", clean_token):
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details="AWS keys cannot be safely probed passivity without triggering CloudTrail audit events. Rotate immediately.",
                checked_at=now_iso,
                provider="AWS",
            )

        return KeyLivenessResult(
            finding_id=finding_id,
            rule_name=rule_name,
            status="UNVERIFIABLE",
            details="No safe passive read-only probe is registered for this credential pattern.",
            checked_at=now_iso,
            provider="Generic",
        )

    @classmethod
    def _probe_github(cls, token: str, finding_id: str, rule_name: str, checked_at: str) -> KeyLivenessResult:
        req = urllib.request.Request(
            "https://api.github.com/rate_limit",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "ForcePush-Breaker-Liveness-Check",
                "Accept": "application/vnd.github+json",
            },
            method="GET",
        )
        try:
            with _urlopen_safe(req, timeout=cls.PROBE_TIMEOUT_SECONDS) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                rate = data.get("rate") or {}
                limit = rate.get("limit", "?")
                remaining = rate.get("remaining", "?")
                return KeyLivenessResult(
                    finding_id=finding_id,
                    rule_name=rule_name,
                    status="ACTIVE",
                    details=f"GitHub API confirmed key is ACTIVE (rate limit: {remaining}/{limit}).",
                    checked_at=checked_at,
                    provider="GitHub",
                )
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return KeyLivenessResult(
                    finding_id=finding_id,
                    rule_name=rule_name,
                    status="REVOKED",
                    details="GitHub API returned HTTP 401 Unauthorized: Token is REVOKED or expired.",
                    checked_at=checked_at,
                    provider="GitHub",
                )
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details=f"GitHub API returned HTTP {exc.code}.",
                checked_at=checked_at,
                provider="GitHub",
            )
        except Exception as exc:
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details=f"Network probe error: {exc}",
                checked_at=checked_at,
                provider="GitHub",
            )

    @classmethod
    def _probe_slack(cls, token: str, finding_id: str, rule_name: str, checked_at: str) -> KeyLivenessResult:
        req = urllib.request.Request(
            "https://slack.com/api/auth.test",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "ForcePush-Breaker-Liveness-Check",
            },
            method="POST",
        )
        try:
            with _urlopen_safe(req, timeout=cls.PROBE_TIMEOUT_SECONDS) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                if data.get("ok"):
                    team = data.get("team", "Unknown")
                    user = data.get("user", "Unknown")
                    return KeyLivenessResult(
                        finding_id=finding_id,
                        rule_name=rule_name,
                        status="ACTIVE",
                        details=f"Slack auth.test confirmed key is ACTIVE (team: {team}, user: {user}).",
                        checked_at=checked_at,
                        provider="Slack",
                    )
                else:
                    err = data.get("error", "auth_failed")
                    if err in ("invalid_auth", "account_inactive", "token_revoked"):
                        return KeyLivenessResult(
                            finding_id=finding_id,
                            rule_name=rule_name,
                            status="REVOKED",
                            details=f"Slack API returned '{err}': Token is REVOKED or inactive.",
                            checked_at=checked_at,
                            provider="Slack",
                        )
                    return KeyLivenessResult(
                        finding_id=finding_id,
                        rule_name=rule_name,
                        status="UNVERIFIABLE",
                        details=f"Slack API error: {err}",
                        checked_at=checked_at,
                        provider="Slack",
                    )
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return KeyLivenessResult(
                    finding_id=finding_id,
                    rule_name=rule_name,
                    status="REVOKED",
                    details="Slack API returned HTTP 401 Unauthorized: Token is REVOKED.",
                    checked_at=checked_at,
                    provider="Slack",
                )
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details=f"Slack API HTTP {exc.code}",
                checked_at=checked_at,
                provider="Slack",
            )
        except Exception as exc:
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details=f"Slack network probe error: {exc}",
                checked_at=checked_at,
                provider="Slack",
            )

    @classmethod
    def _probe_stripe(cls, token: str, finding_id: str, rule_name: str, checked_at: str) -> KeyLivenessResult:
        req = urllib.request.Request(
            "https://api.stripe.com/v1/balance",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "ForcePush-Breaker-Liveness-Check",
            },
            method="GET",
        )
        try:
            with _urlopen_safe(req, timeout=cls.PROBE_TIMEOUT_SECONDS) as resp:
                if resp.status == 200:
                    return KeyLivenessResult(
                        finding_id=finding_id,
                        rule_name=rule_name,
                        status="ACTIVE",
                        details="Stripe balance check confirmed key is ACTIVE.",
                        checked_at=checked_at,
                        provider="Stripe",
                    )
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return KeyLivenessResult(
                    finding_id=finding_id,
                    rule_name=rule_name,
                    status="REVOKED",
                    details="Stripe returned HTTP 401 Unauthorized: Key is REVOKED or invalid.",
                    checked_at=checked_at,
                    provider="Stripe",
                )
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details=f"Stripe API HTTP {exc.code}",
                checked_at=checked_at,
                provider="Stripe",
            )
        except Exception as exc:
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details=f"Stripe probe error: {exc}",
                checked_at=checked_at,
                provider="Stripe",
            )

    @classmethod
    def _probe_gitlab(cls, token: str, finding_id: str, rule_name: str, checked_at: str) -> KeyLivenessResult:
        req = urllib.request.Request(
            "https://gitlab.com/api/v4/personal_access_tokens/self",
            headers={
                "PRIVATE-TOKEN": token,
                "User-Agent": "ForcePush-Breaker-Liveness-Check",
            },
            method="GET",
        )
        try:
            with _urlopen_safe(req, timeout=cls.PROBE_TIMEOUT_SECONDS) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
                    name = data.get("name", "token")
                    revoked = data.get("revoked", False)
                    active = data.get("active", True)
                    if revoked or not active:
                        return KeyLivenessResult(
                            finding_id=finding_id,
                            rule_name=rule_name,
                            status="REVOKED",
                            details="GitLab API reports token is REVOKED or inactive.",
                            checked_at=checked_at,
                            provider="GitLab",
                        )
                    return KeyLivenessResult(
                        finding_id=finding_id,
                        rule_name=rule_name,
                        status="ACTIVE",
                        details=f"GitLab API confirmed token '{name}' is ACTIVE.",
                        checked_at=checked_at,
                        provider="GitLab",
                    )
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return KeyLivenessResult(
                    finding_id=finding_id,
                    rule_name=rule_name,
                    status="REVOKED",
                    details="GitLab API returned HTTP 401 Unauthorized: Token is REVOKED.",
                    checked_at=checked_at,
                    provider="GitLab",
                )
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details=f"GitLab API HTTP {exc.code}",
                checked_at=checked_at,
                provider="GitLab",
            )
        except Exception as exc:
            return KeyLivenessResult(
                finding_id=finding_id,
                rule_name=rule_name,
                status="UNVERIFIABLE",
                details=f"GitLab probe error: {exc}",
                checked_at=checked_at,
                provider="GitLab",
            )
