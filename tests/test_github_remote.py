"""
Unit tests for Remote GitHub URL parsing, token sanitization, API forensics, and SmartGitCloner.
"""

from pathlib import Path
import pytest
from gitghost.github_remote import (
    is_github_target,
    parse_github_url,
    sanitize_token_in_text,
)


class TestGitHubUrlParser:
    def test_parse_https_urls(self):
        parsed = parse_github_url("https://github.com/octocat/Hello-World")
        assert parsed is not None
        assert parsed.owner == "octocat"
        assert parsed.repo == "Hello-World"
        assert parsed.full_name == "octocat/Hello-World"
        assert parsed.clone_url == "https://github.com/octocat/Hello-World.git"
        assert parsed.api_repo_url == "https://api.github.com/repos/octocat/Hello-World"

    def test_parse_https_url_with_git_suffix_and_trailing_slash(self):
        parsed = parse_github_url("https://www.github.com/org-name/sec-repo.git/")
        assert parsed is not None
        assert parsed.owner == "org-name"
        assert parsed.repo == "sec-repo"

    def test_parse_ssh_url(self):
        parsed = parse_github_url("git@github.com:security-team/vault.git")
        assert parsed is not None
        assert parsed.owner == "security-team"
        assert parsed.repo == "vault"
        assert parsed.clone_url == "https://github.com/security-team/vault.git"

    def test_parse_owner_repo_shorthand(self):
        parsed = parse_github_url("torvalds/linux")
        assert parsed is not None
        assert parsed.owner == "torvalds"
        assert parsed.repo == "linux"
        assert is_github_target("torvalds/linux") is True

    def test_rejects_local_filesystem_paths(self, tmp_path: Path):
        assert parse_github_url(".") is None
        assert parse_github_url("..") is None
        assert parse_github_url("./local/folder") is None
        assert parse_github_url("C:\\Users\\Project\\Repo") is None
        assert parse_github_url(str(tmp_path)) is None
        assert is_github_target(str(tmp_path)) is False

    def test_sanitize_token_in_text_never_leaks_token(self):
        secret_tok = "ghp_SecretTokenValue1234567890ABCDEFGHIJ"
        raw_err = (
            f"fatal: unable to access 'https://x-access-token:{secret_tok}@github.com/org/repo.git/': "
            f"Authorization: Bearer {secret_tok} failed"
        )
        cleaned = sanitize_token_in_text(raw_err, secret_tok)
        assert secret_tok not in cleaned
        assert "[REDACTED_GITHUB_TOKEN]" in cleaned
