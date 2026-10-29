"""
Unit tests for Remote GitHub URL parsing, token sanitization, API forensics, and SmartGitCloner.
"""

from pathlib import Path
import pytest
from gitghost.github_remote import (
    GitHubAPIForensicsClient,
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


class TestGitHubAPIForensicsClient:
    def test_discover_history_overwrite_events_parses_force_push_and_pr(self, monkeypatch):
        target = parse_github_url("https://github.com/acme/payments")
        assert target is not None
        client = GitHubAPIForensicsClient(github_token="ghp_SuperSecretTokenForTestOnly999")
        assert "ghp_SuperSecretTokenForTestOnly999" not in repr(client)

        fake_events = [
            {
                "id": "1001",
                "type": "PushEvent",
                "actor": {"login": "dev-alice"},
                "created_at": "2026-10-15T10:00:00Z",
                "payload": {
                    "ref": "refs/heads/main",
                    "before": "deadbeef11111111111111111111111111111111",
                    "head": "cafebabe22222222222222222222222222222222",
                    "forced": True,
                    "size": 0,
                },
            },
            {
                "id": "1002",
                "type": "DeleteEvent",
                "actor": {"login": "dev-bob"},
                "created_at": "2026-10-15T11:00:00Z",
                "payload": {"ref_type": "branch", "ref": "feature/temp-secrets"},
            },
        ]
        fake_pulls = [
            {
                "number": 42,
                "title": "WIP: add database config",
                "merged_at": None,
                "closed_at": "2026-10-15T12:00:00Z",
                "user": {"login": "dev-charlie"},
                "head": {
                    "sha": "1234567890abcdef1234567890abcdef12345678",
                    "ref": "wip-db",
                },
            }
        ]

        def mock_get_json(url: str):
            if "/events" in url:
                return fake_events
            if "/pulls" in url:
                return fake_pulls
            return []

        monkeypatch.setattr(client, "_get_json", mock_get_json)
        events, orphan_shas, warnings = client.discover_history_overwrite_events(target)

        assert len(warnings) == 0
        assert len(events) == 3
        assert events[0].event_type == "force_push"
        assert events[0].before_sha == "deadbeef11111111111111111111111111111111"
        assert events[1].event_type == "branch_delete"
        assert events[2].event_type == "closed_pr_orphan"
        assert "deadbeef11111111111111111111111111111111" in orphan_shas
        assert "1234567890abcdef1234567890abcdef12345678" in orphan_shas

    def test_fetch_orphan_commit_via_api_reconstructs_diff(self, monkeypatch):
        target = parse_github_url("https://github.com/acme/payments")
        assert target is not None
        client = GitHubAPIForensicsClient()

        fake_commit = {
            "sha": "deadbeef11111111111111111111111111111111",
            "commit": {
                "author": {
                    "name": "Alice Dev",
                    "email": "alice@acme.io",
                    "date": "2026-10-15T09:30:00Z",
                },
                "message": "chore: add temporary prod keys",
            },
            "parents": [{"sha": "0000111122223333444455556666777788889999"}],
            "files": [
                {
                    "filename": ".env.prod",
                    "patch": "@@ -0,0 +1,2 @@\n+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
                }
            ],
        }

        monkeypatch.setattr(client, "_get_json", lambda url: fake_commit)
        commit = client.fetch_orphan_commit_via_api(
            target, "deadbeef11111111111111111111111111111111"
        )
        assert commit is not None
        assert commit.commit_hash == "deadbeef11111111111111111111111111111111"
        assert commit.author == "Alice Dev <alice@acme.io>"
        assert ".env.prod" in commit.changed_files
        assert "diff --git a/.env.prod b/.env.prod" in commit.diff_content
        assert "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" in commit.diff_content


class TestSmartGitCloner:
    def test_mirror_clone_and_guaranteed_cleanup(self, tmp_path: Path):
        import subprocess
        from gitghost.github_remote import SmartGitCloner

        upstream = tmp_path / "upstream_repo"
        upstream.mkdir()
        subprocess.run(["git", "init"], cwd=str(upstream), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(upstream), check=True)
        subprocess.run(["git", "config", "user.email", "tester@acme.io"], cwd=str(upstream), check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(upstream), check=True)
        (upstream / "app.py").write_text("print('ok')\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=str(upstream), check=True)
        subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(upstream), check=True)

        target = parse_github_url("https://github.com/acme/upstream_repo")
        assert target is not None

        acq = SmartGitCloner.acquire(
            target=target,
            clone_source_override=str(upstream),
        )
        try:
            assert acq.local_clone_path.exists()
            assert (acq.local_clone_path / "HEAD").exists()
        finally:
            SmartGitCloner.cleanup_workspace(acq.local_clone_path)
            assert not acq.local_clone_path.exists()

    def test_failed_clone_cleans_up_and_scrubs_token(self, tmp_path: Path):
        from gitghost.github_remote import SmartGitCloner

        target = parse_github_url("https://github.com/acme/nonexistent")
        assert target is not None
        fake_token = "ghp_VerySensitiveToken9876543210ABCDEFG"

        with pytest.raises(RuntimeError) as exc_info:
            SmartGitCloner.acquire(
                target=target,
                github_token=fake_token,
                clone_source_override=str(tmp_path / "does_not_exist_repo.git"),
            )
        assert fake_token not in str(exc_info.value)

    def test_query_public_forks(self, monkeypatch):
        from gitghost.github_remote import ForkForensicsTarget

        target = parse_github_url("https://github.com/acme/vault")
        assert target is not None
        client = GitHubAPIForensicsClient()

        fake_forks_payload = [
            {
                "name": "vault",
                "owner": {"login": "attacker-org"},
                "clone_url": "https://github.com/attacker-org/vault.git",
                "html_url": "https://github.com/attacker-org/vault",
                "default_branch": "main",
                "pushed_at": "2026-10-15T15:30:00Z",
                "stargazers_count": 5,
                "forks_count": 1,
            }
        ]
        monkeypatch.setattr(client, "_get_json", lambda url: fake_forks_payload)
        forks = client.query_public_forks(target)
        assert len(forks) == 1
        assert forks[0].owner == "attacker-org"
        assert forks[0].full_name == "attacker-org/vault"
        assert forks[0].stargazers_count == 5

    def test_compare_fork_with_parent_and_event_generation(self, monkeypatch):
        from gitghost.github_remote import ForkForensicsTarget

        target = parse_github_url("https://github.com/acme/vault")
        assert target is not None
        client = GitHubAPIForensicsClient()

        fake_fork = ForkForensicsTarget(
            owner="developer-bob",
            repo="vault",
            clone_url="https://github.com/developer-bob/vault.git",
            html_url="https://github.com/developer-bob/vault",
            default_branch="main",
            pushed_at="2026-10-15T16:00:00Z",
        )

        def mock_get(url: str):
            if "/events" in url:
                return []
            if "/pulls" in url:
                return []
            if "/forks" in url:
                return [
                    {
                        "name": "vault",
                        "owner": {"login": "developer-bob"},
                        "clone_url": "https://github.com/developer-bob/vault.git",
                        "html_url": "https://github.com/developer-bob/vault",
                        "default_branch": "main",
                        "pushed_at": "2026-10-15T16:00:00Z",
                    }
                ]
            if "/compare" in url:
                return {
                    "commits": [
                        {
                            "sha": "aaaabbbbcccc1111222233334444555566667777",
                            "author": {"login": "developer-bob"},
                            "commit": {"message": "feat: retain leaked key locally"},
                        }
                    ]
                }
            return {}

        monkeypatch.setattr(client, "_get_json", mock_get)
        events, candidates, warnings = client.discover_history_overwrite_events(target, scan_forks=True)

        assert len(events) == 1
        assert events[0].event_type == "fork_divergence"
        assert events[0].before_sha == "aaaabbbbcccc1111222233334444555566667777"
        assert "aaaabbbbcccc1111222233334444555566667777" in candidates
        assert "developer-bob" in events[0].actor


