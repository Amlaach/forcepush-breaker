"""
Unit and integration tests for multi-platform remote forensics (GitLab & Bitbucket),
in-memory token resolution, and token sanitization.
"""

from pathlib import Path
import pytest
from gitghost.github_remote import (
    ParsedRemoteTarget,
    parse_remote_url,
    parse_gitlab_url,
    parse_bitbucket_url,
    resolve_system_gitlab_token,
    resolve_system_bitbucket_token,
    sanitize_token_in_text,
    GitLabAPIForensicsClient,
    BitbucketAPIForensicsClient,
)

def test_parsed_remote_target_properties():
    gh = parse_remote_url("https://github.com/amlaach/unforce")
    assert gh is not None
    assert gh.platform == "github"
    assert gh.owner == "amlaach"
    assert gh.repo == "unforce"
    assert gh.full_name == "amlaach/unforce"

    gl = parse_remote_url("https://gitlab.com/gitlab-org/gitlab-runner.git")
    assert gl is not None
    assert gl.platform == "gitlab"
    assert gl.owner == "gitlab-org"
    assert gl.repo == "gitlab-runner"
    assert gl.full_name == "gitlab-org/gitlab-runner"
    assert gl.api_repo_url.startswith("https://gitlab.com/api/v4/projects/")

    bb = parse_remote_url("https://bitbucket.org/atlassian/jira-subtask.git")
    assert bb is not None
    assert bb.platform == "bitbucket"
    assert bb.owner == "atlassian"
    assert bb.repo == "jira-subtask"
    assert bb.full_name == "atlassian/jira-subtask"

def test_local_path_not_treated_as_remote():
    assert parse_remote_url("C:\\Users\\dev\\my-repo") is None
    assert parse_remote_url("/home/user/project") is None
    assert parse_remote_url("./relative/folder") is None

def test_sanitize_token_in_text_all_platforms():
    token = "glpat-Secret123456789"
    text = f"Connecting with PRIVATE-TOKEN: {token} to https://gitlab.com/group/repo"
    sanitized = sanitize_token_in_text(text, token)
    assert token not in sanitized
    assert "[REDACTED_TOKEN]" in sanitized

    bb_token = "bb_sec_token_999"
    bb_text = f"Auth failed for https://user:{bb_token}@bitbucket.org/ws/repo"
    bb_clean = sanitize_token_in_text(bb_text, bb_token)
    assert bb_token not in bb_clean
