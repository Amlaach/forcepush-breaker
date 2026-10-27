"""
Unit tests for Cloud Garbage Collection diagnostics (GC_PURGED_REMOTE)
when candidate before_sha returns HTTP 404 from remote API.
"""

from unittest.mock import MagicMock, patch
import urllib.error
import pytest
from gitghost.github_remote import (
    ParsedRemoteTarget,
    HistoryOverwriteEvent,
    GitHubAPIForensicsClient,
    GitLabAPIForensicsClient,
    BitbucketAPIForensicsClient,
)

def test_gc_purged_remote_detection_on_http_404():
    target = ParsedRemoteTarget(
        owner="owner",
        repo="repo",
        clone_url="https://github.com/owner/repo.git",
        api_repo_url="https://api.github.com/repos/owner/repo",
        original_input="https://github.com/owner/repo",
    )
    client = GitHubAPIForensicsClient()

    with patch("urllib.request.urlopen") as mock_url:
        mock_url.side_effect = urllib.error.HTTPError(
            url="https://api.github.com/repos/owner/repo/commits/deadbeef01",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )
        commit, is_404 = client.fetch_commit_or_check_gc(target, "deadbeef01")
        assert commit is None
        assert is_404 is True

def test_gitlab_client_gc_detection():
    target = ParsedRemoteTarget(
        owner="group",
        repo="project",
        clone_url="https://gitlab.com/group/project.git",
        api_repo_url="https://gitlab.com/api/v4/projects/group%2Fproject",
        original_input="https://gitlab.com/group/project",
        platform="gitlab",
        host="gitlab.com",
    )
    client = GitLabAPIForensicsClient()

    with patch("urllib.request.urlopen") as mock_url:
        mock_url.side_effect = urllib.error.HTTPError(
            url="https://gitlab.com/api/v4/projects/group%2Fproject/repository/commits/1234567890",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )
        commit, is_404 = client.fetch_commit_or_check_gc(target, "1234567890")
        assert commit is None
        assert is_404 is True
