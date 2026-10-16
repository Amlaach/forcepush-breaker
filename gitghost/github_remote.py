"""
Remote GitHub Repository Acquisition & History Overwrite Forensics.

Provides URL parsing, token sanitization, GitHub Events/Commits API querying
for force-push/deleted branch discovery, and smart mirror cloning with resource guards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from gitghost.git_forensics import DanglingCommit

_HTTPS_GITHUB_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
_SSH_GITHUB_RE = re.compile(
    r"^git@github\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$"
)
_SHORTHAND_GITHUB_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$"
)


@dataclass(frozen=True)
class ParsedGitHubTarget:
    owner: str
    repo: str
    clone_url: str
    api_repo_url: str
    original_input: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass
class HistoryOverwriteEvent:
    event_id: str
    event_type: str  # "force_push" | "branch_delete" | "closed_pr_orphan" | "push_before"
    ref: str
    before_sha: str
    after_sha: Optional[str]
    actor: str
    created_at: str
    description: str


@dataclass
class RemoteAcquisitionResult:
    target: ParsedGitHubTarget
    local_clone_path: Path
    is_temporary: bool = True
    history_events: List[HistoryOverwriteEvent] = field(default_factory=list)
    discovered_orphan_shas: List[str] = field(default_factory=list)
    api_recovered_commits: List[DanglingCommit] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)



def sanitize_token_in_text(text: str, token: Optional[str] = None) -> str:
    """Strictly strips any GitHub token or Basic/Bearer credentials from logs and error strings."""
    if not text:
        return ""
    sanitized = text
    if token and token.strip():
        sanitized = sanitized.replace(token.strip(), "[REDACTED_GITHUB_TOKEN]")
    # Also mask any inline https://<token>@github.com or x-access-token:<token>@github.com
    sanitized = re.sub(
        r"(https?://)([^@\s/]+)@github\.com",
        r"\1[REDACTED_GITHUB_TOKEN]@github.com",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)(authorization:\s*(?:bearer|token|basic)\s+)([^\s\"']+)",
        r"\1[REDACTED_GITHUB_TOKEN]",
        sanitized,
    )
    return sanitized


def parse_github_url(target: str) -> Optional[ParsedGitHubTarget]:
    """Parses a GitHub HTTPS URL, SSH URL, or 'owner/repo' shorthand into a structured target.

    Returns None if the target points to an existing local path or is not a valid GitHub identifier.
    """
    raw = (target or "").strip()
    if not raw or raw in (".", ".."):
        return None

    m = _HTTPS_GITHUB_RE.match(raw) or _SSH_GITHUB_RE.match(raw)
    if m:
        owner, repo = m.group(1), m.group(2)
        if repo.endswith(".git"):
            repo = repo[:-4]
        return ParsedGitHubTarget(
            owner=owner,
            repo=repo,
            clone_url=f"https://github.com/{owner}/{repo}.git",
            api_repo_url=f"https://api.github.com/repos/{owner}/{repo}",
            original_input=raw,
        )

    # Check if it's an existing local filesystem path before treating as owner/repo shorthand
    try:
        local_candidate = Path(raw)
        if local_candidate.exists() or raw.startswith(("/", "\\", "./", ".\\", "../", "..\\")) or ":" in raw:
            return None
    except Exception:
        pass

    m_short = _SHORTHAND_GITHUB_RE.match(raw)
    if m_short:
        owner, repo = m_short.group(1), m_short.group(2)
        if owner not in (".", "..") and repo not in (".", ".."):
            if repo.endswith(".git"):
                repo = repo[:-4]
            return ParsedGitHubTarget(
                owner=owner,
                repo=repo,
                clone_url=f"https://github.com/{owner}/{repo}.git",
                api_repo_url=f"https://api.github.com/repos/{owner}/{repo}",
                original_input=raw,
            )

    return None


def is_github_target(target: str) -> bool:
    """Returns True if the target string represents a remote GitHub repository."""
    return parse_github_url(target) is not None
