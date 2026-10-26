"""
Remote GitHub Repository Acquisition & History Overwrite Forensics.

Provides permissive GitHub URL parsing, system credential auto-resolution,
strict token sanitization, GitHub Events/PRs/Forks API querying, SSL proxy
resilience, and smart mirror cloning with resource guards.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from gitghost.git_forensics import DanglingCommit, detect_ai_agent

# Matches https://github.com/owner/repo, github.com/owner/repo, and sub-paths (/tree/main, /commits/..., ?tab=...)
_HTTPS_GITHUB_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#].*)?$",
    re.IGNORECASE,
)
_SSH_GITHUB_RE = re.compile(
    r"^git@github\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
_SHORTHAND_GITHUB_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$"
)

_CACHED_SYS_GH_TOKEN: Optional[str] = None
_SYS_GH_TOKEN_PROBED: bool = False


def resolve_system_github_token() -> Optional[str]:
    """Safely probes Git Credential Manager in-memory for an existing github.com token.

    Never writes to disk and never blocks on interactive prompts (`GIT_TERMINAL_PROMPT=0`).
    Allows seamless scanning of private GitHub repositories the user already has access to.
    """
    global _CACHED_SYS_GH_TOKEN, _SYS_GH_TOKEN_PROBED
    env_tok = (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or "").strip()
    if env_tok:
        return env_tok

    if _SYS_GH_TOKEN_PROBED:
        return _CACHED_SYS_GH_TOKEN

    _SYS_GH_TOKEN_PROBED = True
    if not shutil.which("git"):
        return None

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"

    try:
        res = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=3,
            check=False,
        )
        if res.returncode == 0 and res.stdout:
            for line in res.stdout.splitlines():
                if line.startswith("password="):
                    pw = line.split("=", 1)[1].strip()
                    if pw:
                        _CACHED_SYS_GH_TOKEN = pw
                        return pw
    except Exception:
        pass
    return None


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

    @property
    def html_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"


@dataclass
class HistoryOverwriteEvent:
    event_id: str
    event_type: str  # "force_push" | "branch_delete" | "closed_pr_orphan" | "push_before" | "fork_divergence"
    ref: str
    before_sha: str
    after_sha: Optional[str]
    actor: str
    created_at: str
    description: str


@dataclass(frozen=True)
class ForkForensicsTarget:
    owner: str
    repo: str
    clone_url: str
    html_url: str
    default_branch: str = "main"
    pushed_at: str = ""
    stargazers_count: int = 0
    forks_count: int = 0

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass
class RemoteAcquisitionResult:
    target: ParsedGitHubTarget
    local_clone_path: Path
    is_temporary: bool = True
    history_events: List[HistoryOverwriteEvent] = field(default_factory=list)
    discovered_orphan_shas: List[str] = field(default_factory=list)
    api_recovered_commits: List[DanglingCommit] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    discovered_forks: List[ForkForensicsTarget] = field(default_factory=list)


def sanitize_token_in_text(text: str, token: Optional[str] = None) -> str:
    """Strictly strips any GitHub token or Basic/Bearer credentials from logs and error strings."""
    if not text:
        return ""
    sanitized = text
    if token and token.strip():
        clean_tok = token.strip()
        sanitized = sanitized.replace(clean_tok, "[REDACTED_GITHUB_TOKEN]")
        b64_basic = base64.b64encode(f"x-access-token:{clean_tok}".encode("utf-8")).decode("ascii")
        sanitized = sanitized.replace(b64_basic, "[REDACTED_GITHUB_TOKEN]")

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
    """Parses a GitHub HTTPS URL (including /tree/... browser links), SSH URL, or 'owner/repo' shorthand.

    Returns None if the target points to an existing local path or is not a valid GitHub identifier.
    """
    raw = (target or "").strip()
    if not raw or raw in (".", ".."):
        return None

    m = _HTTPS_GITHUB_RE.match(raw) or _SSH_GITHUB_RE.match(raw)
    if m:
        owner, repo = m.group(1), m.group(2)
        if repo.lower().endswith(".git"):
            repo = repo[:-4]
        if owner in ("settings", "orgs", "organizations", "users", "marketplace", "explore", "topics"):
            return None
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
            if repo.lower().endswith(".git"):
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


class GitHubAPIForensicsClient:
    """Queries GitHub REST API for history overwrite events, force-pushes, and orphaned commits.

    Token is held strictly in memory and never emitted in logs, exceptions, or reports.
    """

    DEFAULT_TIMEOUT_SECONDS = 12

    def __init__(self, github_token: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        resolved_token = (github_token or resolve_system_github_token() or "").strip()
        self._token: Optional[str] = resolved_token if resolved_token else None
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"GitHubAPIForensicsClient(authenticated={bool(self._token)}, timeout={self.timeout})"

    def _build_headers(self, accept: str = "application/vnd.github+json") -> Dict[str, str]:
        headers = {
            "Accept": accept,
            "User-Agent": "UnForce-Security-Forensics/1.0.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _get_json(self, url: str) -> Any:
        req = urllib.request.Request(url, headers=self._build_headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.URLError as url_exc:
            # Handle SSL-intercepting proxies (e.g. corporate firewalls / NetFree where NODE_TLS_REJECT_UNAUTHORIZED=0)
