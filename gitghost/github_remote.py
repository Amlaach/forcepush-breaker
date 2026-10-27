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
_HTTPS_GITLAB_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?gitlab\.com/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*?)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#].*)?$",
    re.IGNORECASE,
)
_SSH_GITLAB_RE = re.compile(
    r"^git@gitlab\.com:([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*?)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
_HTTPS_BITBUCKET_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?bitbucket\.org/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#].*)?$",
    re.IGNORECASE,
)
_SSH_BITBUCKET_RE = re.compile(
    r"^git@bitbucket\.org:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)

_CACHED_REMOTE_TOKENS: Dict[str, str] = {}
_PROBED_REMOTE_HOSTS: Set[str] = set()


def resolve_system_remote_token(host: str = "github.com") -> Optional[str]:
    """Safely probes Git Credential Manager in-memory for an existing token for the specified host.

    Never writes to disk and never blocks on interactive prompts (`GIT_TERMINAL_PROMPT=0`).
    """
    clean_host = host.lower().strip()
    if "github" in clean_host:
        env_tok = (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or "").strip()
        if env_tok:
            return env_tok
    elif "gitlab" in clean_host:
        env_tok = (os.getenv("GITLAB_TOKEN") or os.getenv("GL_TOKEN") or "").strip()
        if env_tok:
            return env_tok
    elif "bitbucket" in clean_host:
        env_tok = (os.getenv("BITBUCKET_TOKEN") or "").strip()
        if env_tok:
            return env_tok

    if clean_host in _CACHED_REMOTE_TOKENS:
        return _CACHED_REMOTE_TOKENS[clean_host]
    if clean_host in _PROBED_REMOTE_HOSTS:
        return None

    _PROBED_REMOTE_HOSTS.add(clean_host)
    if not shutil.which("git"):
        return None

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"

    CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    flags = CREATE_NO_WINDOW if sys.platform == "win32" else 0

    try:
        res = subprocess.run(
            ["git", "credential", "fill"],
            input=f"protocol=https\nhost={clean_host}\n\n",
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=3,
            check=False,
            creationflags=flags,
        )
        if res.returncode == 0 and res.stdout:
            for line in res.stdout.splitlines():
                if line.startswith("password="):
                    pw = line.split("=", 1)[1].strip()
                    if pw:
                        _CACHED_REMOTE_TOKENS[clean_host] = pw
                        return pw
    except Exception:
        pass
    return None


def resolve_system_github_token() -> Optional[str]:
    return resolve_system_remote_token("github.com")


def resolve_system_gitlab_token() -> Optional[str]:
    return resolve_system_remote_token("gitlab.com")


def resolve_system_bitbucket_token() -> Optional[str]:
    return resolve_system_remote_token("bitbucket.org")


@dataclass(frozen=True)
class ParsedRemoteTarget:
    owner: str
    repo: str
    clone_url: str
    api_repo_url: str
    original_input: str
    platform: str = "github"
    host: str = "github.com"
    project_path: str = ""

    @property
    def full_name(self) -> str:
        return self.project_path or f"{self.owner}/{self.repo}"

    @property
    def html_url(self) -> str:
        if self.platform == "gitlab":
            return f"https://{self.host}/{self.full_name}"
        elif self.platform == "bitbucket":
            return f"https://{self.host}/{self.owner}/{self.repo}"
        return f"https://github.com/{self.owner}/{self.repo}"


@dataclass(frozen=True)
class ParsedGitHubTarget(ParsedRemoteTarget):
    platform: str = "github"
    host: str = "github.com"


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
    target: ParsedRemoteTarget
    local_clone_path: Path
    is_temporary: bool = True
    history_events: List[HistoryOverwriteEvent] = field(default_factory=list)
    discovered_orphan_shas: List[str] = field(default_factory=list)
    api_recovered_commits: List[DanglingCommit] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    discovered_forks: List[ForkForensicsTarget] = field(default_factory=list)


def _fetch_json_resilient(req: urllib.request.Request, timeout: int, token: Optional[str] = None) -> Any:
    """Executes an HTTP JSON request with corporate SSL proxy interception fallback and token safety."""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as http_err:
        if http_err.code == 404:
            raise http_err
        safe_msg = sanitize_token_in_text(str(http_err), token)
        raise RuntimeError(f"API request failed with HTTP {http_err.code}: {safe_msg}") from None
    except urllib.error.URLError as url_exc:
        reason_str = str(getattr(url_exc, "reason", url_exc))
        if "CERTIFICATE_VERIFY_FAILED" in reason_str or os.getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
            try:
                ctx = ssl._create_unverified_context()
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    return json.loads(resp.read().decode("utf-8", errors="replace"))
            except urllib.error.HTTPError as retry_http:
                if retry_http.code == 404:
                    raise retry_http
                safe_msg = sanitize_token_in_text(str(retry_http), token)
                raise RuntimeError(f"API request failed with HTTP {retry_http.code}: {safe_msg}") from None
            except Exception as retry_exc:
                safe_msg = sanitize_token_in_text(str(retry_exc), token)
                raise RuntimeError(f"API request failed: {safe_msg}") from None
        safe_msg = sanitize_token_in_text(str(url_exc), token)
        raise RuntimeError(f"API request failed: {safe_msg}") from None
    except Exception as exc:
        safe_msg = sanitize_token_in_text(str(exc), token)
        raise RuntimeError(f"API request failed: {safe_msg}") from None


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
        r"(https?://)([^@\s/]+)@(github\.com|gitlab\.com|bitbucket\.org)",
        r"\1[REDACTED_TOKEN]@\3",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)(authorization:\s*(?:bearer|token|basic)\s+)([^\s\"']+)",
        r"\1[REDACTED_TOKEN]",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)(private-token:\s*)([^\s\"']+)",
        r"\1[REDACTED_TOKEN]",
        sanitized,
    )
    return sanitized


def parse_bitbucket_url(target: str) -> Optional[ParsedRemoteTarget]:
    raw = (target or "").strip()
    if not raw or "bitbucket.org" not in raw.lower():
        return None
    m = _HTTPS_BITBUCKET_RE.match(raw) or _SSH_BITBUCKET_RE.match(raw)
    if m:
        workspace, repo_slug = m.group(1), m.group(2)
        if repo_slug.lower().endswith(".git"):
            repo_slug = repo_slug[:-4]
        return ParsedRemoteTarget(
            platform="bitbucket",
            host="bitbucket.org",
            owner=workspace,
            repo=repo_slug,
            clone_url=f"https://bitbucket.org/{workspace}/{repo_slug}.git",
            api_repo_url=f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}",
            original_input=raw,
        )
    return None


def parse_gitlab_url(target: str) -> Optional[ParsedRemoteTarget]:
    raw = (target or "").strip()
    if not raw or "gitlab.com" not in raw.lower():
        return None
    m = _HTTPS_GITLAB_RE.match(raw) or _SSH_GITLAB_RE.match(raw)
    if m:
        full_group = m.group(1).strip("/")
        project = m.group(2)
        if project.lower().endswith(".git"):
            project = project[:-4]
        full_project_path = f"{full_group}/{project}".strip("/")
        encoded_path = urllib.parse.quote(full_project_path, safe="")
        return ParsedRemoteTarget(
            platform="gitlab",
            host="gitlab.com",
            owner=full_group,
            repo=project,
            project_path=full_project_path,
            clone_url=f"https://gitlab.com/{full_project_path}.git",
            api_repo_url=f"https://gitlab.com/api/v4/projects/{encoded_path}",
            original_input=raw,
        )
    return None


def parse_remote_url(target: str) -> Optional[ParsedRemoteTarget]:
    """Parses a remote Git target across GitHub, GitLab, or Bitbucket.

    Returns None if the target points to an existing local path or is not a valid remote identifier.
    """
    raw = (target or "").strip()
    if not raw or raw in (".", ".."):
        return None

    try:
        local_candidate = Path(raw)
        if (
            local_candidate.exists()
            or raw.startswith(("/", "\\", "./", ".\\", "../", "..\\"))
            or (len(raw) > 1 and raw[1] == ":")
        ):
            return None
    except Exception:
        pass

    gl = parse_gitlab_url(raw)
    if gl is not None:
        return gl

    bb = parse_bitbucket_url(raw)
    if bb is not None:
        return bb

    m = _HTTPS_GITHUB_RE.match(raw) or _SSH_GITHUB_RE.match(raw)
    if m:
        owner, repo = m.group(1), m.group(2)
        if repo.lower().endswith(".git"):
            repo = repo[:-4]
        if owner in ("settings", "orgs", "organizations", "users", "marketplace", "explore", "topics", "login"):
            return None
        return ParsedGitHubTarget(
            owner=owner,
            repo=repo,
            clone_url=f"https://github.com/{owner}/{repo}.git",
            api_repo_url=f"https://api.github.com/repos/{owner}/{repo}",
            original_input=raw,
        )

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


def parse_github_url(target: str) -> Optional[ParsedRemoteTarget]:
    """Backwards-compatible wrapper that aliases multi-platform parse_remote_url."""
    return parse_remote_url(target)


def is_remote_target(target: str) -> bool:
    """Returns True if the target string represents a remote repository (GitHub, GitLab, Bitbucket)."""
    return parse_remote_url(target) is not None


def is_github_target(target: str) -> bool:
    """Backwards-compatible alias for is_remote_target."""
    return is_remote_target(target)


class GitLabAPIForensicsClient:
    """Queries GitLab REST API v4 for history overwrite events, force-pushes, and deleted branches."""

    DEFAULT_TIMEOUT_SECONDS = 12

    def __init__(self, gitlab_token: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        resolved = (gitlab_token or resolve_system_gitlab_token() or "").strip()
        self._token: Optional[str] = resolved if resolved else None
        self.timeout = timeout

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "UnForce-Security-Forensics/1.0.0",
        }
        if self._token:
            headers["PRIVATE-TOKEN"] = self._token
        return headers

    def discover_history_overwrite_events(
        self,
        target: ParsedRemoteTarget,
        scan_forks: bool = True,
        max_forks: int = 5,
    ) -> Tuple[List[HistoryOverwriteEvent], List[str], List[str]]:
        events: List[HistoryOverwriteEvent] = []
        candidate_shas: List[str] = []
        seen_shas: Set[str] = set()
        warnings: List[str] = []
        zero_sha = "0" * 40

        events_url = f"{target.api_repo_url}/events?action=pushed&per_page=100"
        try:
            req = urllib.request.Request(events_url, headers=self._build_headers(), method="GET")
            raw_events = _fetch_json_resilient(req, timeout=self.timeout, token=self._token)
            if isinstance(raw_events, list):
                for ev in raw_events:
                    if not isinstance(ev, dict):
                        continue
                    ev_id = str(ev.get("id", ""))
                    author = (ev.get("author") or {}).get("username", "unknown")
                    created_at = str(ev.get("created_at") or "")
                    push_data = ev.get("push_data") or {}
                    commit_from = str(push_data.get("commit_from") or "").strip()
                    commit_to = str(push_data.get("commit_to") or "").strip()
                    ref = str(push_data.get("ref") or "main")
                    action = str(push_data.get("action") or "pushed")

                    if commit_from and commit_from != zero_sha:
                        if action == "removed":
                            events.append(
                                HistoryOverwriteEvent(
                                    event_id=f"gl-{ev_id}",
                                    event_type="branch_delete",
                                    ref=f"refs/heads/{ref}",
                                    before_sha=commit_from,
                                    after_sha=None,
                                    actor=author,
                                    created_at=created_at,
                                    description=f"GitLab deleted branch '{ref}' (previous tip {commit_from[:10]})",
                                )
                            )
                            if commit_from not in seen_shas:
                                seen_shas.add(commit_from)
                                candidate_shas.append(commit_from)
                        elif commit_to and commit_from != commit_to:
                            desc = f"GitLab force-push on {ref} (previous tip {commit_from[:10]} replaced by {commit_to[:10]})"
                            events.append(
                                HistoryOverwriteEvent(
                                    event_id=f"gl-{ev_id}",
                                    event_type="force_push",
                                    ref=f"refs/heads/{ref}",
                                    before_sha=commit_from,
                                    after_sha=commit_to,
                                    actor=author,
                                    created_at=created_at,
                                    description=desc,
                                )
                            )
                            if commit_from not in seen_shas:
                                seen_shas.add(commit_from)
                                candidate_shas.append(commit_from)
        except Exception as exc:
            warnings.append(sanitize_token_in_text(str(exc), self._token))

        mrs_url = f"{target.api_repo_url}/merge_requests?state=closed&per_page=30"
        try:
            req = urllib.request.Request(mrs_url, headers=self._build_headers(), method="GET")
            raw_mrs = _fetch_json_resilient(req, timeout=self.timeout, token=self._token)
            if isinstance(raw_mrs, list):
                for mr in raw_mrs:
                    if not isinstance(mr, dict) or mr.get("merged_at"):
                        continue
                    mr_iid = mr.get("iid", "?")
                    sha = str(mr.get("sha") or "").strip()
                    author = (mr.get("author") or {}).get("username", "unknown")
                    closed_at = str(mr.get("closed_at") or mr.get("updated_at") or "")
                    if sha and sha != zero_sha:
                        events.append(
                            HistoryOverwriteEvent(
                                event_id=f"gl-MR-{mr_iid}",
                                event_type="closed_pr_orphan",
                                ref=f"refs/merge-requests/{mr_iid}/head",
                                before_sha=sha,
                                after_sha=None,
                                actor=author,
                                created_at=closed_at,
                                description=f"GitLab closed unmerged MR !{mr_iid} head commit {sha[:10]}",
                            )
                        )
                        if sha not in seen_shas:
                            seen_shas.add(sha)
                            candidate_shas.append(sha)
        except Exception as exc:
            warnings.append(sanitize_token_in_text(str(exc), self._token))

        return events, candidate_shas, warnings

    def fetch_commit_or_check_gc(
        self,
        target: ParsedRemoteTarget,
        commit_sha: str,
        max_text_bytes: int = 10 * 1024 * 1024,
    ) -> Tuple[Optional[DanglingCommit], bool]:
        sha = (commit_sha or "").strip()
        if not sha:
            return None, False

        commit_url = f"{target.api_repo_url}/repository/commits/{sha}"
        diff_url = f"{target.api_repo_url}/repository/commits/{sha}/diff"
        try:
            req = urllib.request.Request(commit_url, headers=self._build_headers(), method="GET")
            data = _fetch_json_resilient(req, timeout=self.timeout, token=self._token)
            if not isinstance(data, dict):
                return None, False

            full_sha = str(data.get("id") or sha)
            author_name = str(data.get("author_name") or "Unknown")
            author_email = str(data.get("author_email") or "")
            author_str = f"{author_name} <{author_email}>" if author_email else author_name
            date_str = str(data.get("authored_date") or data.get("created_at") or "")
            message = str(data.get("message") or "")
            parents = [str(p) for p in (data.get("parent_ids") or []) if p]

            changed_files: List[str] = []
            diff_chunks: List[str] = []
            accumulated_bytes = 0

            try:
                diff_req = urllib.request.Request(diff_url, headers=self._build_headers(), method="GET")
                diff_data = _fetch_json_resilient(diff_req, timeout=self.timeout, token=self._token)
                if isinstance(diff_data, list):
                    for item in diff_data:
                        if not isinstance(item, dict):
                            continue
                        new_path = str(item.get("new_path") or item.get("old_path") or "")
                        if new_path:
                            changed_files.append(new_path)
                        patch = item.get("diff")
                        if isinstance(patch, str) and patch:
                            patch_bytes = len(patch.encode("utf-8", errors="replace"))
                            if accumulated_bytes + patch_bytes <= max_text_bytes:
                                diff_chunks.append(
                                    f"diff --git a/{new_path} b/{new_path}\n--- a/{new_path}\n+++ b/{new_path}\n{patch}"
                                )
                                accumulated_bytes += patch_bytes
            except Exception:
                pass

            diff_text = "\n".join(diff_chunks)
            ai_attribution = detect_ai_agent(
                author=author_str,
                message=message,
                diff_content=diff_text,
            )

            return DanglingCommit(
                commit_hash=full_sha,
                author=author_str,
                date=date_str,
                message=message,
                parents=parents,
                changed_files=changed_files,
                diff_content=diff_text,
                is_dangling=True,
                ai_agent=ai_attribution,
            ), False
        except urllib.error.HTTPError as h_err:
            if h_err.code == 404:
                return None, True
            return None, False
        except Exception:
            return None, False

    def fetch_orphan_commit_via_api(
        self,
        target: ParsedRemoteTarget,
        commit_sha: str,
        max_text_bytes: int = 10 * 1024 * 1024,
    ) -> Optional[DanglingCommit]:
        commit, _ = self.fetch_commit_or_check_gc(target, commit_sha, max_text_bytes)
        return commit


class BitbucketAPIForensicsClient:
    """Queries Bitbucket Cloud REST API 2.0 for force-pushes and declined PR commits."""

    DEFAULT_TIMEOUT_SECONDS = 12

    def __init__(self, bitbucket_token: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        resolved = (bitbucket_token or resolve_system_bitbucket_token() or "").strip()
        self._token: Optional[str] = resolved if resolved else None
        self.timeout = timeout

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "UnForce-Security-Forensics/1.0.0",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def discover_history_overwrite_events(
        self,
        target: ParsedRemoteTarget,
        scan_forks: bool = True,
        max_forks: int = 5,
    ) -> Tuple[List[HistoryOverwriteEvent], List[str], List[str]]:
        events: List[HistoryOverwriteEvent] = []
        candidate_shas: List[str] = []
        seen_shas: Set[str] = set()
        warnings: List[str] = []
        zero_sha = "0" * 40

        prs_url = f"{target.api_repo_url}/pullrequests?state=DECLINED&pagelen=30"
        try:
            req = urllib.request.Request(prs_url, headers=self._build_headers(), method="GET")
            raw_prs = _fetch_json_resilient(req, timeout=self.timeout, token=self._token)
            values = raw_prs.get("values", []) if isinstance(raw_prs, dict) else []
            for pr in values:
                if not isinstance(pr, dict):
                    continue
                pr_id = pr.get("id", "?")
                src = pr.get("source") or {}
                commit_obj = src.get("commit") or {}
                sha = str(commit_obj.get("hash") or "").strip()
                author_obj = pr.get("author") or {}
                author = author_obj.get("display_name") or author_obj.get("nickname") or "unknown"
                updated_on = str(pr.get("updated_on") or "")
                if sha and sha != zero_sha:
                    events.append(
                        HistoryOverwriteEvent(
                            event_id=f"bb-PR-{pr_id}",
                            event_type="closed_pr_orphan",
                            ref=f"refs/pull-requests/{pr_id}",
                            before_sha=sha,
                            after_sha=None,
                            actor=author,
                            created_at=updated_on,
                            description=f"Bitbucket declined PR #{pr_id} head commit {sha[:10]}",
                        )
                    )
                    if sha not in seen_shas:
                        seen_shas.add(sha)
                        candidate_shas.append(sha)
        except Exception as exc:
            warnings.append(sanitize_token_in_text(str(exc), self._token))

        return events, candidate_shas, warnings

    def fetch_commit_or_check_gc(
        self,
        target: ParsedRemoteTarget,
        commit_sha: str,
        max_text_bytes: int = 10 * 1024 * 1024,
    ) -> Tuple[Optional[DanglingCommit], bool]:
        sha = (commit_sha or "").strip()
        if not sha:
            return None, False

        commit_url = f"{target.api_repo_url}/commit/{sha}"
        diff_url = f"{target.api_repo_url}/diff/{sha}"
        try:
            req = urllib.request.Request(commit_url, headers=self._build_headers(), method="GET")
            data = _fetch_json_resilient(req, timeout=self.timeout, token=self._token)
            if not isinstance(data, dict):
                return None, False

            full_sha = str(data.get("hash") or sha)
            author_obj = data.get("author") or {}
            raw_author = author_obj.get("raw") or "Unknown"
            date_str = str(data.get("date") or "")
            message = str(data.get("message") or "")
            parents = [str(p.get("hash")) for p in (data.get("parents") or []) if isinstance(p, dict) and p.get("hash")]

            diff_text = ""
            changed_files: List[str] = []
            try:
                diff_req = urllib.request.Request(diff_url, headers=self._build_headers(), method="GET")
                with urllib.request.urlopen(diff_req, timeout=self.timeout) as diff_resp:
                    raw_diff_bytes = diff_resp.read(max_text_bytes)
                    diff_text = raw_diff_bytes.decode("utf-8", errors="replace")
                    for m in re.finditer(r"^diff --git a/.*? b/(.+)$", diff_text, re.MULTILINE):
                        changed_files.append(m.group(1).strip())
            except Exception:
                pass

            ai_attribution = detect_ai_agent(
                author=raw_author,
                message=message,
                diff_content=diff_text,
            )

            return DanglingCommit(
                commit_hash=full_sha,
                author=raw_author,
                date=date_str,
                message=message,
                parents=parents,
                changed_files=changed_files,
                diff_content=diff_text,
                is_dangling=True,
                ai_agent=ai_attribution,
            ), False
        except urllib.error.HTTPError as h_err:
            if h_err.code == 404:
                return None, True
            return None, False
        except Exception:
            return None, False

    def fetch_orphan_commit_via_api(
        self,
        target: ParsedRemoteTarget,
        commit_sha: str,
        max_text_bytes: int = 10 * 1024 * 1024,
    ) -> Optional[DanglingCommit]:
        commit, _ = self.fetch_commit_or_check_gc(target, commit_sha, max_text_bytes)
        return commit


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
            reason_str = str(getattr(url_exc, "reason", url_exc))
            if "CERTIFICATE_VERIFY_FAILED" in reason_str or os.getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
                try:
                    ctx = ssl._create_unverified_context()
                    with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                        return json.loads(resp.read().decode("utf-8", errors="replace"))
                except Exception as retry_exc:
                    safe_msg = sanitize_token_in_text(str(retry_exc), self._token)
                    raise RuntimeError(f"GitHub API request failed ({url}): {safe_msg}") from None
            safe_msg = sanitize_token_in_text(str(url_exc), self._token)
            raise RuntimeError(f"GitHub API request failed ({url}): {safe_msg}") from None
        except Exception as exc:
            safe_msg = sanitize_token_in_text(str(exc), self._token)
            raise RuntimeError(f"GitHub API request failed ({url}): {safe_msg}") from None

    def discover_history_overwrite_events(
        self,
        target: ParsedGitHubTarget,
        scan_forks: bool = True,
        max_forks: int = 5,
    ) -> Tuple[List[HistoryOverwriteEvent], List[str], List[str]]:
        events: List[HistoryOverwriteEvent] = []
        candidate_shas: List[str] = []
        seen_shas: Set[str] = set()
        warnings: List[str] = []
        zero_sha = "0" * 40

        # 0. Query /repos/{owner}/{repo}/activity (Modern GitHub Activity API for force_push / branch events)
        activity_url = f"{target.api_repo_url}/activity?per_page=100"
        try:
            raw_activity = self._get_json(activity_url)
            if isinstance(raw_activity, list):
                for act in raw_activity:
                    if not isinstance(act, dict):
                        continue
                    act_type = str(act.get("activity_type") or "").strip()
                    act_id = str(act.get("id", ""))
                    actor = (act.get("actor") or {}).get("login", "unknown")
                    timestamp = str(act.get("timestamp") or "")
                    before_sha = str(act.get("before") or "").strip()
                    after_sha = str(act.get("after") or "").strip()
                    ref = str(act.get("ref") or "refs/heads/main")

                    if act_type == "force_push" and before_sha and before_sha != zero_sha:
                        desc = f"Force-push / history rewrite on {ref} (previous tip {before_sha[:10]} overwritten by {after_sha[:10]})"
                        events.append(
                            HistoryOverwriteEvent(
                                event_id=f"act-{act_id}",
                                event_type="force_push",
                                ref=ref,
                                before_sha=before_sha,
                                after_sha=after_sha,
                                actor=actor,
                                created_at=timestamp,
                                description=desc,
                            )
                        )
                        if before_sha not in seen_shas:
                            seen_shas.add(before_sha)
                            candidate_shas.append(before_sha)
                    elif "branch_delete" in act_type:
                        events.append(
                            HistoryOverwriteEvent(
                                event_id=f"act-{act_id}",
                                event_type="branch_delete",
                                ref=ref,
                                before_sha=before_sha if before_sha != zero_sha else "",
                                after_sha=None,
                                actor=actor,
                                created_at=timestamp,
                                description=f"Deleted branch '{ref}' by {actor}",
                            )
                        )
                        if before_sha and before_sha != zero_sha and before_sha not in seen_shas:
                            seen_shas.add(before_sha)
                            candidate_shas.append(before_sha)
        except Exception:
            pass

        # 1. Query /repos/{owner}/{repo}/events
        events_url = f"{target.api_repo_url}/events?per_page=100"
        try:
            raw_events = self._get_json(events_url)
            if isinstance(raw_events, list):
                for ev in raw_events:
                    if not isinstance(ev, dict):
                        continue
                    ev_type = ev.get("type", "")
                    ev_id = str(ev.get("id", ""))
                    actor = (ev.get("actor") or {}).get("login", "unknown")
                    created_at = ev.get("created_at", "")
                    payload = ev.get("payload") or {}

                    if ev_type == "PushEvent":
                        before_sha = str(payload.get("before") or "").strip()
                        after_sha = str(payload.get("head") or "").strip()
                        ref = str(payload.get("ref") or "refs/heads/main")
                        forced = bool(payload.get("forced", False))
                        size = payload.get("size", 1)

                        if before_sha and before_sha != zero_sha and before_sha != after_sha:
                            is_force_candidate = forced or size == 0
                            kind = "force_push" if is_force_candidate else "push_before"
                            desc = (
                                f"Force-push / history rewrite on {ref} (previous tip {before_sha[:10]} replaced by {after_sha[:10]})"
                                if is_force_candidate
                                else f"Push event on {ref} (previous tip {before_sha[:10]} -> {after_sha[:10]})"
                            )
                            events.append(
                                HistoryOverwriteEvent(
                                    event_id=ev_id,
                                    event_type=kind,
                                    ref=ref,
                                    before_sha=before_sha,
                                    after_sha=after_sha,
                                    actor=actor,
                                    created_at=created_at,
                                    description=desc,
                                )
                            )
                            if before_sha not in seen_shas:
                                seen_shas.add(before_sha)
                                candidate_shas.append(before_sha)

                    elif ev_type == "DeleteEvent":
                        ref_type = str(payload.get("ref_type") or "")
                        ref = str(payload.get("ref") or "")
                        if ref_type in ("branch", "tag") and ref:
                            events.append(
                                HistoryOverwriteEvent(
                                    event_id=ev_id,
                                    event_type="branch_delete",
                                    ref=f"refs/heads/{ref}" if ref_type == "branch" else f"refs/tags/{ref}",
                                    before_sha="",
                                    after_sha=None,
                                    actor=actor,
                                    created_at=created_at,
                                    description=f"Deleted {ref_type} '{ref}' by {actor}",
                                )
                            )
        except Exception as exc:
            warnings.append(sanitize_token_in_text(str(exc), self._token))

        # 2. Query closed unmerged PRs for orphaned head SHAs
        pulls_url = f"{target.api_repo_url}/pulls?state=closed&per_page=30"
        try:
            raw_pulls = self._get_json(pulls_url)
            if isinstance(raw_pulls, list):
                for pr in raw_pulls:
                    if not isinstance(pr, dict) or pr.get("merged_at"):
                        continue
                    head = pr.get("head") or {}
                    head_sha = str(head.get("sha") or "").strip()
                    head_ref = str(head.get("ref") or "pr-branch")
                    pr_num = pr.get("number", "?")
                    user_login = (pr.get("user") or {}).get("login", "unknown")
                    closed_at = str(pr.get("closed_at") or "")
                    if head_sha and head_sha != zero_sha:
                        events.append(
                            HistoryOverwriteEvent(
                                event_id=f"PR-{pr_num}",
                                event_type="closed_pr_orphan",
                                ref=f"refs/pull/{pr_num}/head ({head_ref})",
                                before_sha=head_sha,
                                after_sha=None,
                                actor=user_login,
                                created_at=closed_at,
                                description=f"Closed unmerged PR #{pr_num} ('{pr.get('title', '')}') head commit {head_sha[:10]}",
                            )
                        )
                        if head_sha not in seen_shas:
                            seen_shas.add(head_sha)
                            candidate_shas.append(head_sha)
        except Exception as exc:
            warnings.append(sanitize_token_in_text(str(exc), self._token))

        # 3. Query public forks and compare branches for divergent / overwritten commits
        if scan_forks:
            try:
                public_forks = self.query_public_forks(target, limit=max_forks)
                for f in public_forks:
                    div_commits = self.compare_fork_with_parent(target, f)
                    for c_sha, c_actor, c_msg in div_commits:
                        short_msg = c_msg.splitlines()[0] if c_msg else "Commit in fork"
                        events.append(
                            HistoryOverwriteEvent(
                                event_id=f"fork-{f.owner}-{c_sha[:7]}",
                                event_type="fork_divergence",
                                ref=f"fork:{f.full_name}:{f.default_branch}",
                                before_sha=c_sha,
                                after_sha=None,
                                actor=c_actor or f.owner,
                                created_at=f.pushed_at,
                                description=f"Fork '{f.full_name}' holds commit {c_sha[:10]} not in parent ('{short_msg}')",
                            )
                        )
                        if c_sha not in seen_shas:
                            seen_shas.add(c_sha)
                            candidate_shas.append(c_sha)
            except Exception as exc:
                warnings.append(sanitize_token_in_text(str(exc), self._token))

        return events, candidate_shas, warnings

    def query_public_forks(
        self,
        target: ParsedGitHubTarget,
        limit: int = 20,
    ) -> List[ForkForensicsTarget]:
        forks_url = f"{target.api_repo_url}/forks?sort=newest&per_page={limit}"
        forks: List[ForkForensicsTarget] = []
        try:
            raw_forks = self._get_json(forks_url)
            if isinstance(raw_forks, list):
                for item in raw_forks:
                    if not isinstance(item, dict):
                        continue
                    owner_obj = item.get("owner") or {}
                    owner = str(owner_obj.get("login") or "").strip()
                    repo = str(item.get("name") or "").strip()
                    clone_url = str(item.get("clone_url") or f"https://github.com/{owner}/{repo}.git")
                    html_url = str(item.get("html_url") or f"https://github.com/{owner}/{repo}")
                    default_branch = str(item.get("default_branch") or "main")
                    pushed_at = str(item.get("pushed_at") or "")
                    stars = int(item.get("stargazers_count") or 0)
                    forks_cnt = int(item.get("forks_count") or 0)

                    if owner and repo:
                        forks.append(
                            ForkForensicsTarget(
                                owner=owner,
                                repo=repo,
                                clone_url=clone_url,
                                html_url=html_url,
                                default_branch=default_branch,
                                pushed_at=pushed_at,
                                stargazers_count=stars,
                                forks_count=forks_cnt,
                            )
                        )
        except Exception:
            pass
        return forks

    def compare_fork_with_parent(
        self,
        target: ParsedGitHubTarget,
        fork: ForkForensicsTarget,
    ) -> List[Tuple[str, str, str]]:
        divergent_commits: List[Tuple[str, str, str]] = []
        compare_urls = [
            f"{target.api_repo_url}/compare/{target.repo}:{fork.default_branch}...{fork.owner}:{fork.default_branch}",
            f"{target.api_repo_url}/compare/{fork.default_branch}...{fork.owner}:{fork.default_branch}",
        ]
        for c_url in compare_urls:
            try:
                data = self._get_json(c_url)
                if isinstance(data, dict):
                    commits = data.get("commits") or []
                    for c in commits:
                        if not isinstance(c, dict):
                            continue
                        sha = str(c.get("sha") or "").strip()
                        author_obj = c.get("author") or {}
                        author_login = (author_obj.get("login") if isinstance(author_obj, dict) else "") or fork.owner
                        commit_inner = c.get("commit") or {}
                        msg = str(commit_inner.get("message") or "")
                        if sha:
                            divergent_commits.append((sha, author_login, msg))
                    if divergent_commits:
                        break
            except Exception:
                continue
        return divergent_commits

    def fetch_orphan_commit_via_api(
        self,
        target: ParsedGitHubTarget,
        commit_sha: str,
        max_text_bytes: int = 10 * 1024 * 1024,
    ) -> Optional[DanglingCommit]:
        sha = (commit_sha or "").strip()
        if not sha:
            return None

        commit_url = f"{target.api_repo_url}/commits/{sha}"
        try:
            data = self._get_json(commit_url)
            if not isinstance(data, dict):
                return None

            full_sha = str(data.get("sha") or sha)
            commit_obj = data.get("commit") or {}
            author_obj = commit_obj.get("author") or {}
            author_name = author_obj.get("name") or "Unknown"
            author_email = author_obj.get("email") or ""
            author_str = f"{author_name} <{author_email}>" if author_email else author_name
            date_str = str(author_obj.get("date") or "")
            message = str(commit_obj.get("message") or "")
            parents = [
                str(p.get("sha"))
                for p in (data.get("parents") or [])
                if isinstance(p, dict) and p.get("sha")
            ]

            changed_files: List[str] = []
            diff_chunks: List[str] = []
            accumulated_bytes = 0

            for f_item in data.get("files") or []:
                if not isinstance(f_item, dict):
                    continue
                fname = str(f_item.get("filename") or "")
                if fname:
                    changed_files.append(fname)
                patch = f_item.get("patch")
                if isinstance(patch, str) and patch:
                    patch_bytes = len(patch.encode("utf-8", errors="replace"))
                    if accumulated_bytes + patch_bytes <= max_text_bytes:
                        diff_chunks.append(
                            f"diff --git a/{fname} b/{fname}\n--- a/{fname}\n+++ b/{fname}\n{patch}"
                        )
                        accumulated_bytes += patch_bytes

            diff_text = "\n".join(diff_chunks)
            ai_attribution = detect_ai_agent(
                author=author_str,
                message=message,
                diff_content=diff_text,
            )

            return DanglingCommit(
                commit_hash=full_sha,
                author=author_str,
                date=date_str,
                message=message,
                parents=parents,
                changed_files=changed_files,
                diff_content=diff_text,
                is_dangling=True,
                ai_agent=ai_attribution,
            )
        except Exception:
            return None


def get_forensics_client_for_target(target: ParsedRemoteTarget, token: Optional[str] = None):
    """Instantiates the dedicated platform forensics client (GitLab, Bitbucket, or GitHub)."""
    if target.platform == "gitlab":
        return GitLabAPIForensicsClient(gitlab_token=token)
    elif target.platform == "bitbucket":
        return BitbucketAPIForensicsClient(bitbucket_token=token)
    return GitHubAPIForensicsClient(github_token=token)


class SmartGitCloner:
    """Performs smart mirror cloning of remote GitHub repositories and fetches orphaned SHAs."""

    CLONE_TIMEOUT_SECONDS = 120
    FETCH_TIMEOUT_SECONDS = 30

    @classmethod
    def acquire(
        cls,
        target: ParsedGitHubTarget,
        github_token: Optional[str] = None,
        clone_source_override: Optional[str] = None,
        scan_forks: bool = True,
        max_forks: int = 5,
        on_phase: Optional[Callable[[str, int], None]] = None,
    ) -> RemoteAcquisitionResult:
        if not shutil.which("git"):
            raise RuntimeError("Git executable was not found on the system PATH.")

        explicit_token = (github_token or os.getenv("GITHUB_TOKEN") or "").strip() or None
        resolved_token = explicit_token
        if not resolved_token and not clone_source_override:
            resolved_token = resolve_system_github_token()

        api_client = GitHubAPIForensicsClient(github_token=resolved_token)

        if on_phase:
            on_phase(f"Querying GitHub API events & PRs for {target.full_name}...", 10)

        history_events: List[HistoryOverwriteEvent] = []
        candidate_shas: List[str] = []
        warnings: List[str] = []
        discovered_forks: List[ForkForensicsTarget] = []

        if not clone_source_override:
            history_events, candidate_shas, warnings = api_client.discover_history_overwrite_events(
                target, scan_forks=scan_forks, max_forks=max_forks
            )
            if scan_forks:
                discovered_forks = api_client.query_public_forks(target, limit=max_forks)

        temp_dir = Path(tempfile.mkdtemp(prefix=f"gitghost_remote_{target.repo}_")).resolve()
        effective_clone_url = clone_source_override or target.clone_url

        try:
            if on_phase:
                on_phase(f"Cloning bare object mirror of {target.full_name}...", 25)

            cls._run_git_with_auth(
                ["clone", "--mirror", effective_clone_url, str(temp_dir)],
                cwd=temp_dir.parent,
                token=resolved_token,
                timeout=cls.CLONE_TIMEOUT_SECONDS,
            )

            # Extended refs: fetch pull requests and tags
            for ref_spec in ("+refs/pull/*:refs/pull/*", "+refs/tags/*:refs/tags/*"):
                try:
                    cls._run_git_with_auth(
                        ["fetch", "origin", ref_spec],
                        cwd=temp_dir,
                        token=resolved_token,
                        timeout=cls.FETCH_TIMEOUT_SECONDS,
                        check=False,
                    )
                except Exception:
                    pass

            # Fetch branches from discovered public forks into refs/forks/<owner>/*
            if discovered_forks and not clone_source_override:
                if on_phase:
                    on_phase(f"Auditing and fetching {len(discovered_forks)} public fork(s)...", 35)

                for fork in discovered_forks[:max_forks]:
                    try:
                        cls._run_git_with_auth(
                            ["fetch", fork.clone_url, f"+refs/heads/*:refs/forks/{fork.owner}/*"],
                            cwd=temp_dir,
                            token=resolved_token,
                            timeout=cls.FETCH_TIMEOUT_SECONDS,
                            check=False,
                        )
                    except Exception:
                        pass

            api_recovered_commits: List[DanglingCommit] = []
            if candidate_shas:
                if on_phase:
                    on_phase(f"Exhuming {len(candidate_shas)} overwritten/orphaned commit(s)...", 40)

                for sha in candidate_shas[:25]:
                    exists_locally = cls._object_exists(temp_dir, sha)
                    if not exists_locally:
                        try:
                            cls._run_git_with_auth(
                                ["fetch", "origin", sha],
                                cwd=temp_dir,
                                token=resolved_token,
                                timeout=cls.FETCH_TIMEOUT_SECONDS,
                                check=False,
                            )
                        except Exception:
                            pass
                        exists_locally = cls._object_exists(temp_dir, sha)

                    if not exists_locally:
                        api_commit = api_client.fetch_orphan_commit_via_api(target, sha)
                        if api_commit:
                            api_recovered_commits.append(api_commit)

            return RemoteAcquisitionResult(
                target=target,
                local_clone_path=temp_dir,
                is_temporary=True,
                history_events=history_events,
                discovered_orphan_shas=candidate_shas,
                api_recovered_commits=api_recovered_commits,
                warnings=warnings,
                discovered_forks=discovered_forks,
            )
        except Exception as exc:
            cls.cleanup_workspace(temp_dir)
            safe_err = sanitize_token_in_text(str(exc), resolved_token)
            raise RuntimeError(f"Failed to acquire remote GitHub repository '{target.full_name}': {safe_err}") from None

    @classmethod
    def _object_exists(cls, repo_dir: Path, sha: str) -> bool:
        try:
            res = subprocess.run(
                ["git", "cat-file", "-t", sha],
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return res.returncode == 0 and res.stdout.strip() == "commit"
        except Exception:
            return False

    @classmethod
    def _run_git_with_auth(
        cls,
        args: List[str],
        cwd: Path,
        token: Optional[str],
        timeout: int,
        check: bool = True,
        disable_ssl_verify: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        cmd = ["git"]
        if disable_ssl_verify or os.getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
            cmd.extend(["-c", "http.sslVerify=false"])

        if token:
            # GitHub Git Smart HTTP requires Basic auth with x-access-token:<token>
            b64_creds = base64.b64encode(f"x-access-token:{token.strip()}".encode("utf-8")).decode("ascii")
            cmd.extend([
                "-c", "credential.helper=",
                "-c", "core.askPass=",
                "-c", f"http.https://github.com/.extraHeader=Authorization: Basic {b64_creds}",
            ])
        else:
            cmd.extend(["-c", "core.askPass="])

        cmd.extend(args)

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GCM_INTERACTIVE"] = "never"

        try:
            return subprocess.run(
                cmd,
                cwd=str(cwd),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=check,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Git operation timed out after {timeout}s.") from None
        except subprocess.CalledProcessError as exc:
            raw_msg = (exc.stderr or exc.stdout or str(exc)).strip()
            if not disable_ssl_verify and (
                "SSL certificate problem" in raw_msg or "certificate verify failed" in raw_msg.lower()
            ):
                return cls._run_git_with_auth(
                    args=args,
                    cwd=cwd,
                    token=token,
                    timeout=timeout,
                    check=check,
                    disable_ssl_verify=True,
                )
            safe_msg = sanitize_token_in_text(raw_msg, token)
            if check:
                raise RuntimeError(safe_msg) from None
            return subprocess.CompletedProcess(cmd, exc.returncode, exc.stdout or "", safe_msg)

    @classmethod
    def cleanup_workspace(cls, workspace_path: Optional[Path | str]) -> None:
        """Guarantees removal of temporary clone directories, handling Windows read-only packfiles."""
        if not workspace_path:
            return
        path_obj = Path(workspace_path)
        if not path_obj.exists():
            return

        def _handle_readonly(func, p, exc_info):
            try:
                os.chmod(p, stat.S_IWRITE)
                func(p)
            except Exception:
                pass

        try:
            shutil.rmtree(path_obj, onerror=_handle_readonly)
        except Exception:
            shutil.rmtree(path_obj, ignore_errors=True)
