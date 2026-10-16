"""
Remote GitHub Repository Acquisition & History Overwrite Forensics.

Provides URL parsing, token sanitization, GitHub Events/Commits API querying
for force-push/deleted branch discovery, and smart mirror cloning with resource guards.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from gitghost.git_forensics import DanglingCommit, detect_ai_agent

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


class GitHubAPIForensicsClient:
    """Queries GitHub REST API for history overwrite events, force-pushes, and orphaned commits.

    Token is held strictly in memory and never emitted in logs, exceptions, or reports.
    """

    DEFAULT_TIMEOUT_SECONDS = 12

    def __init__(self, github_token: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        resolved_token = (github_token or os.getenv("GITHUB_TOKEN") or "").strip()
        self._token: Optional[str] = resolved_token if resolved_token else None
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"GitHubAPIForensicsClient(authenticated={bool(self._token)}, timeout={self.timeout})"

    def _build_headers(self, accept: str = "application/vnd.github+json") -> Dict[str, str]:
        headers = {
            "Accept": accept,
            "User-Agent": "GitGhost-Security-Forensics/0.1.0",
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
        except Exception as exc:
            safe_msg = sanitize_token_in_text(str(exc), self._token)
            raise RuntimeError(f"GitHub API request failed ({url}): {safe_msg}") from None

    def discover_history_overwrite_events(
        self,
        target: ParsedGitHubTarget,
        scan_forks: bool = True,
        max_forks: int = 5,
    ) -> Tuple[List[HistoryOverwriteEvent], List[str], List[str]]:
        """Inspects repository activity events, closed PRs, and public forks for force-push/overwritten SHAs.

        Returns (events, candidate_orphan_shas, warnings).
        """
        events: List[HistoryOverwriteEvent] = []
        candidate_shas: List[str] = []
        seen_shas: Set[str] = set()
        warnings: List[str] = []
        zero_sha = "0" * 40

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
        """Queries public forks of the target repository via /repos/{owner}/{repo}/forks.

        Sorted by newest first to identify branches and forks created before/after force-pushes.
        """
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
        """Compares a fork with the parent repository to identify divergent commits.

        Calls /repos/{owner}/{repo}/compare/{parent_branch}...{fork_owner}:{fork_branch}.
        Returns a list of (commit_sha, author_login, commit_message) present in fork but not parent.
        """
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
        """Fetches an overwritten or orphaned commit directly from GitHub Commits API (/commits/{sha})."""
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


class SmartGitCloner:
    """Performs smart mirror cloning of remote GitHub repositories and fetches orphaned SHAs.

    Enforces network/git timeouts, keeps authentication tokens strictly in memory (never written to .git/config),
    and provides guaranteed temporary directory cleanup.
    """

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

        resolved_token = (github_token or os.getenv("GITHUB_TOKEN") or "").strip() or None
        api_client = GitHubAPIForensicsClient(github_token=resolved_token)

        if on_phase:
            on_phase(f"Querying GitHub API events for {target.full_name}...", 10)

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
                on_phase(f"Smart mirror-cloning {target.full_name}...", 25)

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
                    # Check if commit already exists in local object database
                    exists_Locally = cls._object_exists(temp_dir, sha)
                    if not exists_Locally:
                        # Try explicit git fetch origin <sha> (leaves fetched object unreferenced in FETCH_HEAD)
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
                        exists_Locally = cls._object_exists(temp_dir, sha)

                    if not exists_Locally:
                        # Fallback to GitHub Commits REST API to recover commit & patch directly
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
    ) -> subprocess.CompletedProcess[str]:
        cmd = ["git", "-c", "credential.helper=", "-c", "core.askPass="]
        if token:
            cmd.extend(["-c", f"http.extraHeader=Authorization: Bearer {token}"])
        cmd.extend(args)

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

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

