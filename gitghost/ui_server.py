"""
UI Server and REST API backend for UnForce (ForcePush-Breaker / GitGhost).
Engineered for ultra-fast cold boot (<80ms), windowless Git operations,
session-cached GitHub bare mirrors, and 100% functional GitHub repository forensics.
"""

from __future__ import annotations

import atexit
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import urllib.parse
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

from gitghost import BRAND_NAME, BRAND_SHORT, __version__

# Thread-safe server-side cache for full pipeline scan results
_SCAN_CACHE: Dict[str, Any] = {}
_CACHE_LOCK = threading.Lock()

# Managed session bare-mirror directories for scanned GitHub repos (bounded & cleaned on exit)
_SESSION_MIRRORS: List[Path] = []
_MIRROR_LOCK = threading.Lock()

# Managed sandbox demo directories (for backwards compatibility with test suites)
_DEMO_DIRS: List[Path] = []
_DEMO_LOCK = threading.Lock()


def _register_session_mirror(mirror_path: Optional[Path]) -> None:
    if not mirror_path:
        return
    from gitghost.github_remote import SmartGitCloner

    with _MIRROR_LOCK:
        if mirror_path in _SESSION_MIRRORS:
            return
        while len(_SESSION_MIRRORS) >= 3:
            evicted = _SESSION_MIRRORS.pop(0)
            try:
                SmartGitCloner.cleanup_workspace(evicted)
            except Exception:
                pass
        _SESSION_MIRRORS.append(mirror_path)


def _cleanup_all_workspaces() -> None:
    try:
        from gitghost.github_remote import SmartGitCloner

        with _MIRROR_LOCK:
            while _SESSION_MIRRORS:
                m = _SESSION_MIRRORS.pop(0)
                try:
                    SmartGitCloner.cleanup_workspace(m)
                except Exception:
                    pass
    except Exception:
        pass

    try:
        from gitghost.demo_builder import DemoBuilder

        with _DEMO_LOCK:
            while _DEMO_DIRS:
                d = _DEMO_DIRS.pop(0)
                try:
                    DemoBuilder.cleanup(d)
                except Exception:
                    pass
    except Exception:
        pass


atexit.register(_cleanup_all_workspaces)


def _cache_pipeline_result(pipeline_res: Any, raw_target: str) -> None:
    from gitghost.github_remote import parse_github_url, parse_remote_url, is_remote_target

    keys = {pipeline_res.repo_path, raw_target, "__latest__"}
    if getattr(pipeline_res, "remote_url", None):
        keys.add(pipeline_res.remote_url)
    gh = parse_github_url(raw_target) or parse_github_url(pipeline_res.repo_path)
    if gh is not None:
        keys.add(gh.clone_url)
        keys.add(gh.html_url)
        keys.add(gh.full_name)
        keys.add(f"{gh.html_url}/")

    with _CACHE_LOCK:
        for k in keys:
            if k:
                _SCAN_CACHE[k] = pipeline_res


def _get_effective_git_dir(pipeline_res: Any) -> Optional[Path]:
    mirror = getattr(pipeline_res, "local_mirror_path", None)
    if mirror and Path(mirror).exists():
        return Path(mirror)
    if not getattr(pipeline_res, "is_remote", False):
        p = Path(pipeline_res.repo_path)
        if p.exists():
            return p
    return None


@dataclass
class ScanJob:
    job_id: str
    repo_target: str
    status: str = "queued"  # "queued" | "running" | "completed" | "failed"
    progress_pct: int = 0
    phase_message: str = "Initializing forensics scan..."
    scanned_objects: int = 0
    total_objects: int = 0
    phase_logs: Optional[List[str]] = None
    error: Optional[str] = None
    result: Any = None


class ScanJobManager:
    """Manages asynchronous background repository scans with real-time progress and telemetry logs."""

    MAX_JOBS = 25
    _jobs: Dict[str, ScanJob] = {}
    _lock = threading.Lock()

    @classmethod
    def start_job(
        cls,
        repo_target: str,
        ai_provider: str = "heuristic",
        ai_api_key: Optional[str] = None,
        entropy_threshold: float = 4.0,
        github_token: Optional[str] = None,
        clone_source_override: Optional[str] = None,
        scan_forks: bool = True,
    ) -> ScanJob:
        job_id = uuid.uuid4().hex[:12]
        job = ScanJob(
            job_id=job_id,
            repo_target=repo_target,
            status="running",
            progress_pct=5,
            phase_logs=["[INIT] Bootstrapping UnForce forensics pipeline..."],
        )

        with cls._lock:
            if len(cls._jobs) >= cls.MAX_JOBS:
                oldest_key = next(iter(cls._jobs))
                cls._jobs.pop(oldest_key, None)
            cls._jobs[job_id] = job

        ephemeral_token = (github_token or "").strip() or None
        ephemeral_ai_key = (ai_api_key or "").strip() or None

        def _worker():
            from gitghost.github_remote import sanitize_token_in_text
            from gitghost.pipeline import run_scan_pipeline

            try:
                def on_phase(msg: str, pct: int):
                    job.phase_message = msg
                    job.progress_pct = max(job.progress_pct, min(99, pct))
                    if job.phase_logs is not None and (not job.phase_logs or job.phase_logs[-1] != msg):
                        job.phase_logs.append(msg)

                def on_forensics_done(scan_res: Any):
                    total = len(scan_res.dangling_commits) + len(scan_res.dangling_blobs)
                    job.total_objects = total
                    msg = (
                        f"Exhumed {len(scan_res.dangling_commits)} ghost commit(s), "
                        f"{len(scan_res.branch_commits)} branch commit(s), "
                        f"{len(scan_res.dangling_blobs)} detached blob(s)."
                    )
                    job.phase_message = msg
                    job.progress_pct = max(job.progress_pct, 60)
                    if job.phase_logs is not None:
                        job.phase_logs.append(msg)

                def on_item_scanned(current: int, total: int):
                    job.scanned_objects = current
                    job.total_objects = total
                    if total > 0:
                        ratio = current / total
                        job.progress_pct = min(90, 60 + int(ratio * 25))

                keep_ws = clone_source_override is None
                pipeline_res = run_scan_pipeline(
                    repo_path=repo_target,
                    ai_provider=ai_provider,
                    ai_api_key=ephemeral_ai_key,
                    entropy_threshold=entropy_threshold,
                    github_token=ephemeral_token,
                    clone_source_override=clone_source_override,
                    scan_forks=scan_forks,
                    keep_remote_workspace=keep_ws,
                    on_forensics_done=on_forensics_done,
                    on_item_scanned=on_item_scanned,
                    on_phase=on_phase,
                )

                if keep_ws and getattr(pipeline_res, "local_mirror_path", None):
                    _register_session_mirror(pipeline_res.local_mirror_path)

                _cache_pipeline_result(pipeline_res, repo_target)

                job.result = pipeline_res
                job.progress_pct = 100
                job.phase_message = "Forensics audit completed."
                if job.phase_logs is not None:
                    job.phase_logs.append("Forensics audit completed.")
                job.status = "completed"
            except Exception as exc:
                err_msg = sanitize_token_in_text(str(exc), ephemeral_token)
                if ephemeral_ai_key:
                    err_msg = err_msg.replace(ephemeral_ai_key, "[REDACTED_API_KEY]")
                job.error = err_msg
                job.phase_message = "Scan failed."
                if job.phase_logs is not None:
                    job.phase_logs.append(f"[ERROR] {err_msg}")
                job.status = "failed"

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return job

    @classmethod
    def get_job(cls, job_id: str) -> Optional[ScanJob]:
        with cls._lock:
            return cls._jobs.get(job_id)


class GitGhostRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for the UnForce Chromium Studio UI and REST API."""

    def log_message(self, format, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            from gitghost.ui_assets import get_dashboard_html

            self._send_html(get_dashboard_html())
        elif self.path == "/api/status":
            self._send_json({
                "status": "ok",
                "version": __version__,
                "app": "GitGhost",
                "brand": f"{BRAND_NAME} ({BRAND_SHORT})",
            })
        elif self.path == "/api/system/info":
            self._handle_system_info()
        elif self.path.startswith("/api/scan/status"):
            self._handle_scan_status()
        elif self.path.startswith("/api/download/report"):
            self._handle_download_report_get()
        elif self.path.startswith("/api/download/bundle"):
            self._handle_download_bundle_get()
        else:
            self._send_error(404, "Not Found")

    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            data = json.loads(post_body.decode("utf-8")) if post_body else {}
        except Exception as e:
            self._send_error(400, f"Malformed JSON: {e}")
            return

        routes = {
            "/api/browse": lambda: self._handle_browse(),
            "/api/demo/create": lambda: self._handle_demo_create(),
            "/api/scan/start": lambda: self._handle_scan_start(data),
            "/api/scan": lambda: self._handle_scan(data),
            "/api/cleanup": lambda: self._handle_cleanup(data),
            "/api/export": lambda: self._handle_export(data),
            "/api/download/report": lambda: self._handle_download_report(data),
            "/api/download/bundle": lambda: self._handle_download_bundle(data),
            "/api/recover/file": lambda: self._handle_recover_file(data),
            "/api/commit/diff": lambda: self._handle_commit_diff(data),
            "/api/commit/files": lambda: self._handle_commit_files(data),
            "/api/commit/file-preview": lambda: self._handle_commit_file_preview(data),
            "/api/git/restore-branch": lambda: self._handle_git_restore_branch(data),
            "/api/git/cherry-pick": lambda: self._handle_git_cherry_pick(data),
            "/api/git/restore-file": lambda: self._handle_git_restore_file(data),
            "/api/search": lambda: self._handle_search(data),
            "/api/verify/key": lambda: self._handle_verify_key(data),
            "/api/hook": lambda: self._handle_hook(data),
            "/api/shutdown": lambda: self._handle_shutdown(),
        }

        handler = routes.get(self.path)
        if handler:
            handler()
        else:
            self._send_error(404, "Endpoint Not Found")

    def _send_html(self, html: str):
        content = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def _send_download(self, content_bytes: bytes, filename: str, content_type: str = "application/octet-stream"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(content_bytes)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content_bytes)

    def _send_json(self, payload: dict, status: int = 200):
        content = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def _send_error(self, status: int, message: str):
        self._send_json({"error": message, "status": status}, status=status)

    def _handle_system_info(self):
        from gitghost.github_remote import resolve_system_github_token

        git_path = shutil.which("git")
        git_ver = ""
        if git_path:
            try:
                res = subprocess.run(
                    ["git", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
                git_ver = res.stdout.strip()
            except Exception:
                git_ver = "git (available)"

        gh_auto = bool(resolve_system_github_token())
        self._send_json({
            "app": "GitGhost",
            "brand": BRAND_NAME,
            "short_name": BRAND_SHORT,
            "version": __version__,
            "git_available": bool(git_path),
            "git_version": git_ver,
            "github_auth_auto": gh_auto,
            "platform": sys.platform,
            "os_release": platform.platform(),
            "is_frozen": bool(getattr(sys, "frozen", False)),
        })

    def _handle_demo_create(self):
        from gitghost.demo_builder import DemoBuilder

        if not shutil.which("git"):
            self._send_error(500, "Git executable not found in system PATH.")
            return
        try:
            info = DemoBuilder.create_demo_repository()
            with _DEMO_LOCK:
                while len(_DEMO_DIRS) >= 4:
                    old = _DEMO_DIRS.pop(0)
                    DemoBuilder.cleanup(old)
                _DEMO_DIRS.append(info.repo_path)

            self._send_json({
                "success": True,
                "repo_path": str(info.repo_path),
                "description": info.description,
                "leaked_filename": info.leaked_filename,
                "dangling_commit_sha": info.dangling_commit_sha,
            })
        except Exception as exc:
            self._send_error(500, f"Failed to initialize sandbox demo: {exc}")

    def _handle_shutdown(self):
        self._send_json({"status": "shutting_down"})
        setattr(self.server, "_shutdown_requested", True)

        def _stop():
            _cleanup_all_workspaces()
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass

        threading.Thread(target=_stop, daemon=True).start()

    def _handle_browse(self):
        self._send_json({"folder": ""})

    def _validate_target_or_error(self, repo_path_str: str) -> Optional[str]:
        from gitghost.git_forensics import GitForensics
        from gitghost.github_remote import is_remote_target

        if not shutil.which("git"):
            self._send_error(500, "Git executable not found in system PATH. Install Git to scan repositories.")
            return None
        if is_remote_target(repo_path_str):
            return repo_path_str
        repo_path = Path(repo_path_str).resolve()
        if not repo_path.exists():
            self._send_error(
                400,
                f"Invalid repository target: '{repo_path_str}'. Provide a valid GitHub, GitLab, or Bitbucket URL, or an existing local Git directory path.",
            )
            return None
        forensics = GitForensics(repo_path)
        if not forensics.is_valid_repo():
            self._send_error(
                400,
                f"Directory '{repo_path}' is not a valid Git repository (missing .git directory).",
            )
            return None
        return str(repo_path)

    def _handle_scan_start(self, data: dict):
        repo_path_str = (data.get("repo_path") or "").strip()
        if not repo_path_str:
            self._send_error(400, "Please paste a GitHub repository URL (e.g. https://github.com/owner/repo).")
            return
        validated = self._validate_target_or_error(repo_path_str)
        if validated is None:
            return

        job = ScanJobManager.start_job(
            repo_target=validated,
            ai_provider=data.get("ai_provider", "heuristic"),
            ai_api_key=data.get("ai_api_key"),
            entropy_threshold=float(data.get("entropy_threshold", 4.0)),
            github_token=data.get("github_token"),
            clone_source_override=data.get("clone_source_override"),
            scan_forks=bool(data.get("scan_forks", True)),
        )
        self._send_json({
            "job_id": job.job_id,
            "status": job.status,
            "progress_pct": job.progress_pct,
            "phase_message": job.phase_message,
            "phase_logs": job.phase_logs or [],
        })

    def _handle_scan_status(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        job_id = (params.get("job_id") or [""])[0].strip()
        if not job_id:
            self._send_error(400, "Missing required query parameter: job_id")
            return

        job = ScanJobManager.get_job(job_id)
        if job is None:
            self._send_error(404, f"Scan job not found: {job_id}")
            return

        resp: Dict[str, Any] = {
            "job_id": job.job_id,
            "repo_target": job.repo_target,
            "status": job.status,
            "progress_pct": job.progress_pct,
            "phase_message": job.phase_message,
            "phase_logs": job.phase_logs or [],
            "scanned_objects": job.scanned_objects,
            "total_objects": job.total_objects,
            "error": job.error,
        }
        if job.status == "completed" and job.result is not None:
            resp["result"] = self._serialize_pipeline_result(job.result)
        self._send_json(resp)

    def _handle_scan(self, data: dict):
        from gitghost.github_remote import sanitize_token_in_text
        from gitghost.pipeline import run_scan_pipeline

        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        validated = self._validate_target_or_error(repo_path_str)
        if validated is None:
            return

        ai_provider = data.get("ai_provider", "heuristic")
        ai_api_key = data.get("ai_api_key")
        entropy_thresh = float(data.get("entropy_threshold", 4.0))
        github_token = data.get("github_token")
        clone_override = data.get("clone_source_override")
        scan_forks = bool(data.get("scan_forks", True))
        keep_ws = clone_override is None

        try:
            pipeline_res = run_scan_pipeline(
                repo_path=validated,
                ai_provider=ai_provider,
                ai_api_key=ai_api_key,
                entropy_threshold=entropy_thresh,
                github_token=github_token,
                clone_source_override=clone_override,
                scan_forks=scan_forks,
                keep_remote_workspace=keep_ws,
            )
        except Exception as exc:
            err_msg = sanitize_token_in_text(str(exc), github_token)
            if ai_api_key:
                err_msg = err_msg.replace(ai_api_key, "[REDACTED_API_KEY]")
            self._send_error(500, err_msg)
            return

        if keep_ws and getattr(pipeline_res, "local_mirror_path", None):
            _register_session_mirror(pipeline_res.local_mirror_path)
        _cache_pipeline_result(pipeline_res, validated)
        self._send_json(self._serialize_pipeline_result(pipeline_res))

    def _serialize_pipeline_result(self, pipeline_res: Any) -> dict:
        from gitghost.github_remote import parse_github_url

        findings_payload = []
        for f in pipeline_res.findings:
            t = pipeline_res.triage_map.get(f.finding_id)
            findings_payload.append({
                "finding_id": f.finding_id,
                "rule_name": f.rule_name,
                "severity_estimate": f.severity_estimate,
                "masked_value": f.masked_value,
                "line_number": f.line_number,
                "context_line": f.context_line,
                "diff_hunk": f.diff_hunk or f.context_line,
                "entropy": round(f.entropy, 2),
                "file_path": f.file_path,
                "commit_hash": f.commit_hash,
                "blob_hash": f.blob_hash,
                "triage_severity": t.severity if t else f.severity_estimate,
                "is_false_positive": t.is_false_positive if t else False,
                "triage_risk_score": t.risk_score if t else None,
                "triage_explanation": t.technical_explanation if t else None,
                "triage_action": t.recommended_action if t else None,
                "triage_provider": t.provider_used if t else None,
                "is_ai_agent": getattr(f, "is_ai_agent", False),
                "ai_agent_name": getattr(f, "ai_agent_name", None),
                "ai_agent_evidence": getattr(f, "ai_agent_evidence", []),
            })

        def _commit_dict(c: Any, is_orphan: bool) -> dict:
            return {
                "commit_hash": c.commit_hash,
                "author": c.author,
                "date": c.date,
                "message": c.redacted_message or c.message,
                "parents": getattr(c, "parents", []),
                "changed_files": c.changed_files,
                "redacted_diff": c.redacted_diff,
                "is_dangling": is_orphan,
                "is_ai_agent": c.ai_agent.is_ai_agent if c.ai_agent else False,
                "ai_agent_name": c.ai_agent.agent_name if c.ai_agent else None,
                "ai_agent_evidence": c.ai_agent.evidence if c.ai_agent else [],
            }

        commits_payload = [_commit_dict(c, True) for c in pipeline_res.scan_result.dangling_commits]
        branch_commits_payload = [
            _commit_dict(c, False) for c in getattr(pipeline_res.scan_result, "branch_commits", [])
        ]

        blobs_payload = [
            {
                "blob_hash": b.blob_hash,
                "size": b.size,
                "is_binary": b.is_binary,
                "associated_path": b.associated_path,
                "redacted_content": b.redacted_content if not b.is_binary else "[Binary blob data]",
            }
            for b in pipeline_res.scan_result.dangling_blobs
        ]

        history_events_payload = [
            {
                "event_id": ev.event_id,
                "event_type": ev.event_type,
                "ref": ev.ref,
                "before_sha": ev.before_sha,
                "after_sha": ev.after_sha,
                "actor": ev.actor,
                "created_at": ev.created_at,
                "description": ev.description,
                "status": getattr(ev, "status", "detected"),
                "gc_purged": getattr(ev, "gc_purged", False),
                "diagnostic_message": getattr(ev, "diagnostic_message", None),
            }
            for ev in pipeline_res.history_events
        ]

        reflog_payload = [
            {
                "index": r.index,
                "selector": r.selector,
                "commit_hash": r.commit_hash,
                "action": r.action,
                "message": r.message,
                "date": r.date,
                "author": r.author,
                "is_unreachable": r.is_unreachable,
            }
            for r in getattr(pipeline_res.scan_result, "reflog_entries", [])
        ]

        rm = getattr(pipeline_res.scan_result, "repo_metadata", None)
        repo_meta_payload = (
            {
                "current_branch": rm.current_branch,
                "head_sha": rm.head_sha,
                "head_subject": rm.head_subject,
                "remote_url": rm.remote_url,
                "is_bare": rm.is_bare,
                "is_clean": rm.is_clean,
                "local_branches": rm.local_branches,
                "tags_count": rm.tags_count,
            }
            if rm is not None
            else None
        )

        hygiene_payload = {
            "score": pipeline_res.hygiene.score,
            "grade": pipeline_res.hygiene.grade,
            "color": pipeline_res.hygiene.color,
            "summary": pipeline_res.hygiene.summary,
            "critical_findings_count": pipeline_res.hygiene.critical_findings_count,
            "high_findings_count": pipeline_res.hygiene.high_findings_count,
            "medium_findings_count": pipeline_res.hygiene.medium_findings_count,
            "low_findings_count": pipeline_res.hygiene.low_findings_count,
            "false_positives_count": pipeline_res.hygiene.false_positives_count,
            "deductions": [
                {"category": d.category, "points": d.points, "reason": d.reason}
                for d in pipeline_res.hygiene.deductions
            ],
        }

        remediation_payload = {
            "rotation_warning": pipeline_res.remediation.rotation_warning,
            "bash_script": pipeline_res.remediation.bash_script,
            "powershell_script": pipeline_res.remediation.powershell_script,
            "github_support_ticket": getattr(pipeline_res.remediation, "github_support_ticket", ""),
            "steps": [
                {
                    "order": s.order,
                    "title": s.title,
                    "description": s.description,
                    "commands": s.commands,
                }
                for s in pipeline_res.remediation.steps
            ],
        }

        config_files_payload = [
            {
                "file_path": cf.file_path,
                "file_type": cf.file_type,
                "commit_hash": cf.commit_hash,
                "blob_hash": cf.blob_hash,
                "size": cf.size,
                "date": cf.date,
                "author": cf.author,
            }
            for cf in getattr(pipeline_res.scan_result, "deleted_config_files", [])
        ]

        forks_payload = [
            {
                "owner": f.owner,
                "repo": f.repo,
                "full_name": f.full_name,
                "clone_url": f.clone_url,
                "html_url": f.html_url,
                "default_branch": f.default_branch,
                "pushed_at": f.pushed_at,
                "stargazers_count": f.stargazers_count,
                "forks_count": f.forks_count,
            }
            for f in getattr(pipeline_res, "discovered_forks", [])
        ]

        gh_parsed = parse_github_url(pipeline_res.remote_url or pipeline_res.repo_path)
        gh_html_url = gh_parsed.html_url if gh_parsed else ""

        remote_target = parse_remote_url(pipeline_res.repo_path)
        return {
            "repo_path": pipeline_res.repo_path,
            "is_remote": getattr(pipeline_res, "is_remote", False),
            "remote_platform": remote_target.platform if remote_target else ("remote" if getattr(pipeline_res, "is_remote", False) else "local"),
            "is_remote": pipeline_res.is_remote,
            "remote_url": pipeline_res.remote_url,
            "github_html_url": gh_html_url,
            "github_full_name": gh_parsed.full_name if gh_parsed else "",
            "scan_timestamp": pipeline_res.scan_result.scan_timestamp,
            "total_objects_scanned": pipeline_res.scan_result.total_objects_scanned,
            "repo_metadata": repo_meta_payload,
            "reflog_entries": reflog_payload,
            "dangling_commits": commits_payload,
            "branch_commits": branch_commits_payload,
            "dangling_blobs": blobs_payload,
            "deleted_config_files": config_files_payload,
            "history_events": history_events_payload,
            "discovered_forks": forks_payload,
            "findings": findings_payload,
            "hygiene_score": hygiene_payload,
            "remediation": remediation_payload,
        }

    def _resolve_pipeline_result(self, repo_path_str: str) -> Optional[Any]:
        from gitghost.github_remote import is_github_target, parse_github_url
        from gitghost.pipeline import run_scan_pipeline

        target = (repo_path_str or "").strip()
        with _CACHE_LOCK:
            if target and target in _SCAN_CACHE:
                return _SCAN_CACHE[target]
            gh = parse_github_url(target)
            if gh:
                for candidate in (gh.clone_url, gh.html_url, gh.full_name):
                    if candidate in _SCAN_CACHE:
                        return _SCAN_CACHE[candidate]
            if target and not is_github_target(target):
                try:
                    resolved = str(Path(target).resolve())
                    if resolved in _SCAN_CACHE:
                        return _SCAN_CACHE[resolved]
                except Exception:
                    pass
            if "__latest__" in _SCAN_CACHE:
                if not target or target == ".":
                    return _SCAN_CACHE["__latest__"]

        if not target:
            self._send_error(400, "No scanned repository in session yet. Scan a GitHub repository URL first.")
            return None

        validated = self._validate_target_or_error(target)
        if validated is None:
            return None
        try:
            pipeline_res = run_scan_pipeline(validated, ai_provider="heuristic", keep_remote_workspace=True)
            if getattr(pipeline_res, "local_mirror_path", None):
                _register_session_mirror(pipeline_res.local_mirror_path)
            _cache_pipeline_result(pipeline_res, validated)
            return pipeline_res
        except Exception as exc:
            self._send_error(500, str(exc))
            return None

    def _find_commit_obj(self, pipeline_res: Any, commit_hash: str) -> Optional[Any]:
        for c in pipeline_res.scan_result.dangling_commits:
            if c.commit_hash == commit_hash or c.commit_hash.startswith(commit_hash):
                return c
        for c in getattr(pipeline_res.scan_result, "branch_commits", []):
            if c.commit_hash == commit_hash or c.commit_hash.startswith(commit_hash):
                return c
        return None

    def _handle_commit_diff(self, data: dict):
        from gitghost.git_forensics import GitForensics
        from gitghost.pipeline import _scan_unified_diff_by_file
        from gitghost.redactor import SecretRedactor

        repo_path_str = (data.get("repo_path") or "").strip()
        commit_hash = (data.get("commit_hash") or "").strip()
        include_raw = bool(data.get("include_raw", False))

        if not commit_hash:
            self._send_error(400, "commit_hash is required.")
            return

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return

        commit_obj = self._find_commit_obj(pipeline_res, commit_hash)
        if commit_obj:
            if include_raw and commit_obj.diff_content:
                self._send_json({"success": True, "commit_hash": commit_obj.commit_hash, "diff": commit_obj.diff_content})
                return
            if not include_raw and commit_obj.redacted_diff:
                self._send_json({"success": True, "commit_hash": commit_obj.commit_hash, "diff": commit_obj.redacted_diff})
                return

        git_dir = _get_effective_git_dir(pipeline_res)
        if git_dir:
            raw_diff = GitForensics(git_dir).read_commit_diff(
                commit_obj.commit_hash if commit_obj else commit_hash
            )
            if raw_diff is not None:
                if include_raw:
                    out_diff = raw_diff
                else:
                    red = SecretRedactor()
                    fb = commit_obj.changed_files[0] if (commit_obj and commit_obj.changed_files) else "Diff"
                    out_diff = _scan_unified_diff_by_file(red, raw_diff, fb, commit_hash).redacted_text
                    if commit_obj:
                        commit_obj.diff_content = raw_diff
                        commit_obj.redacted_diff = out_diff
                self._send_json({
                    "success": True,
                    "commit_hash": commit_obj.commit_hash if commit_obj else commit_hash,
                    "diff": out_diff,
                })
                return

        self._send_json({"success": True, "commit_hash": commit_hash, "diff": ""})

    def _handle_commit_files(self, data: dict):
        from gitghost.git_forensics import GitForensics

        repo_path_str = (data.get("repo_path") or "").strip()
        commit_hash = (data.get("commit_hash") or "").strip()
        if not commit_hash:
            self._send_error(400, "commit_hash is required.")
            return

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return

        commit_obj = self._find_commit_obj(pipeline_res, commit_hash)
        changed_set = set(commit_obj.changed_files) if commit_obj else set()
        tree_files: List[Dict[str, Any]] = []

        git_dir = _get_effective_git_dir(pipeline_res)
        if git_dir:
            forensics = GitForensics(git_dir)
            full_sha = commit_obj.commit_hash if commit_obj else commit_hash
            raw_tree = forensics.list_commit_files(full_sha)
            for item in raw_tree:
                tree_files.append({
                    "path": item["path"],
                    "size": item["size"],
                    "blob_hash": item["blob_hash"],
                    "is_changed": item["path"] in changed_set,
                })

        if not tree_files and commit_obj:
            snapshots = getattr(commit_obj, "file_snapshots", {}) or {}
            for fp in commit_obj.changed_files:
                snap = snapshots.get(fp, "")
                tree_files.append({
                    "path": fp,
                    "size": len(snap.encode("utf-8")) if snap else 0,
                    "blob_hash": "",
                    "is_changed": True,
                })

        tree_files.sort(key=lambda x: (0 if x["is_changed"] else 1, x["path"]))
        self._send_json({
            "success": True,
            "commit_hash": commit_obj.commit_hash if commit_obj else commit_hash,
            "changed_files": list(changed_set),
            "files": tree_files,
        })

    def _handle_commit_file_preview(self, data: dict):
        from gitghost.git_forensics import GitForensics
        from gitghost.recovery import ObjectRecoveryEngine
        from gitghost.redactor import SecretRedactor

        repo_path_str = (data.get("repo_path") or "").strip()
        commit_hash = (data.get("commit_hash") or "").strip()
        file_path = (data.get("file_path") or "").strip()
        include_raw = bool(data.get("include_raw", False))

        if not commit_hash or not file_path:
            self._send_error(400, "commit_hash and file_path are required.")
            return

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return

        # 1. Try session Git mirror directly for instant full-file snapshot
        git_dir = _get_effective_git_dir(pipeline_res)
        if git_dir:
            raw_content = GitForensics(git_dir).read_commit_file(commit_hash, file_path)
            if raw_content is not None:
                content = (
                    raw_content
                    if include_raw
                    else SecretRedactor().scan_and_redact(
                        raw_content, file_path=file_path, commit_hash=commit_hash
                    ).redacted_text
                )
                self._send_json({
                    "success": True,
                    "file_path": file_path,
                    "commit_hash": commit_hash,
                    "is_redacted": not include_raw,
                    "content": content,
                })
                return

        # 2. Fallback to ObjectRecoveryEngine (handles API-recovered commits & pre-populated snapshots)
        try:
            artifact = ObjectRecoveryEngine.recover_commit_file(
                pipeline_res,
                commit_hash,
                file_path=file_path,
                include_raw=include_raw,
            )
            self._send_json({
                "success": True,
                "file_path": file_path,
                "commit_hash": artifact.object_hash,
                "is_redacted": artifact.is_redacted,
                "content": artifact.content,
            })
            return
        except ValueError:
            pass

        self._send_error(404, f"Could not read file '{file_path}' at commit '{commit_hash[:10]}'.")

    def _handle_cleanup(self, data: dict):
        from gitghost.git_forensics import GitForensics
        from gitghost.github_remote import is_github_target

        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        if is_github_target(repo_path_str):
            self._send_error(400, "Use the GitHub Purge Playbook & Support Ticket for remote GitHub repositories.")
            return
        repo_path = Path(repo_path_str).resolve()
        if not GitForensics(repo_path).is_valid_repo():
            self._send_error(400, "Target is not a valid Git repository.")
            return

        try:
            subprocess.run(
                ["git", "reflog", "expire", "--expire=now", "--expire-unreachable=now", "--all"],
                cwd=str(repo_path),
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "gc", "--prune=now", "--aggressive"],
                cwd=str(repo_path),
                check=True,
                capture_output=True,
                text=True,
            )
            with _CACHE_LOCK:
                _SCAN_CACHE.pop(str(repo_path), None)
            self._send_json({"success": True, "message": "All unreferenced objects permanently excised."})
        except subprocess.CalledProcessError as e:
            self._send_error(500, f"Git command failed: {e.stderr or e.stdout}")

    def _handle_git_restore_branch(self, data: dict):
        from gitghost.git_forensics import GitForensics
        from gitghost.recovery import ObjectRecoveryEngine

        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        commit_hash = (data.get("commit_hash") or "").strip()
        branch_name = (data.get("branch_name") or "").strip()
        checkout = bool(data.get("checkout", False))

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        git_dir = _get_effective_git_dir(pipeline_res) if pipeline_res else None
        target_dir = git_dir or Path(repo_path_str).resolve()

        if not GitForensics(target_dir).is_valid_repo():
            self._send_error(400, "Branch restoration requires a valid local repository or active session clone.")
            return

        try:
            res = ObjectRecoveryEngine.restore_commit_as_branch(
                repo_path=target_dir,
                commit_hash=commit_hash,
                branch_name=branch_name,
                checkout=checkout,
            )
            self._send_json(res)
        except ValueError as ve:
            self._send_error(400, str(ve))
        except Exception as exc:
            self._send_error(500, str(exc))

    def _handle_git_cherry_pick(self, data: dict):
        from gitghost.git_forensics import GitForensics
        from gitghost.recovery import ObjectRecoveryEngine

        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        commit_hash = (data.get("commit_hash") or "").strip()
        no_commit = bool(data.get("no_commit", False))

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        git_dir = _get_effective_git_dir(pipeline_res) if pipeline_res else None
        target_dir = git_dir or Path(repo_path_str).resolve()

        if not GitForensics(target_dir).is_valid_repo():
            self._send_error(400, "Cherry-pick requires a valid local repository clone.")
            return

        try:
            res = ObjectRecoveryEngine.cherry_pick_commit(
                repo_path=target_dir,
                commit_hash=commit_hash,
                no_commit=no_commit,
            )
            self._send_json(res)
        except ValueError as ve:
            self._send_error(400, str(ve))
        except Exception as exc:
            self._send_error(500, str(exc))

    def _handle_git_restore_file(self, data: dict):
        from gitghost.recovery import ObjectRecoveryEngine

        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return

        try:
            res = ObjectRecoveryEngine.restore_file_to_disk(
                pipeline_res=pipeline_res,
                object_type=(data.get("object_type") or "file").strip().lower(),
                commit_hash=(data.get("commit_hash") or "").strip(),
                blob_hash=(data.get("blob_hash") or "").strip(),
                file_path=(data.get("file_path") or "").strip(),
                destination_path=(data.get("destination_path") or "").strip() or None,
                include_raw=bool(data.get("include_raw", False)),
                create_backup=bool(data.get("create_backup", True)),
            )
            self._send_json(res)
        except ValueError as ve:
            self._send_error(400, str(ve))
        except Exception as exc:
            self._send_error(500, str(exc))

    def _handle_search(self, data: dict):
        repo_path_str = (data.get("repo_path") or "").strip()
        query = (data.get("query") or "").strip()
        if not query:
            self._send_json({"matches": [], "query": ""})
            return

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return

        q_lower = query.lower()
        matches: List[Dict[str, Any]] = []
        seen_commits = set()

        all_commits = list(pipeline_res.scan_result.dangling_commits) + list(
            getattr(pipeline_res.scan_result, "branch_commits", [])
        )

        for c in all_commits:
            if c.commit_hash in seen_commits:
                continue
            msg_red = c.redacted_message or c.message
            diff_red = c.redacted_diff or ""
            in_meta = (
                q_lower in c.commit_hash.lower()
                or q_lower in (c.author or "").lower()
                or q_lower in msg_red.lower()
                or any(q_lower in fp.lower() for fp in c.changed_files)
            )
            in_diff = q_lower in diff_red.lower()
            if in_meta or in_diff:
                seen_commits.add(c.commit_hash)
                snippet = msg_red.splitlines()[0] if msg_red else ""
                if in_diff:
                    for ln in diff_red.splitlines():
                        if q_lower in ln.lower():
                            snippet = ln[:180]
                            break
                matches.append({
                    "kind": "commit",
                    "is_dangling": getattr(c, "is_dangling", True),
                    "hash": c.commit_hash,
                    "title": (msg_red.splitlines()[0] if msg_red else c.commit_hash[:10]),
                    "subtitle": f"{c.author} • {c.date[:10] if c.date else ''}",
                    "snippet": snippet,
                    "files": c.changed_files,
                })

        for b in pipeline_res.scan_result.dangling_blobs:
            if b.is_binary:
                continue
            red = b.redacted_content or ""
            path_str = b.associated_path or "Detached Blob"
            if q_lower in b.blob_hash.lower() or q_lower in path_str.lower() or q_lower in red.lower():
                snippet = ""
                for ln in red.splitlines():
                    if q_lower in ln.lower():
                        snippet = ln[:180]
                        break
                matches.append({
                    "kind": "blob",
                    "hash": b.blob_hash,
                    "title": path_str,
                    "subtitle": f"Blob {b.blob_hash[:10]} • {b.size} bytes",
                    "snippet": snippet or (red[:140] if red else ""),
                })

        for f in pipeline_res.findings:
            if (
                q_lower in f.rule_name.lower()
                or q_lower in (f.file_path or "").lower()
                or q_lower in f.finding_id.lower()
                or q_lower in (f.context_line or "").lower()
            ):
                matches.append({
                    "kind": "finding",
                    "hash": f.commit_hash or f.blob_hash or "",
                    "finding_id": f.finding_id,
                    "title": f"[{f.finding_id}] {f.rule_name}",
                    "subtitle": f"{f.file_path}:{f.line_number}",
                    "snippet": f.context_line[:180],
                })

        self._send_json({"query": query, "matches": matches[:100]})

    def _build_report_payload(self, pipeline_res: Any, fmt: str) -> tuple[str, str, str]:
        from gitghost.exporters import ReportExporter

        fmt_norm = (fmt or "sarif").lower()
        if fmt_norm == "sarif":
            content = ReportExporter.to_sarif(
                pipeline_res.scan_result, pipeline_res.findings, pipeline_res.triage_map
            )
            return content, "unforce_report.sarif", "application/json; charset=utf-8"
        if fmt_norm == "json":
            content = ReportExporter.to_json(
                pipeline_res.scan_result,
                pipeline_res.findings,
                pipeline_res.triage_map,
                pipeline_res.hygiene,
                pipeline_res.remediation,
            )
            return content, "unforce_report.json", "application/json; charset=utf-8"
        content = ReportExporter.to_markdown(
            pipeline_res.scan_result,
            pipeline_res.findings,
            pipeline_res.triage_map,
            pipeline_res.hygiene,
            pipeline_res.remediation,
        )
        return content, "unforce_report.md", "text/markdown; charset=utf-8"

    def _handle_download_report_get(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        repo_path_str = (params.get("repo_path") or [""])[0]
        fmt = (params.get("format") or ["json"])[0]
        self._handle_download_report({"repo_path": repo_path_str, "format": fmt})

    def _handle_download_report(self, data: dict):
        repo_path_str = (data.get("repo_path") or "").strip()
        fmt = (data.get("format") or "json").lower()
        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return
        content, filename, content_type = self._build_report_payload(pipeline_res, fmt)
        self._send_download(content.encode("utf-8"), filename, content_type)

    def _handle_download_bundle_get(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        repo_path_str = (params.get("repo_path") or [""])[0]
        raw_param = (params.get("include_raw") or ["false"])[0].lower()
        include_raw = raw_param in ("1", "true", "yes")
        self._handle_download_bundle({"repo_path": repo_path_str, "include_raw": include_raw})

    def _handle_download_bundle(self, data: dict):
        from gitghost.recovery import ObjectRecoveryEngine

        repo_path_str = (data.get("repo_path") or "").strip()
        include_raw = bool(data.get("include_raw", False))
        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return
        try:
            zip_bytes = ObjectRecoveryEngine.build_recovery_zip_bundle(
                pipeline_res, include_raw=include_raw
            )
            filename = (
                "unforce_recovery_bundle_raw.zip"
                if include_raw
                else "unforce_recovery_bundle.zip"
            )
            self._send_download(zip_bytes, filename, "application/zip")
        except Exception as exc:
            self._send_error(500, f"Failed to build recovery bundle: {exc}")

    def _handle_recover_file(self, data: dict):
        from gitghost.git_forensics import GitForensics
        from gitghost.pipeline import _scan_unified_diff_by_file
        from gitghost.recovery import ObjectRecoveryEngine
        from gitghost.redactor import SecretRedactor

        repo_path_str = (data.get("repo_path") or "").strip()
        include_raw = bool(data.get("include_raw", False))
        object_type = (data.get("object_type") or "").strip().lower()
        commit_hash = (data.get("commit_hash") or "").strip()
        blob_hash = (data.get("blob_hash") or "").strip()
        file_path = (data.get("file_path") or "").strip()

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return

        artifact_content: Optional[str] = None
        artifact_filename: str = "recovered.txt"
        artifact_redacted: bool = not include_raw
        artifact_source: str = object_type or "file"
        artifact_hash: str = commit_hash or blob_hash

        try:
            if object_type == "blob" or (blob_hash and not commit_hash):
                art = ObjectRecoveryEngine.recover_blob(pipeline_res, blob_hash, include_raw=include_raw)
                artifact_content, artifact_filename, artifact_redacted = art.content, art.filename, art.is_redacted
                artifact_source, artifact_hash, file_path = art.source_type, art.object_hash, art.file_path or file_path
            elif object_type == "diff" or (commit_hash and not file_path and object_type != "file"):
                try:
                    art = ObjectRecoveryEngine.recover_commit_diff(pipeline_res, commit_hash, include_raw=include_raw)
                    artifact_content, artifact_filename, artifact_redacted = art.content, art.filename, art.is_redacted
                    artifact_source, artifact_hash = art.source_type, art.object_hash
                except ValueError:
                    git_dir = _get_effective_git_dir(pipeline_res)
                    if git_dir:
                        raw_d = GitForensics(git_dir).read_commit_diff(commit_hash)
                        if raw_d:
                            artifact_content = (
                                raw_d
                                if include_raw
                                else _scan_unified_diff_by_file(SecretRedactor(), raw_d, "Diff", commit_hash).redacted_text
                            )
                            artifact_filename = f"commit_{commit_hash[:10]}.patch"
                            artifact_source = "commit_diff"
            elif commit_hash:
                # Prefer direct mirror read if available (supports both dangling & historical branch commits)
                git_dir = _get_effective_git_dir(pipeline_res)
                if git_dir and file_path:
                    raw_f = GitForensics(git_dir).read_commit_file(commit_hash, file_path)
                    if raw_f is not None:
                        artifact_content = (
                            raw_f
                            if include_raw
                            else SecretRedactor().scan_and_redact(raw_f, file_path=file_path, commit_hash=commit_hash).redacted_text
                        )
                        base_n = Path(file_path).name or "recovered_file.txt"
                        artifact_filename = base_n
                        artifact_source = "commit_file"

                if artifact_content is None:
                    art = ObjectRecoveryEngine.recover_commit_file(
                        pipeline_res, commit_hash, file_path=file_path or None, include_raw=include_raw
                    )
                    artifact_content, artifact_filename, artifact_redacted = art.content, art.filename, art.is_redacted
                    artifact_source, artifact_hash = art.source_type, art.object_hash
            else:
                self._send_error(400, "Must provide commit_hash or blob_hash for recovery.")
                return
        except ValueError as ve:
            self._send_error(404, str(ve))
            return
        except Exception as exc:
            self._send_error(500, f"Recovery failed: {exc}")
            return

        if artifact_content is None:
            self._send_error(404, "Requested object could not be recovered.")
            return

        if data.get("download"):
            self._send_download(
                artifact_content.encode("utf-8"),
                artifact_filename,
                "text/plain; charset=utf-8",
            )
            return

        self._send_json({
            "success": True,
            "filename": artifact_filename,
            "content": artifact_content,
            "is_redacted": artifact_redacted,
            "source_type": artifact_source,
            "object_hash": artifact_hash,
            "file_path": file_path,
        })

    def _handle_export(self, data: dict):
        from gitghost.github_remote import is_github_target

        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        fmt = (data.get("format", "sarif") or "sarif").lower()

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return

        content, filename, _ = self._build_report_payload(pipeline_res, fmt)
        custom_out = (data.get("output_path") or "").strip()
        if custom_out:
            out_file = Path(custom_out).resolve()
        else:
            target_dir = Path.cwd() if is_github_target(repo_path_str) else Path(repo_path_str).resolve()
            out_file = target_dir / filename
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(content, encoding="utf-8")
        self._send_json({"success": True, "file_path": str(out_file), "filename": out_file.name, "content": content})

    def _handle_hook(self, data: dict):
        from gitghost.exporters import ReportExporter
        from gitghost.github_remote import is_github_target

        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        if is_github_target(repo_path_str):
            self._send_error(400, "Pre-push hook installation applies to local clones.")
            return
        repo_path = Path(repo_path_str).resolve()
        success, hook_path, notice = ReportExporter.install_pre_push_hook(repo_path)
        if success:
            self._send_json({"success": True, "hook_path": hook_path, "notice": notice})
        else:
            self._send_error(400, f"Failed to install pre-push hook: {hook_path}")

    def _handle_verify_key(self, data: dict):
        from gitghost.github_remote import parse_github_url
        from gitghost.liveness import SafeKeyLivenessChecker

        finding_id = str(data.get("finding_id") or "").strip()
        rule_name = str(data.get("rule_name") or "").strip()
        raw_token = str(data.get("raw_token") or "").strip()
        repo_path = str(data.get("repo_path") or "").strip()

        if not raw_token and finding_id:
            with _CACHE_LOCK:
                cached = _SCAN_CACHE.get(repo_path)
                if not cached:
                    gh = parse_github_url(repo_path)
                    if gh:
                        cached = _SCAN_CACHE.get(gh.clone_url) or _SCAN_CACHE.get(gh.html_url)
                if not cached:
                    cached = _SCAN_CACHE.get("__latest__")
                if cached:
                    for f in cached.findings:
                        if f.finding_id == finding_id:
                            rule_name = rule_name or f.rule_name
                            raw_token = f.raw_value or ""
                            break

        if not raw_token:
            self._send_error(400, "Token value could not be resolved. Please scan the repository first.")
            return

        result = SafeKeyLivenessChecker.check(
            token=raw_token,
            rule_name=rule_name,
            finding_id=finding_id,
        )
        self._send_json(result.to_dict())


def start_ui_server(host: str = "127.0.0.1", start_port: int = 8765) -> tuple[ThreadingHTTPServer, int]:
    """Starts the UnForce UI HTTP server on the requested or first available port (start_port=0 for OS-assigned)."""
    if start_port == 0:
        server = ThreadingHTTPServer((host, 0), GitGhostRequestHandler)
        bound_port = int(server.server_address[1])
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        return server, bound_port

    port = start_port
    while port < start_port + 30:
        try:
            server = ThreadingHTTPServer((host, port), GitGhostRequestHandler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            return server, port
        except OSError:
            port += 1
    raise RuntimeError(f"Could not bind UI server to any port between {start_port} and {port}")
