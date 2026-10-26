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
    from gitghost.github_remote import parse_github_url

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
        from gitghost.github_remote import is_github_target

        if not shutil.which("git"):
            self._send_error(500, "Git executable not found in system PATH. Install Git to scan repositories.")
            return None
        if is_github_target(repo_path_str):
            return repo_path_str
        repo_path = Path(repo_path_str).resolve()
        if not repo_path.exists():
            self._send_error(
                400,
                f"Invalid GitHub repository URL: '{repo_path_str}'. Paste a valid GitHub link (e.g. https://github.com/owner/repo).",
            )
            return None
        forensics = GitForensics(repo_path)
        if not forensics.is_valid_repo():
            self._send_error(
                400,
                f"Invalid GitHub repository URL: '{repo_path_str}'. Paste a GitHub URL like https://github.com/owner/repo.",
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
