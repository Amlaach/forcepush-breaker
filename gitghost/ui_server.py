"""
UI Server and REST API backend for GitGhost Interactive Dashboard.
Provides standard HTTP endpoints using Python's standard library http.server.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import urllib.parse
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from gitghost import __version__
from gitghost.exporters import ReportExporter
from gitghost.git_forensics import ForensicsScanResult, GitForensics
from gitghost.github_remote import is_github_target, sanitize_token_in_text
from gitghost.pipeline import PipelineResult, run_scan_pipeline
from gitghost.recovery import ObjectRecoveryEngine
from gitghost.ui_assets import HTML_PAGE

# Thread-safe server-side cache for full pipeline scan results
_SCAN_CACHE: Dict[str, PipelineResult] = {}
_CACHE_LOCK = threading.Lock()


@dataclass
class ScanJob:
    job_id: str
    repo_target: str
    status: str = "queued"  # "queued" | "running" | "completed" | "failed"
    progress_pct: int = 0
    phase_message: str = "Initializing forensics scan..."
    scanned_objects: int = 0
    total_objects: int = 0
    error: Optional[str] = None
    result: Optional[PipelineResult] = None


class ScanJobManager:
    """Manages asynchronous background repository scans with real-time progress and memory bounds."""

    MAX_JOBS = 25
    _jobs: Dict[str, ScanJob] = {}
    _lock = threading.Lock()

    @classmethod
    def start_job(
        cls,
        repo_target: str,
        ai_provider: str = "heuristic",
        entropy_threshold: float = 4.0,
        github_token: Optional[str] = None,
        clone_source_override: Optional[str] = None,
    ) -> ScanJob:
        job_id = uuid.uuid4().hex[:12]
        job = ScanJob(job_id=job_id, repo_target=repo_target, status="running", progress_pct=5)

        with cls._lock:
            if len(cls._jobs) >= cls.MAX_JOBS:
                oldest_key = next(iter(cls._jobs))
                cls._jobs.pop(oldest_key, None)
            cls._jobs[job_id] = job

        # Ephemeral token passed only into worker closure; never stored on ScanJob
        ephemeral_token = (github_token or "").strip() or None

        def _worker():
            try:
                def on_phase(msg: str, pct: int):
                    job.phase_message = msg
                    job.progress_pct = max(job.progress_pct, min(99, pct))

                def on_forensics_done(scan_res: ForensicsScanResult):
                    total = len(scan_res.dangling_commits) + len(scan_res.dangling_blobs)
                    job.total_objects = total
                    job.phase_message = f"Scanning {total} unreachable objects for secrets..."
                    job.progress_pct = max(job.progress_pct, 60)

                def on_item_scanned(current: int, total: int):
                    job.scanned_objects = current
                    job.total_objects = total
                    if total > 0:
                        ratio = current / total
                        job.progress_pct = min(90, 60 + int(ratio * 25))

                pipeline_res = run_scan_pipeline(
                    repo_path=repo_target,
                    ai_provider=ai_provider,
                    entropy_threshold=entropy_threshold,
                    github_token=ephemeral_token,
                    clone_source_override=clone_source_override,
                    on_forensics_done=on_forensics_done,
                    on_item_scanned=on_item_scanned,
                    on_phase=on_phase,
                )

                with _CACHE_LOCK:
                    _SCAN_CACHE[pipeline_res.repo_path] = pipeline_res
                    _SCAN_CACHE[repo_target] = pipeline_res
                    _SCAN_CACHE["__latest__"] = pipeline_res

                job.result = pipeline_res
                job.progress_pct = 100
                job.phase_message = "Forensics audit completed."
                job.status = "completed"
            except Exception as exc:
                job.error = sanitize_token_in_text(str(exc), ephemeral_token)
                job.phase_message = "Scan failed."
                job.status = "failed"

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return job

    @classmethod
    def get_job(cls, job_id: str) -> Optional[ScanJob]:
        with cls._lock:
            return cls._jobs.get(job_id)



class GitGhostRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for the GitGhost dashboard UI and REST API."""

    def log_message(self, format, *args):
        # Silence access logs to keep terminal output clean
        pass

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send_html(HTML_PAGE)
        elif self.path == "/api/status":
            self._send_json({"status": "ok", "version": __version__, "app": "GitGhost"})
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

        if self.path == "/api/browse":
            self._handle_browse()
        elif self.path == "/api/scan/start":
            self._handle_scan_start(data)
        elif self.path == "/api/scan":
            self._handle_scan(data)
        elif self.path == "/api/cleanup":
            self._handle_cleanup(data)
        elif self.path == "/api/export":
            self._handle_export(data)
        elif self.path == "/api/download/report":
            self._handle_download_report(data)
        elif self.path == "/api/download/bundle":
            self._handle_download_bundle(data)
        elif self.path == "/api/recover/file":
            self._handle_recover_file(data)
        elif self.path == "/api/hook":
            self._handle_hook(data)
        else:
            self._send_error(404, "Endpoint Not Found")

    def _send_html(self, html: str):
        content = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
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
        content = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def _send_error(self, status: int, message: str):
        self._send_json({"error": message, "status": status}, status=status)

    def _handle_browse(self):
        """Invoke native folder picker dialog."""
        folder = None
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.wm_attributes("-topmost", 1)
            folder = filedialog.askdirectory(title="Select Git Repository Folder")
            root.destroy()
        except Exception:
            # Fallback to PowerShell FolderBrowserDialog on Windows
            if sys.platform == "win32":
                try:
                    cmd = (
                        "Add-Type -AssemblyName System.Windows.Forms; "
                        "$fb = New-Object System.Windows.Forms.FolderBrowserDialog; "
                        "$fb.Description = 'Select Git Repository'; "
                        "if ($fb.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $fb.SelectedPath }"
                    )
                    out = subprocess.check_output(["powershell", "-Command", cmd], text=True).strip()
                    if out:
                        folder = out
                except Exception:
                    pass

        self._send_json({"folder": folder or ""})

    def _validate_target_or_error(self, repo_path_str: str) -> Optional[str]:
        if not shutil.which("git"):
            self._send_error(500, "Git executable not found in system PATH. Git is required to perform forensics.")
            return None
        if is_github_target(repo_path_str):
            return repo_path_str
        repo_path = Path(repo_path_str).resolve()
        if not repo_path.exists():
            self._send_error(400, f"Path does not exist: {repo_path}")
            return None
        forensics = GitForensics(repo_path)
        if not forensics.is_valid_repo():
            self._send_error(400, f"'{repo_path}' is not a valid Git repository (.git directory missing).")
            return None
        return str(repo_path)

    def _handle_scan_start(self, data: dict):
        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        validated = self._validate_target_or_error(repo_path_str)
        if validated is None:
            return

        ai_provider = data.get("ai_provider", "heuristic")
        entropy_thresh = float(data.get("entropy_threshold", 4.0))
        github_token = data.get("github_token")
        clone_override = data.get("clone_source_override")

        job = ScanJobManager.start_job(
            repo_target=validated,
            ai_provider=ai_provider,
            entropy_threshold=entropy_thresh,
            github_token=github_token,
            clone_source_override=clone_override,
        )
        self._send_json({
            "job_id": job.job_id,
            "status": job.status,
            "progress_pct": job.progress_pct,
            "phase_message": job.phase_message,
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
            "scanned_objects": job.scanned_objects,
            "total_objects": job.total_objects,
            "error": job.error,
        }
        if job.status == "completed" and job.result is not None:
            resp["result"] = self._serialize_pipeline_result(job.result)
        self._send_json(resp)

    def _handle_scan(self, data: dict):
        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        validated = self._validate_target_or_error(repo_path_str)
        if validated is None:
            return

        ai_provider = data.get("ai_provider", "heuristic")
        entropy_thresh = float(data.get("entropy_threshold", 4.0))
        github_token = data.get("github_token")
        clone_override = data.get("clone_source_override")

        try:
            pipeline_res = run_scan_pipeline(
                repo_path=validated,
                ai_provider=ai_provider,
                entropy_threshold=entropy_thresh,
                github_token=github_token,
                clone_source_override=clone_override,
            )
        except Exception as exc:
            self._send_error(500, sanitize_token_in_text(str(exc), github_token))
            return

        with _CACHE_LOCK:
            _SCAN_CACHE[pipeline_res.repo_path] = pipeline_res
            _SCAN_CACHE[validated] = pipeline_res
            _SCAN_CACHE["__latest__"] = pipeline_res

        self._send_json(self._serialize_pipeline_result(pipeline_res))

    def _serialize_pipeline_result(self, pipeline_res: PipelineResult) -> dict:
        # Format response payload
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
                "is_ai_agent": getattr(f, "is_ai_agent", False),
                "ai_agent_name": getattr(f, "ai_agent_name", None),
                "ai_agent_evidence": getattr(f, "ai_agent_evidence", []),
            })

        commits_payload = [
            {
                "commit_hash": c.commit_hash,
                "author": c.author,
                "date": c.date,
                "message": c.redacted_message or c.message,
                "changed_files": c.changed_files,
                "redacted_diff": c.redacted_diff,
                "is_ai_agent": c.ai_agent.is_ai_agent if c.ai_agent else False,
                "ai_agent_name": c.ai_agent.agent_name if c.ai_agent else None,
                "ai_agent_evidence": c.ai_agent.evidence if c.ai_agent else [],
            }
            for c in pipeline_res.scan_result.dangling_commits
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

        return {
            "repo_path": pipeline_res.repo_path,
            "is_remote": pipeline_res.is_remote,
            "remote_url": pipeline_res.remote_url,
            "total_objects_scanned": pipeline_res.scan_result.total_objects_scanned,
            "dangling_commits": commits_payload,
            "dangling_blobs": blobs_payload,
            "deleted_config_files": config_files_payload,
            "history_events": history_events_payload,
            "findings": findings_payload,
            "hygiene_score": hygiene_payload,
            "remediation": remediation_payload,
        }

    def _handle_cleanup(self, data: dict):
        repo_path_str = data.get("repo_path", ".").strip() or "."
        repo_path = Path(repo_path_str).resolve()
        if not (repo_path / ".git").exists():
            self._send_error(400, "Target is not a valid Git repository.")
            return

        try:
            subprocess.run(
                ["git", "reflog", "expire", "--expire=now", "--all"],
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
            # Invalidate cached scan for this repository
            _SCAN_CACHE.pop(str(repo_path), None)
            self._send_json({"success": True, "message": "All unreferenced objects permanently excised."})
        except subprocess.CalledProcessError as e:
            self._send_error(500, f"Git command failed: {e.stderr or e.stdout}")

    def _resolve_pipeline_result(self, repo_path_str: str) -> Optional[PipelineResult]:
        target = (repo_path_str or "").strip()
        with _CACHE_LOCK:
            if target and target in _SCAN_CACHE:
                return _SCAN_CACHE[target]
            if target and not is_github_target(target):
                resolved = str(Path(target).resolve())
                if resolved in _SCAN_CACHE:
                    return _SCAN_CACHE[resolved]
            if "__latest__" in _SCAN_CACHE and not target:
                return _SCAN_CACHE["__latest__"]

        validated = self._validate_target_or_error(target or ".")
        if validated is None:
            return None
        try:
            pipeline_res = run_scan_pipeline(validated, ai_provider="heuristic")
            with _CACHE_LOCK:
                _SCAN_CACHE[pipeline_res.repo_path] = pipeline_res
                _SCAN_CACHE[validated] = pipeline_res
                _SCAN_CACHE["__latest__"] = pipeline_res
            return pipeline_res
        except Exception as exc:
            self._send_error(500, str(exc))
            return None

    def _build_report_payload(self, pipeline_res: PipelineResult, fmt: str) -> tuple[str, str, str]:
        fmt_norm = (fmt or "sarif").lower()
        if fmt_norm == "sarif":
            content = ReportExporter.to_sarif(
                pipeline_res.scan_result, pipeline_res.findings, pipeline_res.triage_map
            )
            return content, "gitghost_report.sarif", "application/json; charset=utf-8"
        if fmt_norm == "json":
            content = ReportExporter.to_json(
                pipeline_res.scan_result,
                pipeline_res.findings,
                pipeline_res.triage_map,
                pipeline_res.hygiene,
                pipeline_res.remediation,
            )
            return content, "gitghost_report.json", "application/json; charset=utf-8"
        content = ReportExporter.to_markdown(
            pipeline_res.scan_result,
            pipeline_res.findings,
            pipeline_res.triage_map,
            pipeline_res.hygiene,
            pipeline_res.remediation,
        )
        return content, "gitghost_report.md", "text/markdown; charset=utf-8"

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
                "gitghost_recovery_bundle_raw.zip"
                if include_raw
                else "gitghost_recovery_bundle.zip"
            )
            self._send_download(zip_bytes, filename, "application/zip")
        except Exception as exc:
            self._send_error(500, f"Failed to build recovery bundle: {exc}")

    def _handle_recover_file(self, data: dict):
        repo_path_str = (data.get("repo_path") or "").strip()
        include_raw = bool(data.get("include_raw", False))
        object_type = (data.get("object_type") or "").strip().lower()
        commit_hash = (data.get("commit_hash") or "").strip()
        blob_hash = (data.get("blob_hash") or "").strip()
        file_path = (data.get("file_path") or "").strip()

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return

        try:
            if object_type == "blob" or (blob_hash and not commit_hash):
                artifact = ObjectRecoveryEngine.recover_blob(
                    pipeline_res, blob_hash, include_raw=include_raw
                )
            elif object_type == "diff" or (commit_hash and not file_path and object_type != "file"):
                artifact = ObjectRecoveryEngine.recover_commit_diff(
                    pipeline_res, commit_hash, include_raw=include_raw
                )
            elif commit_hash:
                artifact = ObjectRecoveryEngine.recover_commit_file(
                    pipeline_res,
                    commit_hash,
                    file_path=file_path or None,
                    include_raw=include_raw,
                )
            else:
                self._send_error(400, "Must provide commit_hash or blob_hash for recovery.")
                return
        except ValueError as ve:
            self._send_error(404, str(ve))
            return
        except Exception as exc:
            self._send_error(500, f"Recovery failed: {exc}")
            return

        if data.get("download"):
            self._send_download(
                artifact.content.encode("utf-8"),
                artifact.filename,
                "text/plain; charset=utf-8",
            )
            return

        self._send_json({
            "success": True,
            "filename": artifact.filename,
            "content": artifact.content,
            "is_redacted": artifact.is_redacted,
            "source_type": artifact.source_type,
            "object_hash": artifact.object_hash,
            "file_path": artifact.file_path,
        })

    def _handle_export(self, data: dict):
        repo_path_str = (data.get("repo_path") or ".").strip() or "."
        fmt = (data.get("format", "sarif") or "sarif").lower()

        pipeline_res = self._resolve_pipeline_result(repo_path_str)
        if pipeline_res is None:
            return

        content, filename, _ = self._build_report_payload(pipeline_res, fmt)
        target_dir = Path.cwd() if is_github_target(repo_path_str) else Path(repo_path_str).resolve()
        out_file = target_dir / filename
        out_file.write_text(content, encoding="utf-8")
        self._send_json({"success": True, "file_path": str(out_file), "filename": filename, "content": content})

    def _handle_hook(self, data: dict):
        repo_path_str = data.get("repo_path", ".").strip() or "."
        repo_path = Path(repo_path_str).resolve()
        success, hook_path, notice = ReportExporter.install_pre_push_hook(repo_path)
        if success:
            self._send_json({"success": True, "hook_path": hook_path, "notice": notice})
        else:
            self._send_error(400, f"Failed to install pre-push hook: {hook_path}")


def start_ui_server(host: str = "127.0.0.1", start_port: int = 8765) -> tuple[ThreadingHTTPServer, int]:
    """Starts the GitGhost UI HTTP server on the first available port."""
    port = start_port
    while port < start_port + 20:
        try:
            server = ThreadingHTTPServer((host, port), GitGhostRequestHandler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            return server, port
        except OSError:
            port += 1
    raise RuntimeError(f"Could not bind UI server to any port between {start_port} and {port}")
