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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict

from gitghost import __version__
from gitghost.exporters import ReportExporter
from gitghost.git_forensics import GitForensics
from gitghost.pipeline import PipelineResult, run_scan_pipeline
from gitghost.ui_assets import HTML_PAGE

# Thread-safe server-side cache for full pipeline scan results
_SCAN_CACHE: Dict[str, PipelineResult] = {}


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
        elif self.path == "/api/scan":
            self._handle_scan(data)
        elif self.path == "/api/cleanup":
            self._handle_cleanup(data)
        elif self.path == "/api/export":
            self._handle_export(data)
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

    def _handle_scan(self, data: dict):
        if not shutil.which("git"):
            self._send_error(500, "Git executable not found in system PATH. Git is required to perform forensics.")
            return

        repo_path_str = data.get("repo_path", ".").strip() or "."
        repo_path = Path(repo_path_str).resolve()

        if not repo_path.exists():
            self._send_error(400, f"Path does not exist: {repo_path}")
            return

        forensics = GitForensics(repo_path)
        if not forensics.is_valid_repo():
            self._send_error(400, f"'{repo_path}' is not a valid Git repository (.git directory missing).")
            return

        ai_provider = data.get("ai_provider", "heuristic")
        entropy_thresh = float(data.get("entropy_threshold", 4.0))

        # Run unified full scan pipeline
        pipeline_res = run_scan_pipeline(
            repo_path=repo_path,
            ai_provider=ai_provider,
            entropy_threshold=entropy_thresh,
        )

        # Cache result in memory for seamless export
        _SCAN_CACHE[str(repo_path)] = pipeline_res

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
                "entropy": round(f.entropy, 2),
                "file_path": f.file_path,
                "commit_hash": f.commit_hash,
                "blob_hash": f.blob_hash,
                "triage_severity": t.severity if t else f.severity_estimate,
                "is_false_positive": t.is_false_positive if t else False,
                "triage_risk_score": t.risk_score if t else None,
                "triage_explanation": t.technical_explanation if t else None,
                "triage_action": t.recommended_action if t else None,
            })

        commits_payload = [
            {
                "commit_hash": c.commit_hash,
                "author": c.author,
                "date": c.date,
                "message": c.message,
                "changed_files": c.changed_files,
            }
            for c in pipeline_res.scan_result.dangling_commits
        ]

        blobs_payload = [
            {
                "blob_hash": b.blob_hash,
                "size": b.size,
                "is_binary": b.is_binary,
                "associated_path": b.associated_path,
            }
            for b in pipeline_res.scan_result.dangling_blobs
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

        self._send_json({
            "repo_path": str(repo_path),
            "total_objects_scanned": pipeline_res.scan_result.total_objects_scanned,
            "dangling_commits": commits_payload,
            "dangling_blobs": blobs_payload,
            "findings": findings_payload,
            "hygiene_score": hygiene_payload,
            "remediation": remediation_payload,
        })

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

    def _handle_export(self, data: dict):
        repo_path_str = data.get("repo_path", ".").strip() or "."
        repo_path = Path(repo_path_str).resolve()
        fmt = (data.get("format", "sarif") or "sarif").lower()

        # Use full cached pipeline result if available, or run unified scan pipeline
        cached = _SCAN_CACHE.get(str(repo_path))
        if cached:
            pipeline_res = cached
        else:
            pipeline_res = run_scan_pipeline(repo_path, ai_provider="heuristic")
            _SCAN_CACHE[str(repo_path)] = pipeline_res

        if fmt == "sarif":
            out_file = repo_path / "gitghost_report.sarif"
            content = ReportExporter.to_sarif(
                pipeline_res.scan_result, pipeline_res.findings, pipeline_res.triage_map
            )
        elif fmt == "json":
            out_file = repo_path / "gitghost_report.json"
            content = ReportExporter.to_json(
                pipeline_res.scan_result,
                pipeline_res.findings,
                pipeline_res.triage_map,
                pipeline_res.hygiene,
                pipeline_res.remediation,
            )
        else:
            out_file = repo_path / "gitghost_report.md"
            content = ReportExporter.to_markdown(
                pipeline_res.scan_result,
                pipeline_res.findings,
                pipeline_res.triage_map,
                pipeline_res.hygiene,
                pipeline_res.remediation,
            )

        out_file.write_text(content, encoding="utf-8")
        self._send_json({"success": True, "file_path": str(out_file)})

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
