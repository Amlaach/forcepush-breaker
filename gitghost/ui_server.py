"""
UI Server and REST API backend for GitGhost Interactive Dashboard.
Provides standard HTTP endpoints using Python's standard library http.server.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

from gitghost import __version__
from gitghost.git_forensics import GitForensics, ForensicsScanResult
from gitghost.redactor import SecretRedactor, SecretFinding
from gitghost.ai_triage import AITriage, AITriageResult
from gitghost.scoring import HygieneScorer, HygieneScoreReport
from gitghost.remediation import RemediationGenerator, RemediationPlan
from gitghost.exporters import ReportExporter
from gitghost.ui_assets import HTML_PAGE


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

        # 1. Object Forensics Scan
        scan_res = forensics.scan()

        # 2. Secret Redaction & Shannon Entropy Sweep
        redactor = SecretRedactor(entropy_threshold=entropy_thresh)
        all_findings: list[SecretFinding] = []

        for c in scan_res.dangling_commits:
            msg_res = redactor.scan_and_redact(c.message, file_path="[Commit Message]", commit_hash=c.commit_hash)
            all_findings.extend(msg_res.findings)
            diff_res = redactor.scan_and_redact(
                c.diff_content,
                file_path=c.changed_files[0] if c.changed_files else "Diff",
                commit_hash=c.commit_hash,
            )
            all_findings.extend(diff_res.findings)

        for b in scan_res.dangling_blobs:
            if not b.is_binary:
                blob_res = redactor.scan_and_redact(
                    b.content,
                    file_path=b.associated_path or "Detached Blob",
                    blob_hash=b.blob_hash,
                )
                all_findings.extend(blob_res.findings)

        # 3. AI Triage
        triage_map: dict[str, AITriageResult] = {}
        if ai_provider != "none" and all_findings:
            triage_engine = AITriage(provider=ai_provider)
            for f in all_findings:
                matched_c = next((c for c in scan_res.dangling_commits if c.commit_hash == f.commit_hash), None)
                verdict = triage_engine.triage_finding(
                    finding_rule=f.rule_name,
                    masked_snippet=f.masked_value,
                    context_line=f.context_line,
                    commit_message=matched_c.message if matched_c else None,
                    author=matched_c.author if matched_c else None,
                    file_path=f.file_path,
                )
                triage_map[f.finding_id] = verdict

        # 4. Hygiene Scoring
        commit_dates = [c.date for c in scan_res.dangling_commits if c.date]
        hygiene = HygieneScorer.calculate(
            dangling_commits_count=len(scan_res.dangling_commits),
            dangling_blobs_count=len(scan_res.dangling_blobs),
            findings=all_findings,
            triage_results=triage_map,
            commit_dates=commit_dates,
        )

        # 5. Remediation Playbook
        remediation = RemediationGenerator.generate_plan(
            repo_path=str(repo_path),
            findings=all_findings,
            dangling_commits_count=len(scan_res.dangling_commits),
            dangling_blobs_count=len(scan_res.dangling_blobs),
        )

        # Format response payload
        findings_payload = []
        for f in all_findings:
            t = triage_map.get(f.finding_id)
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
            for c in scan_res.dangling_commits
        ]

        blobs_payload = [
            {
                "blob_hash": b.blob_hash,
                "size": b.size,
                "is_binary": b.is_binary,
                "associated_path": b.associated_path,
            }
            for b in scan_res.dangling_blobs
        ]

        hygiene_payload = {
            "score": hygiene.score,
            "grade": hygiene.grade,
            "color": hygiene.color,
            "summary": hygiene.summary,
            "critical_findings_count": hygiene.critical_findings_count,
            "high_findings_count": hygiene.high_findings_count,
            "medium_findings_count": hygiene.medium_findings_count,
            "low_findings_count": hygiene.low_findings_count,
            "false_positives_count": hygiene.false_positives_count,
            "deductions": [
                {"category": d.category, "points": d.points, "reason": d.reason}
                for d in hygiene.deductions
            ],
        }

        remediation_payload = {
            "rotation_warning": remediation.rotation_warning,
            "steps": [
                {
                    "order": s.order,
                    "title": s.title,
                    "description": s.description,
                    "commands": s.commands,
                }
                for s in remediation.steps
            ],
        }

        self._send_json({
            "repo_path": str(repo_path),
            "total_objects_scanned": scan_res.total_objects_scanned,
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
            self._send_json({"success": True, "message": "All unreferenced objects permanently excised."})
        except subprocess.CalledProcessError as e:
            self._send_error(500, f"Git command failed: {e.stderr or e.stdout}")

    def _handle_export(self, data: dict):
        repo_path_str = data.get("repo_path", ".").strip() or "."
        repo_path = Path(repo_path_str).resolve()
        fmt = (data.get("format", "sarif") or "sarif").lower()

        forensics = GitForensics(repo_path)
        scan_res = forensics.scan()
        redactor = SecretRedactor()
        findings: list[SecretFinding] = []
        for c in scan_res.dangling_commits:
            diff_res = redactor.scan_and_redact(c.diff_content, file_path=c.changed_files[0] if c.changed_files else "Diff", commit_hash=c.commit_hash)
            findings.extend(diff_res.findings)

        triage_engine = AITriage(provider="heuristic")
        triage_map = {
            f.finding_id: triage_engine.triage_finding(f.rule_name, f.masked_value, f.context_line, file_path=f.file_path)
            for f in findings
        }
        hygiene = HygieneScorer.calculate(len(scan_res.dangling_commits), len(scan_res.dangling_blobs), findings, triage_map)
        remediation = RemediationGenerator.generate_plan(str(repo_path), findings)

        if fmt == "sarif":
            out_file = repo_path / "gitghost_report.sarif"
            out_file.write_text(ReportExporter.to_sarif(scan_res, findings, triage_map), encoding="utf-8")
        elif fmt == "json":
            out_file = repo_path / "gitghost_report.json"
            out_file.write_text(ReportExporter.to_json(scan_res, findings, triage_map, hygiene, remediation), encoding="utf-8")
        else:
            out_file = repo_path / "gitghost_report.md"
            out_file.write_text(ReportExporter.to_markdown(scan_res, findings, triage_map, hygiene, remediation), encoding="utf-8")

        self._send_json({"success": True, "file_path": str(out_file)})

    def _handle_hook(self, data: dict):
        repo_path_str = data.get("repo_path", ".").strip() or "."
        repo_path = Path(repo_path_str).resolve()
        success, hook_path = ReportExporter.install_pre_push_hook(repo_path)
        if success:
            self._send_json({"success": True, "hook_path": hook_path})
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
