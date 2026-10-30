"""
Model Context Protocol (MCP) Server for UnForce (ForcePush-Breaker).

Enables AI agents such as Claude Code, Antigravity, OpenAI Codex, Cursor,
and Windsurf to connect directly to UnForce over standard JSON-RPC 2.0 stdio
and invoke git forensics, commit recovery, secret hunting, and remediation tools.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from gitghost import BRAND_NAME, BRAND_SHORT, __version__
from gitghost.git_forensics import GitForensics
from gitghost.liveness import SafeKeyLivenessChecker
from gitghost.pipeline import PipelineResult, run_scan_pipeline
from gitghost.recovery import ObjectRecoveryEngine


MCP_PROTOCOL_VERSION = "2024-11-05"

MCP_TOOLS = [
    {
        "name": "unforce_scan",
        "description": "Performs a complete Git object database forensics scan on a local repository or remote GitHub/GitLab/Bitbucket URL. Discovers dangling commits, deleted .env config files, detached blobs, and scans for leaked credentials with Shannon entropy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {
                    "type": "string",
                    "description": "Local repository directory path or remote URL (e.g. '.' or 'https://github.com/owner/repo'). Defaults to current directory.",
                },
                "entropy_threshold": {
                    "type": "number",
                    "description": "Shannon entropy sensitivity threshold (default 4.0, range 2.0-8.0).",
                },
                "scan_forks": {
                    "type": "boolean",
                    "description": "Whether to audit public forks for divergent/overwritten commits (remote scans).",
                },
            },
        },
    },
    {
        "name": "unforce_list_dangling_commits",
        "description": "Lists all dangling (orphaned / force-pushed over) commits found in the repository's git object database with author, timestamp, commit message, and changed files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {
                    "type": "string",
                    "description": "Optional repository path (uses active/latest scan if omitted).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of dangling commits to return (default 20).",
                },
            },
        },
    },
    {
        "name": "unforce_get_commit_diff",
        "description": "Retrieves the unified diff (patch) of a specific dangling commit SHA to inspect what code or credentials were overwritten.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "commit_hash": {
                    "type": "string",
                    "description": "The commit hash (full or prefix).",
                },
                "repo_path": {
                    "type": "string",
                    "description": "Optional repository path.",
                },
                "include_raw": {
                    "type": "boolean",
                    "description": "Whether to return unredacted raw diff (default false: secrets are masked).",
                },
            },
            "required": ["commit_hash"],
        },
    },
    {
        "name": "unforce_recover_file",
        "description": "Recovers a specific file snapshot or patch from an orphaned commit or detached blob and saves it to disk or returns its content.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "commit_hash": {"type": "string", "description": "The commit SHA hash."},
                "file_path": {"type": "string", "description": "The relative file path within the commit."},
                "destination_path": {"type": "string", "description": "Optional local file path to write recovered content."},
                "include_raw": {"type": "boolean", "description": "Whether to extract unredacted content (default false)."},
                "repo_path": {"type": "string", "description": "Optional repository path."},
            },
            "required": ["commit_hash"],
        },
    },
    {
        "name": "unforce_check_liveness",
        "description": "Safely verifies whether a detected API key or token finding is still live/active in production against provider cloud APIs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding ID from scan results (e.g. 'SEC-0001')."},
                "repo_path": {"type": "string", "description": "Optional repository path."},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "unforce_hygiene_report",
        "description": "Returns the holistic 0-100 repository hygiene score, letter grade (A+ to F), deductions breakdown, and threat recency assessment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Optional repository path."},
            },
        },
    },
    {
        "name": "unforce_remediation_plan",
        "description": "Generates a customized history excision plan, including precise git-filter-repo and git gc prune commands, and a GitHub Support cache purge ticket.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Optional repository path."},
                "format": {"type": "string", "description": "'bash' or 'powershell' (default 'bash')."},
            },
        },
    },
]


class MCPServer:
    """Standard Model Context Protocol stdio server."""

    def __init__(self):
        self._cached_results: Dict[str, PipelineResult] = {}
        self._latest_target: Optional[str] = None

    def _resolve_result(self, repo_path: Optional[str] = None) -> PipelineResult:
        target = (repo_path or self._latest_target or ".").strip() or "."
        if target in self._cached_results:
            return self._cached_results[target]

        res = run_scan_pipeline(target, ai_provider="none", keep_remote_workspace=True)
        self._cached_results[target] = res
        self._latest_target = target
        return res

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                    },
                    "serverInfo": {
                        "name": "unforce-mcp-server",
                        "version": __version__,
                        "brand": f"{BRAND_NAME} ({BRAND_SHORT})",
                    },
                },
            }

        elif method == "notifications/initialized":
            return None

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": MCP_TOOLS},
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments") or {}
            try:
                out_text = self._dispatch_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": out_text}],
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error executing {tool_name}: {exc}"}],
                        "isError": True,
                    },
                }

        elif method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "resources": [
                        {
                            "uri": "unforce://scan/latest.json",
                            "name": "Latest UnForce Forensics Scan JSON",
                            "mimeType": "application/json",
                        },
                    ]
                },
            }

        elif method == "resources/read":
            uri = params.get("uri")
            if uri == "unforce://scan/latest.json" and self._latest_target:
                res = self._resolve_result(self._latest_target)
                from gitghost.exporters import ReportExporter
                json_data = ReportExporter.to_json(res.scan_result, res.findings, res.triage_map, res.hygiene, res.remediation)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "contents": [{"uri": uri, "mimeType": "application/json", "text": json_data}],
                    },
                }
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": f"Resource not found: {uri}"},
            }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def _dispatch_tool(self, name: str, args: Dict[str, Any]) -> str:
        repo_path = args.get("repo_path")

        if name == "unforce_scan":
            target = (repo_path or ".").strip() or "."
            thresh = float(args.get("entropy_threshold") or 4.0)
            scan_forks = bool(args.get("scan_forks", True))
            pipeline_res = run_scan_pipeline(
                target,
                ai_provider="none",
                entropy_threshold=thresh,
                scan_forks=scan_forks,
                keep_remote_workspace=True,
            )
            self._cached_results[target] = pipeline_res
            self._latest_target = target

            summary = {
                "repository": pipeline_res.repo_path,
                "is_remote": pipeline_res.is_remote,
                "hygiene_score": pipeline_res.hygiene.score,
                "hygiene_grade": pipeline_res.hygiene.grade,
                "dangling_commits_count": len(pipeline_res.scan_result.dangling_commits),
                "dangling_blobs_count": len(pipeline_res.scan_result.dangling_blobs),
                "deleted_config_files_count": len(getattr(pipeline_res.scan_result, "deleted_config_files", [])),
                "findings_count": len(pipeline_res.findings),
                "critical_findings": pipeline_res.hygiene.critical_findings_count,
                "high_findings": pipeline_res.hygiene.high_findings_count,
            }
            return json.dumps(summary, indent=2)

        res = self._resolve_result(repo_path)

        if name == "unforce_list_dangling_commits":
            limit = int(args.get("limit") or 20)
            commits = [
                {
                    "commit_hash": c.commit_hash,
                    "author": c.author,
                    "date": c.date,
                    "message": (c.redacted_message or c.message).splitlines()[0] if c.message else "",
                    "changed_files": c.changed_files,
                    "ai_agent": c.ai_agent.agent_name if (c.ai_agent and c.ai_agent.is_ai_agent) else None,
                }
                for c in res.scan_result.dangling_commits[:limit]
            ]
            return json.dumps(commits, indent=2)

        elif name == "unforce_get_commit_diff":
            c_hash = str(args.get("commit_hash") or "").strip()
            raw = bool(args.get("include_raw", False))
            for c in res.scan_result.dangling_commits:
                if c.commit_hash == c_hash or c.commit_hash.startswith(c_hash):
                    diff = c.diff_content if raw else (c.redacted_diff or c.diff_content)
                    return diff or "(Empty diff)"
            raise ValueError(f"Dangling commit not found: {c_hash}")

        elif name == "unforce_recover_file":
            c_hash = str(args.get("commit_hash") or "").strip()
            fpath = str(args.get("file_path") or "").strip()
            dest = str(args.get("destination_path") or "").strip() or None
            raw = bool(args.get("include_raw", False))

            if dest:
                rec_res = ObjectRecoveryEngine.restore_file_to_disk(
                    pipeline_res=res,
                    object_type="commit_file",
                    commit_hash=c_hash,
                    file_path=fpath,
                    destination_path=dest,
                    include_raw=raw,
                )
                return json.dumps(rec_res, indent=2)

            art = ObjectRecoveryEngine.recover_commit_file(res, c_hash, file_path=fpath or None, include_raw=raw)
            return art.content

        elif name == "unforce_check_liveness":
            fid = str(args.get("finding_id") or "").strip()
            f = next((x for x in res.findings if x.finding_id == fid), None)
            if not f or not f.raw_value:
                raise ValueError(f"Finding {fid} not found or secret unavailable.")
            res_live = SafeKeyLivenessChecker.check(token=f.raw_value, rule_name=f.rule_name, finding_id=fid)
            return json.dumps(res_live.to_dict(), indent=2)

        elif name == "unforce_hygiene_report":
            h = res.hygiene
            payload = {
                "score": h.score,
                "grade": h.grade,
                "color": h.color,
                "summary": h.summary,
                "critical_findings_count": h.critical_findings_count,
                "high_findings_count": h.high_findings_count,
                "medium_findings_count": h.medium_findings_count,
                "low_findings_count": h.low_findings_count,
                "deductions": [{"category": d.category, "points": d.points, "reason": d.reason} for d in h.deductions],
            }
            return json.dumps(payload, indent=2)

        elif name == "unforce_remediation_plan":
            fmt = str(args.get("format") or "bash").lower()
            script = res.remediation.powershell_script if fmt == "powershell" else res.remediation.bash_script
            return script

        raise ValueError(f"Unknown tool: {name}")

    def run_stdio(self) -> None:
        """Runs the JSON-RPC standard I/O communication loop."""
        sys.stderr.write(f"[UnForce-MCP] MCP Server v{__version__} ready on stdio.\n")
        sys.stderr.flush()

        while True:
            line = sys.stdin.readline()
            if not line:
                break
            line_str = line.strip()
            if not line_str:
                continue
            try:
                req = json.loads(line_str)
                resp = self.handle_request(req)
                if resp is not None:
                    out = json.dumps(resp) + "\n"
                    sys.stdout.write(out)
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error / execution failed: {e}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


def run_mcp_server() -> None:
    server = MCPServer()
    server.run_stdio()
