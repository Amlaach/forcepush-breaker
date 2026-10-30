"""Unit tests for the UnForce Model Context Protocol (MCP) server."""
import json
import pytest
from gitghost.mcp_server import MCPServer, MCP_TOOLS, MCP_PROTOCOL_VERSION
from gitghost.pipeline import PipelineResult
from gitghost.git_forensics import ForensicsScanResult, DanglingCommit
from gitghost.scoring import HygieneScoreReport
from gitghost.remediation import RemediationPlan

def _make_mock_hygiene(score=85, grade="B"):
    return HygieneScoreReport(
        score=score,
        grade=grade,
        color="green",
        summary="Clean",
        dangling_commits_count=1,
        dangling_blobs_count=0,
        critical_findings_count=0,
        high_findings_count=0,
        medium_findings_count=0,
        low_findings_count=0,
        false_positives_count=0,
        deductions=[]
    )

def _make_mock_remediation(repo_path="/mock/repo"):
    return RemediationPlan(
        repo_path=repo_path,
        affected_paths=[],
        bash_script="git gc --prune=now",
        powershell_script="git gc --prune=now",
        github_support_ticket="Purge ticket",
    )

def test_mcp_initialize():
    server = MCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "test-agent", "version": "1.0"}
        }
    }
    resp = server.handle_request(req)
    assert resp is not None
    assert resp["id"] == 1
    assert "result" in resp
    assert resp["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert resp["result"]["serverInfo"]["name"] == "unforce-mcp-server"

def test_mcp_tools_list():
    server = MCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    resp = server.handle_request(req)
    assert resp is not None
    assert resp["id"] == 2
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "unforce_scan" in tool_names
    assert "unforce_list_dangling_commits" in tool_names
    assert "unforce_get_commit_diff" in tool_names
    assert "unforce_recover_file" in tool_names
    assert "unforce_check_liveness" in tool_names
    assert "unforce_hygiene_report" in tool_names
    assert "unforce_remediation_plan" in tool_names

def test_mcp_tool_call_hygiene_report():
    server = MCPServer()
    mock_res = PipelineResult(
        repo_path="/mock/repo",
        scan_result=ForensicsScanResult(
            repo_path="/mock/repo",
            is_git_repo=True,
            dangling_commits=[
                DanglingCommit(
                    commit_hash="abcdef1234567890abcdef1234567890abcdef12",
                    author="Dev",
                    date="2026-10-30T12:00:00Z",
                    message="secret commit",
                    is_dangling=True
                )
            ]
        ),
        findings=[],
        triage_map={},
        hygiene=_make_mock_hygiene(85, "B"),
        remediation=_make_mock_remediation("/mock/repo")
    )
    server._cached_results["/mock/repo"] = mock_res
    server._latest_target = "/mock/repo"

    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "unforce_hygiene_report",
            "arguments": {"repo_path": "/mock/repo"}
        }
    }
    resp = server.handle_request(req)
    assert resp is not None
    assert resp["id"] == 3
    content = resp["result"]["content"]
    assert len(content) > 0
    text_data = json.loads(content[0]["text"])
    assert text_data["score"] == 85
    assert text_data["grade"] == "B"

def test_mcp_tool_call_list_dangling():
    server = MCPServer()
    mock_res = PipelineResult(
        repo_path="/mock/repo",
        scan_result=ForensicsScanResult(
            repo_path="/mock/repo",
            is_git_repo=True,
            dangling_commits=[
                DanglingCommit(
                    commit_hash="1111222233334444555566667777888899990000",
                    author="Attacker",
                    date="2026-10-30T10:00:00Z",
                    message="overwritten work",
                    is_dangling=True
                )
            ]
        ),
        findings=[],
        triage_map={},
        hygiene=_make_mock_hygiene(90, "A"),
        remediation=_make_mock_remediation("/mock/repo")
    )
    server._cached_results["/mock/repo"] = mock_res
    server._latest_target = "/mock/repo"

    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "unforce_list_dangling_commits",
            "arguments": {"repo_path": "/mock/repo", "limit": 5}
        }
    }
    resp = server.handle_request(req)
    assert resp is not None
    commits_list = json.loads(resp["result"]["content"][0]["text"])
    assert len(commits_list) == 1
    assert commits_list[0]["commit_hash"] == "1111222233334444555566667777888899990000"
    assert commits_list[0]["author"] == "Attacker"
