# -*- coding: utf-8 -*-
"""Unit tests for the AI Chat Engine and Forensics Tools Executor."""
import json
import pytest
from gitghost.ai_chat import AIChatSession, ForensicsToolExecutor, FORENSICS_TOOLS
from gitghost.pipeline import PipelineResult
from gitghost.git_forensics import ForensicsScanResult, DanglingCommit
from gitghost.scoring import HygieneScoreReport
from gitghost.remediation import RemediationPlan

def _create_mock_pipeline():
    return PipelineResult(
        repo_path="/test/repo",
        scan_result=ForensicsScanResult(
            repo_path="/test/repo",
            is_git_repo=True,
            dangling_commits=[
                DanglingCommit(
                    commit_hash="deadbeef1234567890deadbeef1234567890dead",
                    author="Eve",
                    date="2026-10-30T14:00:00Z",
                    message="secret leak commit",
                    diff_content="diff --git a/.env b/.env\n+API_KEY=123",
                    redacted_diff="diff --git a/.env b/.env\n+API_KEY=***",
                    is_dangling=True
                )
            ]
        ),
        findings=[],
        triage_map={},
        hygiene=HygieneScoreReport(
            score=72,
            grade="C",
            color="orange",
            summary="Needs attention",
            dangling_commits_count=1,
            dangling_blobs_count=0,
            critical_findings_count=0,
            high_findings_count=0,
            medium_findings_count=0,
            low_findings_count=0,
            false_positives_count=0,
            deductions=[]
        ),
        remediation=RemediationPlan(
            repo_path="/test/repo",
            affected_paths=[".env"],
            bash_script="git gc --prune=now",
            powershell_script="git gc --prune=now",
            rotation_warning="Rotate keys immediately!",
        )
    )

def test_forensics_tool_executor():
    pipeline = _create_mock_pipeline()
    executor = ForensicsToolExecutor(pipeline)

    # 1. get_scan_summary
    summary_raw = executor.execute("get_scan_summary", {})
    summary = json.loads(summary_raw)
    assert summary["hygiene_score"] == 72
    assert summary["dangling_commits_count"] == 1

    # 2. list_dangling_commits
    commits_raw = executor.execute("list_dangling_commits", {"limit": 5})
    commits = json.loads(commits_raw)
    assert len(commits) == 1
    assert commits[0]["full_hash"] == "deadbeef1234567890deadbeef1234567890dead"

    # 3. get_commit_diff
    diff_raw = executor.execute("get_commit_diff", {"commit_hash": "deadbeef12"})
    diff_data = json.loads(diff_raw)
    assert "+API_KEY=***" in diff_data["diff_snippet"]

    # 4. get_remediation_guide
    rem_raw = executor.execute("get_remediation_guide", {"format": "bash"})
    rem_data = json.loads(rem_raw)
    assert "git gc --prune=now" in rem_data["script"]

def test_ai_chat_heuristic_fallback():
    pipeline = _create_mock_pipeline()
    session = AIChatSession(provider="heuristic")

    # Ask for status summary
    resp1 = session.chat("Give me the repo status summary", pipeline_res=pipeline)
    assert len(resp1["tools_executed"]) > 0
    assert "get_scan_summary" in resp1["tools_executed"]
    assert "72/100" in resp1["content"]

    # Ask for dangling commits
    resp2 = session.chat("Show me dangling commits that were force-pushed", pipeline_res=pipeline)
    assert "list_dangling_commits" in resp2["tools_executed"]
    assert "deadbeef" in resp2["content"]

    # Ask for remediation
    resp3 = session.chat("How do I clean and purge leaked secrets from history?", pipeline_res=pipeline)
    assert "get_remediation_guide" in resp3["tools_executed"]
    assert "git gc" in resp3["content"]
