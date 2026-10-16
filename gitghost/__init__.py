"""
GitGhost - Git Forensics & Ghost Commit Secret Hunter.

Uncovers dangling commits, unreachable blobs, and orphaned history objects
left behind by `git reset`, `git rebase`, and deleted branches.
Strictly redacts sensitive strings, performs AI-powered risk triage,
calculates repository hygiene scores, generates targeted remediation recipes,
and provides an interactive cyber-forensics UI dashboard.
"""

__version__ = "0.1.0"
__author__ = "GitGhost Security Team"
__license__ = "MIT"

from gitghost.git_forensics import GitForensics, DanglingCommit, DanglingBlob, ForensicsScanResult
from gitghost.github_remote import (
    GitHubAPIForensicsClient,
    HistoryOverwriteEvent,
    ParsedGitHubTarget,
    RemoteAcquisitionResult,
    SmartGitCloner,
    is_github_target,
    parse_github_url,
)
from gitghost.redactor import SecretRedactor, SecretFinding, RedactionResult, shannon_entropy
from gitghost.ai_triage import AITriage, AITriageResult
from gitghost.scoring import HygieneScorer, HygieneScoreReport
from gitghost.remediation import RemediationGenerator, RemediationPlan
from gitghost.exporters import ReportExporter
from gitghost.pipeline import PipelineResult, run_scan_pipeline
from gitghost.recovery import ObjectRecoveryEngine, RecoveredArtifact
from gitghost.ui_window import launch_ui
from gitghost.ui_server import ScanJob, ScanJobManager, start_ui_server

__all__ = [
    "__version__",
    "GitForensics",
    "DanglingCommit",
    "DanglingBlob",
    "ForensicsScanResult",
    "ParsedGitHubTarget",
    "HistoryOverwriteEvent",
    "RemoteAcquisitionResult",
    "GitHubAPIForensicsClient",
    "SmartGitCloner",
    "parse_github_url",
    "is_github_target",
    "SecretRedactor",
    "SecretFinding",
    "RedactionResult",
    "shannon_entropy",
    "AITriage",
    "AITriageResult",
    "HygieneScorer",
    "HygieneScoreReport",
    "RemediationGenerator",
    "RemediationPlan",
    "ReportExporter",
    "PipelineResult",
    "run_scan_pipeline",
    "ObjectRecoveryEngine",
    "RecoveredArtifact",
    "ScanJob",
    "ScanJobManager",
    "launch_ui",
    "start_ui_server",
]

