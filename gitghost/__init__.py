"""
GitGhost / ForcePush-Breaker (UnForce) — GitHub History Forensics & Secret Hunter.

Uncovers overwritten commits, force-pushed branches, unreachable blobs, deleted `.env` files,
and leaked credentials hidden inside GitHub repositories and `.git/objects/`.
"""

from __future__ import annotations

from typing import Any

from gitghost._proc import install_windowless_subprocess_patch

install_windowless_subprocess_patch()

__version__ = "0.8.0"
__author__ = "ForcePush-Breaker Security Team"
__license__ = "MIT"

BRAND_NAME = "ForcePush-Breaker"
BRAND_SHORT = "UnForce"
BRAND_TAGLINE = (
    "Think `git push --force` deleted your leaked API keys? Think again. "
    "Audit and recover hidden secrets and lost commits from overwritten GitHub history."
)

_LAZY_EXPORTS = {
    "DanglingBlob": ("gitghost.git_forensics", "DanglingBlob"),
    "DanglingCommit": ("gitghost.git_forensics", "DanglingCommit"),
    "ForensicsScanResult": ("gitghost.git_forensics", "ForensicsScanResult"),
    "GitForensics": ("gitghost.git_forensics", "GitForensics"),
    "ReflogEntry": ("gitghost.git_forensics", "ReflogEntry"),
    "RepoMetadata": ("gitghost.git_forensics", "RepoMetadata"),
    "GitHubAPIForensicsClient": ("gitghost.github_remote", "GitHubAPIForensicsClient"),
    "HistoryOverwriteEvent": ("gitghost.github_remote", "HistoryOverwriteEvent"),
    "ParsedGitHubTarget": ("gitghost.github_remote", "ParsedGitHubTarget"),
    "RemoteAcquisitionResult": ("gitghost.github_remote", "RemoteAcquisitionResult"),
    "SmartGitCloner": ("gitghost.github_remote", "SmartGitCloner"),
    "is_github_target": ("gitghost.github_remote", "is_github_target"),
    "parse_github_url": ("gitghost.github_remote", "parse_github_url"),
    "RedactionResult": ("gitghost.redactor", "RedactionResult"),
    "SecretFinding": ("gitghost.redactor", "SecretFinding"),
    "SecretRedactor": ("gitghost.redactor", "SecretRedactor"),
    "shannon_entropy": ("gitghost.redactor", "shannon_entropy"),
    "AITriage": ("gitghost.ai_triage", "AITriage"),
    "AITriageResult": ("gitghost.ai_triage", "AITriageResult"),
    "HygieneScoreReport": ("gitghost.scoring", "HygieneScoreReport"),
    "HygieneScorer": ("gitghost.scoring", "HygieneScorer"),
    "RemediationGenerator": ("gitghost.remediation", "RemediationGenerator"),
    "RemediationPlan": ("gitghost.remediation", "RemediationPlan"),
    "ReportExporter": ("gitghost.exporters", "ReportExporter"),
    "PipelineResult": ("gitghost.pipeline", "PipelineResult"),
    "run_scan_pipeline": ("gitghost.pipeline", "run_scan_pipeline"),
    "ObjectRecoveryEngine": ("gitghost.recovery", "ObjectRecoveryEngine"),
    "RecoveredArtifact": ("gitghost.recovery", "RecoveredArtifact"),
    "launch_ui": ("gitghost.ui_window", "launch_ui"),
    "ScanJob": ("gitghost.ui_server", "ScanJob"),
    "ScanJobManager": ("gitghost.ui_server", "ScanJobManager"),
    "start_ui_server": ("gitghost.ui_server", "start_ui_server"),
}

__all__ = [
    "__version__",
    "BRAND_NAME",
    "BRAND_SHORT",
    "BRAND_TAGLINE",
    *_LAZY_EXPORTS.keys(),
]


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        mod_name, attr_name = _LAZY_EXPORTS[name]
        import importlib

        mod = importlib.import_module(mod_name)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
