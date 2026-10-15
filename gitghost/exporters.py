"""
Report Exporters and CI/CD Integrations.

Generates industry-standard security reports in Markdown, JSON, and SARIF 2.1.0
(compatible with GitHub Advanced Security / Code Scanning), and installs Git pre-push hooks.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from gitghost.git_forensics import ForensicsScanResult
from gitghost.redactor import SecretFinding
from gitghost.ai_triage import AITriageResult
from gitghost.scoring import HygieneScoreReport
from gitghost.remediation import RemediationPlan


class ReportExporter:
    @classmethod
    def to_json(
        cls, scan_result: ForensicsScanResult, findings: List[SecretFinding],
        triage_map: Dict[str, AITriageResult], hygiene: HygieneScoreReport, remediation: RemediationPlan,
    ) -> str:
        serialized_findings = []
        for f in findings:
            f_dict = asdict(f)
            triage = triage_map.get(f.finding_id)
            if triage: f_dict["ai_triage"] = asdict(triage)
            serialized_findings.append(f_dict)

        data = {
            "tool": "GitGhost", "version": "0.1.0", "timestamp": datetime.now(timezone.utc).isoformat(),
            "repository": scan_result.repo_path,
            "hygiene_score": {"score": hygiene.score, "grade": hygiene.grade, "summary": hygiene.summary, "deductions": [asdict(d) for d in hygiene.deductions]},
            "statistics": {
                "dangling_commits_count": len(scan_result.dangling_commits),
                "dangling_blobs_count": len(scan_result.dangling_blobs),
                "unreachable_trees_count": len(scan_result.unreachable_trees),
                "total_secrets_found": len(findings),
                "critical_secrets": hygiene.critical_findings_count,
                "high_secrets": hygiene.high_findings_count,
                "false_positives": hygiene.false_positives_count,
            },
            "findings": serialized_findings,
            "dangling_commits": [{"commit_hash": c.commit_hash, "author": c.author, "date": c.date, "message": c.message, "changed_files": c.changed_files} for c in scan_result.dangling_commits],
            "remediation": {"rotation_warning": remediation.rotation_warning, "affected_paths": remediation.affected_paths, "steps": [asdict(s) for s in remediation.steps]}
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    @classmethod
    def to_markdown(
        cls, scan_result: ForensicsScanResult, findings: List[SecretFinding],
        triage_map: Dict[str, AITriageResult], hygiene: HygieneScoreReport, remediation: RemediationPlan,
    ) -> str:
        md: List[str] = [
            "# 👻 GitGhost Security & Forensics Audit Report", "",
            f"**Repository:** `{scan_result.repo_path}`  ",
            f"**Scan Date:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  ",
            f"**Audit Engine:** `GitGhost v0.1.0`", "", "---", "",
            "## 1. Repository Hygiene Scorecard", "",
            f"### **Hygiene Score: {hygiene.score}/100 — {hygiene.grade}**",
            f"> {hygiene.summary}", "",
            "| Metric | Count | Status |",
            "| :--- | :--- | :--- |",
            f"| Dangling Commits | `{len(scan_result.dangling_commits)}` | {'⚠️ Warning' if len(scan_result.dangling_commits) > 0 else '✅ Clean'} |",
            f"| Dangling Blobs | `{len(scan_result.dangling_blobs)}` | {'⚠️ Warning' if len(scan_result.dangling_blobs) > 0 else '✅ Clean'} |",
            f"| Critical Secret Leaks | `{hygiene.critical_findings_count}` | {'🚨 CRITICAL' if hygiene.critical_findings_count > 0 else '✅ None'} |",
            f"| High Risk Secrets | `{hygiene.high_findings_count}` | {'⚠️ HIGH' if hygiene.high_findings_count > 0 else '✅ None'} |",
            f"| Filtered False Positives | `{hygiene.false_positives_count}` | ℹ️ Triaged |", "",
        ]

        if hygiene.deductions:
            md.append("#### Hygiene Score Deductions:")
            for d in hygiene.deductions: md.append(f"- **-{d.points} pts** ({d.category}): {d.reason}")
            md.append("")

        md.extend(["---", "", "## 2. Exhumed Ghost Commits & History Objects", ""])
        if not scan_result.dangling_commits:
            md.append("_No dangling or unreachable commits detected in the object store._\n")
        else:
            md.append("| Commit Hash | Author | Date | Subject | Files Touched |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for c in scan_result.dangling_commits:
                short_hash = f"`{c.commit_hash[:10]}`"
                files_str = ", ".join([f"`{f}`" for f in c.changed_files[:3]]) or "_None_"
                if len(c.changed_files) > 3: files_str += f" (+{len(c.changed_files) - 3} more)"
                md.append(f"| {short_hash} | {c.author} | {c.date[:10]} | {c.message.splitlines()[0] if c.message else 'N/A'} | {files_str} |")
            md.append("")

        md.extend(["---", "", "## 3. Discovered Credential Findings & AI Triage", ""])
        if not findings:
            md.append("✅ **No credentials or high-entropy secrets were found in unreachable objects.**\n")
        else:
            for idx, f in enumerate(findings, start=1):
                triage = triage_map.get(f.finding_id)
                status_icon = "🚨" if f.severity_estimate == "Critical" else ("⚠️" if f.severity_estimate == "High" else "ℹ️")
                if triage and triage.is_false_positive: status_icon = "🟢 (False Positive)"
                md.append(f"### {idx}. [{f.finding_id}] {status_icon} {f.rule_name}")
                md.append(f"- **File:** `{f.file_path or 'Unattached Object'}` (Line {f.line_number})")
                md.append(f"- **Associated Commit / Blob:** `{f.commit_hash or f.blob_hash or 'N/A'}`")
                md.append(f"- **Shannon Entropy:** `{f.entropy}`")
                md.append(f"- **Masked Value:** `{f.masked_value}`")
                md.append(f"- **Surrounding Redacted Line:**\n  ```text\n  {f.context_line}\n  ```")
                if triage:
                    md.append(f"- **AI Triage Verdict:** `{triage.severity}` (Risk: {triage.risk_score}/10) via `{triage.provider_used}`")
                    md.append(f"  > **Explanation:** {triage.technical_explanation}")
                    md.append(f"  > **Recommendation:** {triage.recommended_action}")
                md.append("")

        md.extend(["---", "", "## 4. Remediation Action Plan", "", f"> ⚠️ **{remediation.rotation_warning}**", ""])
        for step in remediation.steps:
            md.append(f"### Step {step.order}: {step.title}")
            md.append(f"{step.description}\n\n```bash")
            for cmd in step.commands: md.append(cmd)
            md.append("```\n")

        if remediation.bash_script:
            md.extend([
                "### Automated Remediation Scripts",
                "",
                "#### Bash Script (Linux / macOS / WSL):",
                "```bash",
                remediation.bash_script.strip(),
                "```",
                "",
            ])

        if remediation.powershell_script:
            md.extend([
                "#### PowerShell Script (Windows):",
                "```powershell",
                remediation.powershell_script.strip(),
                "```",
                "",
            ])

        return "\n".join(md)

    @classmethod
    def to_sarif(cls, scan_result: ForensicsScanResult, findings: List[SecretFinding], triage_map: Dict[str, AITriageResult]) -> str:
        level_map = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}
        rules_dict: Dict[str, Dict[str, Any]] = {}
        sarif_results: List[Dict[str, Any]] = []

        for f in findings:
            rule_id = f"GITGHOST-{f.rule_name.upper().replace(' ', '-').replace('/', '-')}"
            triage = triage_map.get(f.finding_id)
            if triage and triage.is_false_positive: continue
            sev = triage.severity if triage else f.severity_estimate
            sarif_level = level_map.get(sev, "warning")

            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id, "name": f.rule_name, "shortDescription": {"text": f"Dangling secret detected: {f.rule_name}"},
                    "fullDescription": {"text": f"GitGhost detected an unreachable/dangling secret ({f.rule_name}) in Git history."},
                    "defaultConfiguration": {"level": sarif_level},
                }

            loc_uri = f.file_path if (f.file_path and f.file_path not in ("Unknown", "N/A")) else ".git/objects"
            sarif_results.append({
                "ruleId": rule_id, "level": sarif_level,
                "message": {"text": f"Credential ({f.rule_name}) discovered in unreachable Git commit/blob. Masked: {f.masked_value}."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc_uri.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": max(1, f.line_number), "snippet": {"text": f.context_line}}
                    }
                }],
                "properties": {"commit_hash": f.commit_hash or "N/A", "entropy": f.entropy}
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "GitGhost", "version": "0.1.0", "rules": list(rules_dict.values())}}, "results": sarif_results}]
        }
        if scan_result:
            sarif_doc["runs"][0]["invocations"] = [{
                "executionSuccessful": True,
                "workingDirectory": {"uri": f"file://{Path(scan_result.repo_path).resolve().as_posix()}"},
                "properties": {
                    "total_objects_scanned": scan_result.total_objects_scanned,
                    "dangling_commits_count": len(scan_result.dangling_commits),
                    "dangling_blobs_count": len(scan_result.dangling_blobs),
                }
            }]
        return json.dumps(sarif_doc, indent=2)

    @classmethod
    def install_pre_push_hook(cls, repo_path: str | Path) -> Tuple[bool, str]:
        repo_dir = Path(repo_path).resolve()
        hooks_dir = repo_dir / ".git" / "hooks"
        if not hooks_dir.exists(): return False, f"Hooks dir not found at {hooks_dir}"
        hook_file = hooks_dir / "pre-push"
        hook_file.write_text("#!/usr/bin/env bash\ngitghost scan . --strict --no-ai\n", encoding="utf-8")
        try:
            hook_file.chmod(hook_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception: pass
        return True, str(hook_file)
