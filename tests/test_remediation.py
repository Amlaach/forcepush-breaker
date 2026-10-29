"""
Unit tests for RemediationGenerator and automated excision script generation.
"""

from pathlib import Path
import pytest
from gitghost.redactor import SecretFinding
from gitghost.remediation import RemediationGenerator, RemediationPlan


class TestRemediationGenerator:
    def test_remediation_plan_with_spaces_in_path(self):
        repo_with_spaces = "C:/Users/Test User/My Projects/Security Vault"
        finding = SecretFinding(
            finding_id="SEC-0001",
            rule_name="AWS Access Key ID",
            match_type="pattern",
            severity_estimate="Critical",
            masked_value="AKIA************MPLE",
            line_number=5,
            context_line="AWS_KEY=AKIA************MPLE",
            entropy=4.5,
            file_path="config/production secrets.env",
            commit_hash="deadbeef1234567890",
        )

        plan: RemediationPlan = RemediationGenerator.generate_plan(
            repo_path=repo_with_spaces,
            findings=[finding],
            dangling_commits_count=2,
            dangling_blobs_count=3,
        )

        # 1. Verify paths are safely quoted in steps
        resolved_repo = str(Path(repo_with_spaces).resolve())
        resolved_backup = f"{resolved_repo}_safety_backup.git"
        step1_cmd = plan.steps[0].commands[0]
        assert f'"{resolved_repo}"' in step1_cmd
        assert f'"{resolved_backup}"' in step1_cmd

        # 2. Verify filter-repo contains quoted affected file
        step2 = next(s for s in plan.steps if "Purge" in s.title)
        assert '--path "config/production secrets.env"' in step2.commands[1]

        # 3. Verify Bash script contains full automated commands and quoted paths
        assert "#!/usr/bin/env bash" in plan.bash_script
        assert f'git clone --mirror "{resolved_repo}" "{resolved_backup}"' in plan.bash_script
        assert 'git filter-repo --invert-paths --path "config/production secrets.env" --force' in plan.bash_script
        assert "git reflog expire --expire=now --expire-unreachable=now --all" in plan.bash_script
        assert "git gc --prune=now --aggressive" in plan.bash_script

        # 4. Verify PowerShell script contains full automated commands and quoted paths
        assert "$ErrorActionPreference = 'Stop'" in plan.powershell_script
        assert f'git clone --mirror "{resolved_repo}" "{resolved_backup}"' in plan.powershell_script
        assert 'git filter-repo --invert-paths --path "config/production secrets.env" --force' in plan.powershell_script
        assert "git reflog expire --expire=now --expire-unreachable=now --all" in plan.powershell_script
        assert "git gc --prune=now --aggressive" in plan.powershell_script

    def test_remediation_plan_without_affected_files(self):
        repo_path = "/clean/repo"
        plan = RemediationGenerator.generate_plan(
            repo_path=repo_path,
            findings=[],
            dangling_commits_count=1,
            dangling_blobs_count=1,
        )

        # No filter-repo step when no file paths are affected
        step_titles = [s.title for s in plan.steps]
        assert not any("Purge Sensitive Files" in t for t in step_titles)

        # Reflog expire and gc prune still present
        assert any("Expire All Reflogs" in t for t in step_titles)
        assert any("Garbage Collection" in t for t in step_titles)

        # Scripts still valid
        assert "git reflog expire" in plan.bash_script
        assert "git gc --prune=now --aggressive" in plan.powershell_script

    def test_github_support_ticket_generation(self):
        orphaned_commits = [
            "deadbeef11111111111111111111111111111111",
            "cafebabe22222222222222222222222222222222",
        ]
        ticket = RemediationGenerator.generate_github_support_ticket(
            repo_url="https://github.com/acme/vault",
            orphaned_commit_shas=orphaned_commits,
            findings_count=3,
        )
        assert "Subject: Request for Server-Side Cache Purge" in ticket
        assert "https://github.com/acme/vault" in ticket
        assert "- `deadbeef11111111111111111111111111111111`" in ticket
        assert "- `cafebabe22222222222222222222222222222222`" in ticket
        assert "2 orphaned/force-pushed commit(s) containing 3 exposed credential finding(s)" in ticket

    def test_pre_push_hook_installation(self, tmp_path: Path):
        from gitghost.exporters import ReportExporter
        (tmp_path / ".git").mkdir()

        success, hook_path, notice = ReportExporter.install_pre_push_hook(tmp_path)
        assert success is True
        assert Path(hook_path).exists()
        content = Path(hook_path).read_text(encoding="utf-8")
        assert "pre-push" in content.lower()
        assert "gitghost" in content.lower() or "unforce" in content.lower()

