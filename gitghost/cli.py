"""
GitGhost Command Line Interface (CLI).

Features rich terminal typography, ASCII art banners, live spinners,
visual trees of dangling commits, structured findings tables, hygiene score gauges,
automated excision recipes, and modern interactive desktop & web UI/UX.
"""

from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from gitghost import __version__
from gitghost.git_forensics import GitForensics, ForensicsScanResult
from gitghost.redactor import SecretRedactor, RedactionResult, SecretFinding
from gitghost.ai_triage import AITriage, AITriageResult
from gitghost.scoring import HygieneScorer, HygieneScoreReport
from gitghost.remediation import RemediationGenerator, RemediationPlan
from gitghost.exporters import ReportExporter
from gitghost.ui_window import launch_ui

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = typer.Typer(
    name="gitghost",
    help="👻 GitGhost - Forensics & Ghost Commit Secret Hunter for Git Repositories.",
    add_completion=False,
)
console = Console(legacy_windows=False)

BANNER_ART = r"""
 [bold cyan]  ██████╗ ██╗████████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗[/bold cyan]
 [bold cyan] ██╔════╝ ██║╚══██╔══╝██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝[/bold cyan]
 [bold cyan] ██║  ███╗██║   ██║   ██║  ███╗███████║██║   ██║███████╗   ██║   [/bold cyan]
 [bold cyan] ██║   ██║██║   ██║   ██║   ██║██╔══██║██║   ██║╚════██║   ██║   [/bold cyan]
 [bold cyan] ╚██████╔╝██║   ██║   ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   [/bold cyan]
 [bold cyan]  ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   [/bold cyan]
      [bold magenta]👻 Exhuming Dangling Commits & Hunting Forgotten Secrets 👻[/bold magenta]
                 [dim]v{version} | Enterprise Git Security Forensics[/dim]
""".format(version=__version__)


def print_banner() -> None:
    console.print(BANNER_ART)


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]GitGhost[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True, help="Show GitGhost version and exit."
    ),
):
    pass


@app.command(name="scan")
def scan_cmd(
    path: str = typer.Argument(".", help="Path to the target Git repository."),
    ai_provider: str = typer.Option("auto", "--ai-provider", "-p", help="AI provider: auto, gemini, openai, anthropic, ollama, heuristic, none."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Custom model name."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Path to export report file."),
    export_format: Optional[str] = typer.Option(None, "--format", "-f", help="Format: markdown, json, sarif."),
    strict: bool = typer.Option(False, "--strict", help="CI/CD mode: Exit with code 1 if score < 70 or critical leaks exist."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI triage."),
) -> None:
    """Perform a comprehensive live forensics scan on a target Git repository."""
    print_banner()
    repo_path = Path(path).resolve()
    if not repo_path.exists():
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {repo_path}")
        raise typer.Exit(1)

    forensics = GitForensics(repo_path)
    if not forensics.is_valid_repo():
        console.print(f"[bold red]Error:[/bold red] '{repo_path}' is not a valid Git repository (.git missing).")
        raise typer.Exit(1)

    with console.status("[bold cyan]Exhuming git graveyard and unearthing unreachable objects...[/bold cyan]", spinner="dots"):
        scan_result = forensics.scan()

    _render_ghost_tree(scan_result)

    redactor = SecretRedactor()
    all_findings: list[SecretFinding] = []

    with console.status("[bold magenta]Scanning unreferenced objects for secrets with Shannon entropy...[/bold magenta]", spinner="material"):
        for c in scan_result.dangling_commits:
            msg_res = redactor.scan_and_redact(c.message, file_path="[Commit Message]", commit_hash=c.commit_hash)
            all_findings.extend(msg_res.findings)
            diff_res = redactor.scan_and_redact(c.diff_content, file_path=c.changed_files[0] if c.changed_files else "Diff", commit_hash=c.commit_hash)
            all_findings.extend(diff_res.findings)

        for b in scan_result.dangling_blobs:
            if not b.is_binary:
                blob_res = redactor.scan_and_redact(b.content, file_path=b.associated_path or "Detached Blob", blob_hash=b.blob_hash)
                all_findings.extend(blob_res.findings)

    triage_map: dict[str, AITriageResult] = {}
    effective_provider = "none" if no_ai else ai_provider

    if effective_provider != "none" and all_findings:
        triage_engine = AITriage(provider=effective_provider, model=model)
        for f in all_findings:
            matched = next((c for c in scan_result.dangling_commits if c.commit_hash == f.commit_hash), None)
            verdict = triage_engine.triage_finding(
                finding_rule=f.rule_name, masked_snippet=f.masked_value, context_line=f.context_line,
                commit_message=matched.message if matched else None, author=matched.author if matched else None,
                file_path=f.file_path,
            )
            triage_map[f.finding_id] = verdict

    commit_dates = [c.date for c in scan_result.dangling_commits if c.date]
    hygiene = HygieneScorer.calculate(
        dangling_commits_count=len(scan_result.dangling_commits),
        dangling_blobs_count=len(scan_result.dangling_blobs),
        findings=all_findings, triage_results=triage_map, commit_dates=commit_dates,
    )

    remediation = RemediationGenerator.generate_plan(
        repo_path=str(repo_path), findings=all_findings,
        dangling_commits_count=len(scan_result.dangling_commits), dangling_blobs_count=len(scan_result.dangling_blobs),
    )

    _render_findings_table(all_findings, triage_map)
    _render_score_panel(hygiene)
    _render_remediation_panel(remediation)

    if output:
        _handle_export(output, export_format, scan_result, all_findings, triage_map, hygiene, remediation)

    if strict and (hygiene.score < 70 or hygiene.critical_findings_count > 0):
        console.print(f"\n[bold red]Strict Check Failed:[/bold red] Hygiene score {hygiene.score}/100.")
        raise typer.Exit(1)


@app.command(name="ui")
def ui_cmd(
    path: str = typer.Argument(".", help="Initial repository path to open in the UI."),
    port: int = typer.Option(8765, "--port", help="Port to bind the local UI server to."),
    web: bool = typer.Option(False, "--web", help="Launch in default system browser instead of desktop window."),
    qt: bool = typer.Option(False, "--qt", help="Launch PySide6 Qt desktop window."),
):
    """Launch the interactive GitGhost desktop & web forensics UI/UX dashboard."""
    print_banner()
    launch_ui(repo_path=path, port=port, web=web, qt=qt)


@app.command(name="gui", hidden=True)
def gui_cmd(
    path: str = typer.Argument(".", help="Initial repository path to open in the UI."),
    port: int = typer.Option(8765, "--port", help="Port to bind the local UI server to."),
    web: bool = typer.Option(False, "--web", help="Launch in default system browser instead of desktop window."),
    qt: bool = typer.Option(False, "--qt", help="Launch PySide6 Qt desktop window."),
):
    """Alias for 'gitghost ui'."""
    ui_cmd(path=path, port=port, web=web, qt=qt)


@app.command(name="install-hook")
def install_hook_cmd(path: str = typer.Argument(".", help="Target repository path.")):
    """Install a pre-push Git hook to prevent pushing unreferenced secrets."""
    print_banner()
    repo_path = Path(path).resolve()
    success, hook_path = ReportExporter.install_pre_push_hook(repo_path)
    if success:
        console.print(f"[bold green]Success![/bold green] Pre-push hook installed at: [cyan]{hook_path}[/cyan]")
    else:
        console.print(f"[bold red]Failed:[/bold red] {hook_path}")
        raise typer.Exit(1)


@app.command(name="clean")
def clean_cmd(
    path: str = typer.Argument(".", help="Target repository path."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print excision commands without running them."),
):
    """Execute physical excision of all unreferenced and dangling objects."""
    print_banner()
    repo_path = Path(path).resolve()
    if dry_run:
        console.print("[cyan]Dry Run:[/cyan] git reflog expire --expire=now --all && git gc --prune=now --aggressive")
        return
    if typer.confirm("Permanently excise unreferenced objects?"):
        subprocess.run(["git", "reflog", "expire", "--expire=now", "--all"], cwd=str(repo_path), check=True)
        subprocess.run(["git", "gc", "--prune=now", "--aggressive"], cwd=str(repo_path), check=True)
        console.print("[bold green]Success![/bold green] All dangling objects excised.")


def _render_ghost_tree(scan_result: ForensicsScanResult):
    tree = Tree(f"[bold cyan]📁 Git Object Store ({Path(scan_result.repo_path).name})[/bold cyan] [dim]({scan_result.total_objects_scanned} unreachable objects)[/dim]")
    commits_branch = tree.add(f"[bold magenta]👻 Dangling Commits ({len(scan_result.dangling_commits)})[/bold magenta]")
    for c in scan_result.dangling_commits:
        c_branch = commits_branch.add(f"[bold red]commit {c.commit_hash[:10]}[/bold red] [yellow]{c.date[:10] if c.date else 'Unknown'}[/yellow] [dim]by {c.author}[/dim]")
        subj = c.message.splitlines()[0] if c.message else ""
        c_branch.add(f'[italic]"{subj}"[/italic]')
    blobs_branch = tree.add(f"[bold yellow]📦 Dangling Blobs ({len(scan_result.dangling_blobs)})[/bold yellow]")
    for b in scan_result.dangling_blobs[:4]:
        blobs_branch.add(f"[yellow]{b.blob_hash[:10]}[/yellow] - {b.size} bytes")
    console.print(tree)
    console.print("")


def _render_findings_table(findings: list[SecretFinding], triage_map: dict[str, AITriageResult]):
    table = Table(title="🔍 Discovered Credentials & Forensic Findings", title_style="bold cyan", box=box.ROUNDED, header_style="bold magenta", show_lines=True)
    table.add_column("ID", style="bold", width=9)
    table.add_column("Severity", width=10)
    table.add_column("Finding Type", width=24)
    table.add_column("Location", width=20)
    table.add_column("Masked Credential", width=26)
    table.add_column("Entropy", width=8, justify="right")
    table.add_column("AI Triage Verdict", width=28)

    if not findings:
        table.add_row("—", "[green]CLEAN[/green]", "No secrets detected", "N/A", "N/A", "—", "[green]No unreachable secrets found.[/green]")
    else:
        for f in findings:
            triage = triage_map.get(f.finding_id)
            sev = triage.severity if triage else f.severity_estimate
            sev_styled = f"[bold red]{sev}[/bold red]" if sev == "Critical" else (f"[bold yellow]{sev}[/bold yellow]" if sev == "High" else f"[cyan]{sev}[/cyan]")
            table.add_row(f.finding_id, sev_styled, f.rule_name, f"{f.file_path}:{f.line_number}", f"[yellow]{f.masked_value}[/yellow]", str(round(f.entropy, 2)), f"{triage.severity} (Risk: {triage.risk_score})" if triage else "N/A")
    console.print(table)
    console.print("")


def _render_score_panel(hygiene: HygieneScoreReport):
    total_blocks = 30
    filled = int((hygiene.score / 100.0) * total_blocks)
    gauge_str = ("█" * filled) + ("░" * (total_blocks - filled))
    text = Text()
    text.append(f"  [{gauge_str}]  {hygiene.score}/100  —  Grade: {hygiene.grade}\n\n", style=hygiene.color)
    text.append(f"  {hygiene.summary}\n\n", style="italic")
    if hygiene.deductions:
        for d in hygiene.deductions:
            text.append(f"    • [-{d.points} pts] ", style="red")
            text.append(f"{d.category}: {d.reason}\n", style="dim")
    console.print(Panel(text, title="[bold white on blue] Repository Hygiene Scorecard [/bold white on blue]", border_style=hygiene.color))


def _render_remediation_panel(remediation: RemediationPlan):
    lines = [f"[bold red]⚠️ {remediation.rotation_warning}[/bold red]\n"]
    for step in remediation.steps:
        lines.append(f"[bold yellow]Step {step.order}: {step.title}[/bold yellow]")
        for cmd in step.commands: lines.append(f"  [bold green]$ {cmd}[/bold green]")
    console.print(Panel("\n".join(lines), title="[bold white on red] Remediation & Excision Playbook [/bold white on red]", border_style="cyan"))


def _handle_export(output_path_str: str, format_arg: Optional[str], scan_result, findings, triage_map, hygiene, remediation):
    output_path = Path(output_path_str).resolve()
    fmt = (format_arg or output_path.suffix.lstrip(".").lower() or "markdown").lower()
    if fmt == "sarif": content = ReportExporter.to_sarif(scan_result, findings, triage_map)
    elif fmt == "json": content = ReportExporter.to_json(scan_result, findings, triage_map, hygiene, remediation)
    else: content = ReportExporter.to_markdown(scan_result, findings, triage_map, hygiene, remediation)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    console.print(f"[bold green]Report exported:[/bold green] {output_path}")


if __name__ == "__main__":
    app()
