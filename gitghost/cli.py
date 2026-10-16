"""
GitGhost Command Line Interface (CLI).

Features rich terminal typography, ASCII art banners, live progress bars,
visual trees of dangling commits, structured findings tables, hygiene score gauges,
automated excision recipes, and modern interactive desktop & web UI/UX.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from gitghost import __version__
from gitghost.ai_triage import AITriageResult
from gitghost.demo_builder import DemoBuilder
from gitghost.exporters import ReportExporter
from gitghost.git_forensics import ForensicsScanResult, GitForensics
from gitghost.github_remote import is_github_target, sanitize_token_in_text
from gitghost.pipeline import run_scan_pipeline
from gitghost.recovery import ObjectRecoveryEngine
from gitghost.redactor import SecretFinding
from gitghost.remediation import RemediationPlan
from gitghost.scoring import HygieneScoreReport
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
    path: str = typer.Argument(".", help="Local repository path or remote GitHub URL (https://github.com/owner/repo)."),
    ai_provider: str = typer.Option("auto", "--ai-provider", "-p", help="AI provider: auto, gemini, openai, anthropic, ollama, heuristic, none."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Custom model name."),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="GITHUB_TOKEN", help="GitHub token for remote API & private clone (in-memory only)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Path to export report file."),
    export_format: Optional[str] = typer.Option(None, "--format", "-f", help="Format: markdown, json, sarif."),
    recover_zip: Optional[str] = typer.Option(None, "--recover-zip", help="Path to export full recovery ZIP bundle (reports, patches, recovered files)."),
    include_raw: bool = typer.Option(False, "--include-raw", help="Export unredacted (raw) files/patches in recovery ZIP bundle (default is redacted)."),
    strict: bool = typer.Option(False, "--strict", help="CI/CD mode: Exit with code 1 if score < 70 or critical leaks exist."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI triage."),
) -> None:
    """Perform a comprehensive live forensics scan on a local or remote GitHub repository."""
    print_banner()

    if not shutil.which("git"):
        console.print("[bold red]Error:[/bold red] Git executable was not found on the system PATH. Git is required to use GitGhost.")
        raise typer.Exit(1)

    target: str | Path
    if is_github_target(path):
        target = path.strip()
    else:
        repo_path = Path(path).resolve()
        if not repo_path.exists():
            console.print(f"[bold red]Error:[/bold red] Target path does not exist: {repo_path}")
            raise typer.Exit(1)

        forensics = GitForensics(repo_path)
        if not forensics.is_valid_repo():
            console.print(f"[bold red]Error:[/bold red] '{repo_path}' is not a valid Git repository (.git missing).")
            raise typer.Exit(1)
        target = repo_path

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("Exhuming git graveyard and unearthing unreachable objects...", total=100)

            def on_phase(msg: str, pct: int):
                progress.update(task_id, description=msg, completed=pct, total=100)

            def on_forensics_done(scan_res: ForensicsScanResult):
                total_items = len(scan_res.dangling_commits) + len(scan_res.dangling_blobs)
                progress.update(
                    task_id,
                    description=f"Scanning {total_items} unreachable objects for credentials...",
                    total=max(1, total_items),
                    completed=0,
                )

            def on_item_scanned(current: int, total: int):
                progress.update(task_id, completed=current, total=max(1, total))

            pipeline_res = run_scan_pipeline(
                repo_path=target,
                ai_provider="none" if no_ai else ai_provider,
                model=model,
                github_token=github_token,
                on_forensics_done=on_forensics_done,
                on_item_scanned=on_item_scanned,
                on_phase=on_phase,
            )
    except Exception as exc:
        safe_err = sanitize_token_in_text(str(exc), github_token)
        console.print(f"[bold red]Error:[/bold red] {safe_err}")
        raise typer.Exit(1)

    _render_ghost_tree(pipeline_res.scan_result)
    _render_findings_table(pipeline_res.findings, pipeline_res.triage_map)
    _render_score_panel(pipeline_res.hygiene)
    _render_remediation_panel(pipeline_res.remediation)

    if output:
        _handle_export(
            output,
            export_format,
            pipeline_res.scan_result,
            pipeline_res.findings,
            pipeline_res.triage_map,
            pipeline_res.hygiene,
            pipeline_res.remediation,
        )

    if recover_zip:
        zip_path = Path(recover_zip).resolve()
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        zip_bytes = ObjectRecoveryEngine.build_recovery_zip_bundle(
            pipeline_res, include_raw=include_raw
        )
        zip_path.write_bytes(zip_bytes)
        mode_str = "UNREDACTED (RAW)" if include_raw else "STRICTLY REDACTED"
        console.print(f"[bold green]Recovery ZIP bundle exported ({mode_str}):[/bold green] {zip_path}")

    if strict and (pipeline_res.hygiene.score < 70 or pipeline_res.hygiene.critical_findings_count > 0):
        console.print(f"\n[bold red]Strict Check Failed:[/bold red] Hygiene score {pipeline_res.hygiene.score}/100.")
        raise typer.Exit(1)


@app.command(name="demo")
def demo_cmd():
    """Run an instant interactive sandbox demo of GitGhost forensics in 5 seconds."""
    print_banner()

    if not shutil.which("git"):
        console.print("[bold red]Error:[/bold red] Git executable was not found on the system PATH. Git is required to use GitGhost.")
        raise typer.Exit(1)

    console.print("[bold cyan]🚀 Initializing GitGhost Interactive Sandbox Demo...[/bold cyan]")
    console.print("[dim]Creating temporary sandbox repository with simulated accidental secret leak...[/dim]\n")

    info = DemoBuilder.create_demo_repository()
    try:
        console.print(f"[bold green]✔[/bold green] Created temporary Git sandbox at: [cyan]{info.repo_path}[/cyan]")
        console.print(
            f"[bold yellow]Scenario:[/bold yellow] Developer committed [red]{info.leaked_filename}[/red] "
            f"([italic]{info.dangling_commit_subject}[/italic]), then ran [bold cyan]git reset --hard HEAD~1[/bold cyan].\n"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("Exhuming sandbox git graveyard...", total=100)

            def on_forensics_done(scan_res: ForensicsScanResult):
                total_items = len(scan_res.dangling_commits) + len(scan_res.dangling_blobs)
                progress.update(
                    task_id,
                    description=f"Scanning {total_items} unreachable sandbox objects...",
                    total=max(1, total_items),
                    completed=0,
                )

            def on_item_scanned(current: int, total: int):
                progress.update(task_id, completed=current, total=max(1, total))

            pipeline_res = run_scan_pipeline(
                repo_path=info.repo_path,
                ai_provider="none",
                on_forensics_done=on_forensics_done,
                on_item_scanned=on_item_scanned,
            )

        _render_ghost_tree(pipeline_res.scan_result)
        _render_findings_table(pipeline_res.findings, pipeline_res.triage_map)
        _render_score_panel(pipeline_res.hygiene)
        _render_remediation_panel(pipeline_res.remediation)
        console.print("[bold green]✔ Sandbox demo completed successfully![/bold green] Cleaning up temporary directory...")
    finally:
        DemoBuilder.cleanup(info.repo_path)
        console.print("[dim]Temporary sandbox cleaned up.[/dim]\n")


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
    success, hook_path, notice = ReportExporter.install_pre_push_hook(repo_path)
    if success:
        console.print(f"[bold green]Success![/bold green] Pre-push hook installed at: [cyan]{hook_path}[/cyan]")
        if notice:
            console.print(f"[bold yellow]{notice}[/bold yellow]")
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

    if not shutil.which("git"):
        console.print("[bold red]Error:[/bold red] Git executable was not found on the system PATH.")
        raise typer.Exit(1)

    repo_path = Path(path).resolve()
    if not (repo_path / ".git").exists():
        console.print(f"[bold red]Error:[/bold red] '{repo_path}' is not a valid Git repository.")
        raise typer.Exit(1)

    if dry_run:
        console.print("[cyan]Dry Run:[/cyan] git reflog expire --expire=now --all && git gc --prune=now --aggressive")
        return

    if typer.confirm("Permanently excise unreferenced objects?"):
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
            console.print("[bold green]Success![/bold green] All dangling objects excised.")
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr or e.stdout or str(e)
            console.print(
                f"[bold red]Excision Failed:[/bold red] Git command returned non-zero exit code ({e.returncode}):\n"
                f"[dim]{err_msg.strip()}[/dim]"
            )
            raise typer.Exit(1)
        except Exception as e:
            console.print(f"[bold red]Excision Failed:[/bold red] {e}")
            raise typer.Exit(1)


def _render_ghost_tree(scan_result: ForensicsScanResult):
    tree = Tree(
        f"[bold cyan]📁 Git Object Store ({Path(scan_result.repo_path).name})[/bold cyan] "
        f"[dim]({scan_result.total_objects_scanned} unreachable objects)[/dim]"
    )
    commits_branch = tree.add(f"[bold magenta]👻 Dangling Commits ({len(scan_result.dangling_commits)})[/bold magenta]")
    for c in scan_result.dangling_commits[:8]:
        c_branch = commits_branch.add(
            f"[bold red]commit {c.commit_hash[:10]}[/bold red] [yellow]{c.date[:10] if c.date else 'Unknown'}[/yellow] [dim]by {c.author}[/dim]"
        )
        subj = c.message.splitlines()[0] if c.message else ""
        c_branch.add(f'[italic]"{subj}"[/italic]')
    if len(scan_result.dangling_commits) > 8:
        commits_branch.add(f"[dim italic]... and {len(scan_result.dangling_commits) - 8} more dangling commits[/dim italic]")

    blobs_branch = tree.add(f"[bold yellow]📦 Dangling Blobs ({len(scan_result.dangling_blobs)})[/bold yellow]")
    for b in scan_result.dangling_blobs[:4]:
        loc = f" ({b.associated_path})" if b.associated_path else ""
        blobs_branch.add(f"[yellow]{b.blob_hash[:10]}[/yellow]{loc} - {b.size} bytes")
    if len(scan_result.dangling_blobs) > 4:
        blobs_branch.add(f"[dim italic]... and {len(scan_result.dangling_blobs) - 4} more dangling blobs[/dim italic]")

    console.print(tree)
    console.print("")


def _render_findings_table(findings: list[SecretFinding], triage_map: dict[str, AITriageResult]):
    table = Table(
        title="🔍 Discovered Credentials & Forensic Findings",
        title_style="bold cyan",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=True,
    )
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
            sev_styled = (
                f"[bold red]{sev}[/bold red]"
                if sev == "Critical"
                else (f"[bold yellow]{sev}[/bold yellow]" if sev == "High" else f"[cyan]{sev}[/cyan]")
            )
            table.add_row(
                f.finding_id,
                sev_styled,
                f.rule_name,
                f"{f.file_path}:{f.line_number}",
                f"[yellow]{f.masked_value}[/yellow]",
                str(round(f.entropy, 2)),
                f"{triage.severity} (Risk: {triage.risk_score})" if triage else "N/A",
            )
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
        for cmd in step.commands:
            lines.append(f"  [bold green]$ {cmd}[/bold green]")
    if remediation.bash_script:
        lines.append("\n[bold cyan]💡 Complete automated scripts available (Bash & PowerShell).[/bold cyan]")
        lines.append("[dim]Inspect in exported reports or copy directly in the Web UI dashboard.[/dim]")
    console.print(Panel("\n".join(lines), title="[bold white on red] Remediation & Excision Playbook [/bold white on red]", border_style="cyan"))


def _handle_export(output_path_str: str, format_arg: Optional[str], scan_result, findings, triage_map, hygiene, remediation):
    output_path = Path(output_path_str).resolve()
    fmt = (format_arg or output_path.suffix.lstrip(".").lower() or "markdown").lower()
    if fmt == "sarif":
        content = ReportExporter.to_sarif(scan_result, findings, triage_map)
    elif fmt == "json":
        content = ReportExporter.to_json(scan_result, findings, triage_map, hygiene, remediation)
    else:
        content = ReportExporter.to_markdown(scan_result, findings, triage_map, hygiene, remediation)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    console.print(f"[bold green]Report exported:[/bold green] {output_path}")


if __name__ == "__main__":
    app()
