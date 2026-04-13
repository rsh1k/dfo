"""
dfo/cli.py
==========
Rich + Click CLI — the main entry point for the DFO tool.
Run via:  dfo --help
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.table import Table

from dfo.terminal import (
    console, print_banner, print_header, print_success,
    print_error, print_warning, print_info,
    build_findings_table, print_query_results,
    print_case_status, create_engine_progress,
    severity_style, severity_icon, severity_label,
)
from dfo.orchestrator import ForensicsOrchestrator


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("1.0.0", prog_name="DFO")
def main():
    """
    🔬  Digital Forensics Orchestrator (DFO)

    NIST-compliant DFIR framework with natural language querying.
    """
    pass


# ---------------------------------------------------------------------------
# dfo ingest
# ---------------------------------------------------------------------------

@main.command()
@click.option("--case", "-c", required=True, help="Case ID (e.g. IR-2026-0042)")
@click.option("--engine", "-e", required=True,
              type=click.Choice(["tshark", "volatility3", "ghidra", "sleuthkit"]),
              help="Forensic engine to use")
@click.option("--file", "-f", "filepath", required=True,
              type=click.Path(exists=True), help="Path to evidence file")
@click.option("--analyst", "-a", default="analyst", help="Analyst name")
@click.option("--offset", default=None, help="Partition offset (sleuthkit)")
def ingest(case: str, engine: str, filepath: str, analyst: str, offset: str):
    """Ingest evidence through a forensic engine."""
    print_banner()
    print_header(f"Ingesting Evidence — Case {case}")

    orch = ForensicsOrchestrator(case_id=case, analyst=analyst)
    evidence = Path(filepath)

    print_info(f"Case ID:   [bold]{case}[/bold]")
    print_info(f"Engine:    [bold]{engine}[/bold]")
    print_info(f"Evidence:  [bold]{evidence.name}[/bold]")
    print_info(f"File size: [bold]{evidence.stat().st_size / 1024:.1f} KB[/bold]")
    console.print()

    kwargs = {}
    if offset:
        kwargs["partition_offset"] = offset

    with create_engine_progress() as progress:
        task = progress.add_task(
            f"Running [bold]{engine}[/bold] analysis…", total=100
        )
        progress.update(task, advance=20)

        try:
            findings = orch.ingest(evidence, engine, **kwargs)
            progress.update(task, advance=80)
        except Exception as exc:
            progress.stop()
            print_error(f"Engine failed: {exc}")
            sys.exit(1)

    console.print()
    print_success(f"Engine produced [bold]{len(findings)}[/bold] findings")

    for tier_name, lo, hi in [("CRITICAL", 0.8, 1.1), ("HIGH", 0.6, 0.8),
                               ("MEDIUM", 0.3, 0.6), ("LOW", 0.0, 0.3)]:
        count = sum(1 for f in findings if lo <= f.severity_score < hi)
        if count > 0:
            style = severity_style(lo)
            console.print(f"    [{style}]{severity_icon(lo)} {tier_name}: {count}[/{style}]")

    orch.save_state()
    print_success(f"State saved to [bold]cases/{case}/[/bold]")
    console.print()


# ---------------------------------------------------------------------------
# dfo score
# ---------------------------------------------------------------------------

@main.command()
@click.option("--case", "-c", required=True, help="Case ID")
@click.option("--iocs", "-i", default=None,
              type=click.Path(exists=True), help="Path to IOC JSON file")
@click.option("--top", "-n", default=25, help="Show top N findings")
def score(case: str, iocs: str, top: int):
    """Score and rank all findings using NIST SP 800-61 weights."""
    print_banner()
    print_header(f"Scoring Findings — Case {case}")

    orch = ForensicsOrchestrator(case_id=case)
    orch.load_state()

    if iocs:
        orch.load_iocs(Path(iocs))
        print_success(f"Loaded IOCs from [bold]{iocs}[/bold]")

    print_info("Applying NIST SP 800-61 Rev.2 weighted scoring…")
    console.print()

    ranked = orch.score_all()

    table = build_findings_table(ranked, title=f"Case {case} — Ranked Findings", max_rows=top)
    console.print(table)
    console.print()

    crit = sum(1 for f in ranked if f.severity_score >= 0.8)
    if crit > 0:
        console.print(
            f"  [critical]⚠  {crit} CRITICAL finding(s) require "
            f"immediate attention[/critical]"
        )
    print_success(f"Scored [bold]{len(ranked)}[/bold] total findings")
    orch.save_state()
    console.print()


# ---------------------------------------------------------------------------
# dfo ask
# ---------------------------------------------------------------------------

@main.command()
@click.option("--case", "-c", required=True, help="Case ID")
@click.argument("question")
@click.option("--top-k", "-k", default=10, help="Number of results to retrieve")
def ask(case: str, question: str, top_k: int):
    """Ask a natural language question about forensic findings."""
    print_banner()
    print_header(f"NL Query — Case {case}")

    orch = ForensicsOrchestrator(case_id=case)
    orch.load_state()

    print_info("Building vector index…")
    orch.build_index()

    result = orch.ask(question, top_k=top_k)
    print_query_results(result)
    console.print()


# ---------------------------------------------------------------------------
# dfo report
# ---------------------------------------------------------------------------

@main.command()
@click.option("--case", "-c", required=True, help="Case ID")
@click.option("--format", "-f", "fmt", default="markdown",
              type=click.Choice(["markdown", "html"]))
@click.option("--output", "-o", default=None, help="Output file path")
def report(case: str, fmt: str, output: str):
    """Generate a NIST SP 800-86 compliant report."""
    print_banner()
    print_header(f"Generating Report — Case {case}")

    orch = ForensicsOrchestrator(case_id=case)
    orch.load_state()

    print_info(f"Format: [bold]{fmt}[/bold]")

    report_text = orch.generate_report()

    if output:
        out_path = Path(output)
        out_path.write_text(report_text, encoding="utf-8")
        print_success(f"Report written to [bold]{out_path}[/bold]")
    else:
        from rich.markdown import Markdown
        console.print()
        console.print(Markdown(report_text))

    console.print()


# ---------------------------------------------------------------------------
# dfo status
# ---------------------------------------------------------------------------

@main.command()
@click.option("--case", "-c", required=True, help="Case ID")
def status(case: str):
    """Show case status dashboard."""
    print_banner()

    orch = ForensicsOrchestrator(case_id=case)
    orch.load_state()

    engines_run = list({f.engine for f in orch.findings})
    print_case_status(
        case_id=case,
        findings=orch.findings,
        custody_count=len(orch.custody._entries),
        engines_run=engines_run,
    )

    if orch.findings:
        table = build_findings_table(
            orch.findings, title="Top Findings", max_rows=10
        )
        console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# dfo interactive
# ---------------------------------------------------------------------------

@main.command()
@click.option("--case", "-c", required=True, help="Case ID")
@click.option("--analyst", "-a", default="analyst", help="Analyst name")
def interactive(case: str, analyst: str):
    """Launch interactive forensic analysis session."""
    print_banner()
    print_header(f"Interactive Session — Case {case}")

    orch = ForensicsOrchestrator(case_id=case, analyst=analyst)

    try:
        orch.load_state()
        print_info(
            f"Loaded existing case with "
            f"[bold]{len(orch.findings)}[/bold] findings"
        )
    except FileNotFoundError:
        print_info("New case — no existing findings")

    console.print()
    console.print("[muted]Commands: ingest, score, ask, status, report, help, quit[/muted]")
    console.print()

    while True:
        try:
            raw = console.input("[bold bright_cyan]dfo>[/bold bright_cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[muted]Exiting…[/muted]")
            break

        if not raw:
            continue

        parts = raw.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd == "help":
            _interactive_help()
        elif cmd == "ingest":
            _interactive_ingest(orch, args)
        elif cmd == "score":
            _interactive_score(orch, args)
        elif cmd == "ask":
            if not args:
                print_warning("Usage: ask <your question>")
                continue
            _interactive_ask(orch, args)
        elif cmd == "status":
            engines = list({f.engine for f in orch.findings})
            print_case_status(case, orch.findings,
                              len(orch.custody._entries), engines)
        elif cmd == "report":
            md = orch.generate_report()
            from rich.markdown import Markdown
            console.print(Markdown(md))
        elif cmd in ("quit", "exit", "q"):
            orch.save_state()
            print_success("State saved. Goodbye!")
            break
        else:
            print_warning(f"Unknown command: [bold]{cmd}[/bold]. Type 'help'.")


def _interactive_help():
    help_table = Table(
        title="[header]Available Commands[/header]",
        border_style="bright_cyan",
        show_header=True,
        header_style="bold bright_white",
    )
    help_table.add_column("Command", style="bold bright_cyan", width=22)
    help_table.add_column("Description")

    cmds = [
        ("ingest <engine> <file>", "Run engine on evidence file"),
        ("score [ioc_file]",       "Score findings (optional IOC file)"),
        ("ask <question>",         "Natural language query"),
        ("status",                 "Show case dashboard"),
        ("report",                 "Generate NIST report"),
        ("help",                   "Show this help"),
        ("quit",                   "Save and exit"),
    ]
    for cmd, desc in cmds:
        help_table.add_row(cmd, desc)
    console.print(help_table)


def _interactive_ingest(orch, args: str):
    parts = args.split()
    if len(parts) < 2:
        print_warning("Usage: ingest <engine> <filepath> [--offset N]")
        return

    engine, filepath = parts[0], parts[1]
    kwargs = {}
    if "--offset" in parts:
        idx = parts.index("--offset")
        if idx + 1 < len(parts):
            kwargs["partition_offset"] = parts[idx + 1]

    path = Path(filepath)
    if not path.exists():
        print_error(f"File not found: {filepath}")
        return

    with create_engine_progress() as progress:
        task = progress.add_task(f"Running {engine}…", total=100)
        progress.update(task, advance=10)
        try:
            findings = orch.ingest(path, engine, **kwargs)
            progress.update(task, advance=90)
        except Exception as exc:
            progress.stop()
            print_error(f"Engine error: {exc}")
            return

    print_success(f"{engine} produced [bold]{len(findings)}[/bold] findings")


def _interactive_score(orch, args: str):
    if args:
        ioc_path = Path(args.strip())
        if ioc_path.exists():
            orch.load_iocs(ioc_path)
            print_success(f"Loaded IOCs from {ioc_path}")

    ranked = orch.score_all()
    table = build_findings_table(ranked, max_rows=15)
    console.print(table)


def _interactive_ask(orch, question: str):
    if not orch.findings:
        print_warning("No findings loaded. Ingest evidence first.")
        return

    print_info("Building index and searching…")
    orch.build_index()
    result = orch.ask(question)
    print_query_results(result)


if __name__ == "__main__":
    main()
