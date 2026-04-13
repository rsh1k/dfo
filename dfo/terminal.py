"""
dfo/terminal.py
===============
Centralized color theming and terminal output utilities using Rich.
"""

from rich.console import Console
from rich.theme import Theme
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.tree import Tree

# ---------------------------------------------------------------------------
# Global Theme
# ---------------------------------------------------------------------------

DFO_THEME = Theme({
    "critical":     "bold red",
    "high":         "dark_orange",
    "medium":       "yellow",
    "low":          "green",
    "info":         "cyan",
    "header":       "bold bright_cyan",
    "subheader":    "bold bright_white",
    "accent":       "magenta",
    "muted":        "dim white",
    "success":      "bold green",
    "error":        "bold red",
    "warning":      "bold yellow",
    "engine.tshark":      "bright_blue",
    "engine.volatility3": "bright_magenta",
    "engine.ghidra":      "bright_red",
    "engine.sleuthkit":   "bright_yellow",
    "cat.network":  "bright_blue",
    "cat.memory":   "bright_magenta",
    "cat.binary":   "bright_red",
    "cat.disk":     "bright_yellow",
    "query":        "bold bright_magenta",
    "relevance":    "bright_cyan",
})

console = Console(theme=DFO_THEME)


def severity_style(score: float) -> str:
    if score >= 0.8: return "critical"
    if score >= 0.6: return "high"
    if score >= 0.3: return "medium"
    return "low"

def severity_label(score: float) -> str:
    if score >= 0.8: return "CRITICAL"
    if score >= 0.6: return "HIGH"
    if score >= 0.3: return "MEDIUM"
    return "LOW"

def severity_icon(score: float) -> str:
    if score >= 0.8: return "🔴"
    if score >= 0.6: return "🟠"
    if score >= 0.3: return "🟡"
    return "🟢"

def engine_style(engine: str) -> str:
    return f"engine.{engine}" if engine in (
        "tshark", "volatility3", "ghidra", "sleuthkit"
    ) else "info"

def category_style(category: str) -> str:
    return f"cat.{category}" if category in (
        "network", "memory", "binary", "disk"
    ) else "info"


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
[bold bright_cyan]
    ____  ____________
   / __ \/ ____/ __ \
  / / / / /_  / / / /
 / /_/ / __/ / /_/ /
/_____/_/    \____/
[/bold bright_cyan]
[bold white]Digital Forensics Orchestrator[/bold white]
[dim]NIST SP 800-86 · SP 800-61 Rev.2 Compliant[/dim]
"""

def print_banner():
    console.print(BANNER)

def print_header(text: str):
    console.print()
    console.rule(f"[header] {text} [/header]", style="bright_cyan")
    console.print()

def print_success(text: str):
    console.print(f"  [success]✓[/success] {text}")

def print_error(text: str):
    console.print(f"  [error]✗[/error] {text}")

def print_warning(text: str):
    console.print(f"  [warning]⚠[/warning] {text}")

def print_info(text: str):
    console.print(f"  [info]ℹ[/info] {text}")


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------

def build_findings_table(findings: list, title: str = "Ranked Findings",
                         max_rows: int = 25) -> Table:
    table = Table(
        title=f"[header]{title}[/header]",
        show_header=True,
        header_style="bold bright_white on dark_blue",
        border_style="bright_cyan",
        row_styles=["", "dim"],
        expand=True,
    )
    table.add_column("#", style="muted", width=4, justify="right")
    table.add_column("Sev", width=5, justify="center")
    table.add_column("Score", width=7, justify="right")
    table.add_column("Category", width=10)
    table.add_column("Engine", width=13)
    table.add_column("Title", width=28)
    table.add_column("IOCs", width=6, justify="center")
    table.add_column("Description", ratio=1)

    for i, f in enumerate(findings[:max_rows], 1):
        sev = severity_style(f.severity_score)
        icon = severity_icon(f.severity_score)
        ioc_count = str(len(f.ioc_matches)) if f.ioc_matches else "-"
        desc = (f.description[:80] + "…") if len(f.description) > 80 else f.description
        table.add_row(
            str(i),
            f"[{sev}]{icon}[/{sev}]",
            f"[{sev}]{f.severity_score:.3f}[/{sev}]",
            f"[{category_style(f.category.value)}]{f.category.value}[/]",
            f"[{engine_style(f.engine)}]{f.engine}[/]",
            f.title,
            f"[muted]{ioc_count}[/muted]",
            desc,
        )
    return table


# ---------------------------------------------------------------------------
# NLI query results — reads directly from page_content, not metadata
# ---------------------------------------------------------------------------

def print_query_results(result: dict):
    """Pretty-print NLI query results."""
    console.print()
    console.print(
        Panel(
            f"[query]{result['query']}[/query]",
            title="[bold bright_white]🔍 Natural Language Query[/]",
            border_style="magenta",
            padding=(0, 2),
        )
    )

    # Print AI answer if available
    ai_answer = result.get("ai_answer", "")
    if ai_answer:
        console.print()
        console.print(
            Panel(
                ai_answer,
                title="[bold bright_white]🤖 AI Analysis[/]",
                border_style="bright_cyan",
                padding=(1, 2),
            )
        )

    console.print(
        f"\n  [muted]Retrieved {result['retrieved_count']} "
        f"relevant findings[/muted]\n"
    )

    for i, item in enumerate(result["findings"], 1):
        meta = item.get("metadata", {})
        sev = meta.get("severity", 0)
        style = severity_style(sev)
        icon = severity_icon(sev)
        relevance = item.get("relevance", 0)

        # Get title and description from metadata first, fallback to page_content
        title = meta.get("title", "")
        description = meta.get("description", "")

        # If metadata is empty, extract from page_content text
        if not title or not description:
            text = item.get("text", "")
            for line in text.split("\n"):
                line = line.strip()
                if line.startswith("Title:") and not title:
                    title = line[6:].strip()
                elif line.startswith("Description:") and not description:
                    description = line[12:].strip()

        # Final fallback
        if not title:
            title = "Finding"
        if not description:
            description = item.get("text", "No data")[:200]

        category = meta.get("category", "unknown")
        engine = meta.get("engine", "unknown")

        console.print(
            Panel(
                Text.from_markup(
                    f"[bold]{title}[/bold]\n"
                    f"[{category_style(category)}]{category}[/] · "
                    f"[{engine_style(engine)}]{engine}[/]\n\n"
                    f"{description}\n\n"
                    f"[relevance]Relevance: {relevance:.1%}[/relevance]"
                ),
                title=(
                    f"{icon} Result {i}  "
                    f"[{style}]{severity_label(sev)}[/{style}]  "
                    f"[muted]score={sev:.3f}[/muted]"
                ),
                border_style=style,
                padding=(0, 2),
            )
        )


# ---------------------------------------------------------------------------
# Status dashboard
# ---------------------------------------------------------------------------

def print_case_status(case_id: str, findings: list,
                      custody_count: int, engines_run: list[str]):
    print_header(f"Case Status: {case_id}")
    tree = Tree(f"[header]📂 Case {case_id}[/header]")
    evidence = tree.add("[subheader]📋 Evidence[/subheader]")
    evidence.add(f"[info]Chain-of-custody entries:[/info] {custody_count}")
    eng_branch = tree.add("[subheader]⚙️  Engines Executed[/subheader]")
    for eng in engines_run:
        eng_branch.add(f"[{engine_style(eng)}]{eng}[/]")
    stats = tree.add("[subheader]📊 Findings Summary[/subheader]")
    crit = sum(1 for f in findings if f.severity_score >= 0.8)
    high = sum(1 for f in findings if 0.6 <= f.severity_score < 0.8)
    med = sum(1 for f in findings if 0.3 <= f.severity_score < 0.6)
    low = sum(1 for f in findings if f.severity_score < 0.3)
    stats.add(f"Total: [bold]{len(findings)}[/bold]")
    stats.add(f"[critical]🔴 CRITICAL: {crit}[/critical]")
    stats.add(f"[high]🟠 HIGH:     {high}[/high]")
    stats.add(f"[medium]🟡 MEDIUM:   {med}[/medium]")
    stats.add(f"[low]🟢 LOW:      {low}[/low]")
    console.print(tree)
    console.print()


def create_engine_progress() -> Progress:
    return Progress(
        SpinnerColumn(style="bright_cyan"),
        TextColumn("[bold bright_white]{task.description}[/]"),
        BarColumn(bar_width=30, style="bright_cyan", complete_style="green"),
        TextColumn("[muted]{task.percentage:>3.0f}%[/muted]"),
        console=console,
    )
