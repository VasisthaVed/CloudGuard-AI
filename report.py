import json
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.columns import Columns
from rich.text import Text

console = Console()


def _severity_bar(counts: dict) -> str:
    """Build a small inline bar showing severity distribution."""
    total = sum(counts.values())
    if total == 0:
        return "[dim]No findings[/dim]"

    parts = []
    colors = {
        "Critical": "red",
        "High": "yellow",
        "Medium": "bright_yellow",
        "Low": "green",
    }
    for sev in ["Critical", "High", "Medium", "Low"]:
        n = counts.get(sev, 0)
        if n > 0:
            blocks = "#" * n  # safe block character
            parts.append(f"[{colors[sev]}]{blocks}[/{colors[sev]}]")
    return " ".join(parts) if parts else "[dim]None[/dim]"


def generate_report(findings, filename="cloudguard_report.json"):
    """
    Formats and saves the security findings (with AI advice) to a JSON report.
    Prints a severity summary table and an overall risk score.
    """
    if not findings:
        console.print("[yellow]No findings to report.[/yellow]")
        return

    console.print(f"[bold cyan]Saving report to {filename}...[/bold cyan]")

    # 1. Severity counts
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        sev = finding.get("severity", "Unknown")
        if sev in counts:
            counts[sev] += 1

    # 2. Risk score
    score = (counts["Critical"] * 10) + (counts["High"] * 5) + (counts["Medium"] * 2)

    if score >= 50:
        score_color = "bold red"
        score_label = "CRITICAL"
        score_emoji = "[X]"
    elif score >= 20:
        score_color = "bold yellow"
        score_label = "ELEVATED"
        score_emoji = "[!]"
    else:
        score_color = "bold green"
        score_label = "LOW"
        score_emoji = "[v]"

    # 3. Save JSON with audit metadata
    report_data = {
        "tool": "CloudGuard AI",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "audit_metadata": {
            "overall_risk_score": score,
            "risk_level": score_label,
            "severity_counts": counts,
            "formula": "Critical*10 + High*5 + Medium*2",
        },
        "findings": findings,
    }

    try:
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=4, default=str)
        console.print(f"[bold green]Report saved to {filename}[/bold green]\n")
    except Exception as e:
        console.print(f"[bold red]Failed to save report: {e}[/bold red]")

    # 4. Severity summary table
    table = Table(
        title="[bold]Findings Summary[/bold]",
        show_header=True,
        header_style="bold",
        border_style="dim",
        padding=(0, 2),
    )
    table.add_column("Severity", justify="left", min_width=12)
    table.add_column("Count", justify="center", min_width=7)
    table.add_column("Impact", justify="left", min_width=15)

    sev_config = [
        ("Critical", "bold red", "[X]", "x10 risk weight"),
        ("High",     "bold yellow", "[!]", "x5 risk weight"),
        ("Medium",   "bright_yellow", "[-]", "x2 risk weight"),
        ("Low",      "green", "[v]", "x0 risk weight"),
    ]

    for sev, style, icon, impact in sev_config:
        count = counts[sev]
        count_display = f"[{style}]{count}[/{style}]" if count > 0 else "[dim]0[/dim]"
        table.add_row(
            f"[{style}]{icon} {sev}[/{style}]",
            count_display,
            f"[dim]{impact}[/dim]",
        )

    console.print(table)

    # 5. Risk score panel
    bar = _severity_bar(counts)
    console.print(
        Panel(
            f"[{score_color}]{score_emoji} Risk Score: {score}  ({score_label})[/{score_color}]\n\n"
            f"  {bar}\n\n"
            f"  [dim]Formula: (Critical x10) + (High x5) + (Medium x2)\n"
            f"           ({counts['Critical']}x10) + ({counts['High']}x5) + ({counts['Medium']}x2) = {score}[/dim]",
            border_style="dim",
            padding=(1, 3),
        )
    )

    # 6. Preview one piece of AI Advice in the terminal, nicely formatted
    for finding in findings:
        advice = finding.get("ai_advice", "")
        # Because we split it into a list in ai_advisor, we need to join it back for Markdown rendering
        if isinstance(advice, list):
            advice = "\n\n".join(advice)

        if advice and not advice.startswith("Failed ") and not advice.startswith("Skipped "):
            md = Markdown(advice)

            # If AI Comparison was on, add the meta info
            judge_info = finding.get("judge_info")
            resource = finding.get("resource_name", "Unknown")
            severity = finding.get("severity", "Unknown")

            if judge_info:
                title_text = (
                    f"[cyan]AI Remediation:[/cyan] [bold]{resource}[/bold]  "
                    f"[dim]({severity})[/dim]"
                )
                subtitle_text = (
                    f"[magenta]Winner:[/magenta] {judge_info.get('winning_model')}  "
                    f"[magenta]Confidence:[/magenta] {judge_info.get('confidence_score')}"
                )
            else:
                title_text = (
                    f"[cyan]AI Remediation:[/cyan] [bold]{resource}[/bold]  "
                    f"[dim]({severity})[/dim]"
                )
                subtitle_text = None

            preview_panel = Panel(
                md,
                title=title_text,
                subtitle=subtitle_text,
                border_style="green",
                padding=(1, 3),
            )
            console.print(preview_panel)

            if judge_info:
                console.print(
                    f"  [dim italic]Judge Reasoning: "
                    f"{judge_info.get('reasoning')}[/dim italic]"
                )

            console.print(
                f"[dim]... See {filename} for all "
                f"{len(findings)} findings with AI remediation ...[/dim]\n"
            )
            break


if __name__ == "__main__":
    generate_report(
        [
            {"severity": "Critical", "resource_name": "test"},
            {"severity": "High", "resource_name": "test2"},
            {"severity": "Medium", "resource_name": "test3"},
        ]
    )
