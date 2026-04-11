import json
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()


def generate_report(findings, filename="cloudguard_report.json"):
    """
    Formats and saves the security findings (with AI advice) to a JSON report.
    Prints a severity summary table and an overall risk score.
    """
    if not findings:
        console.print("[yellow]No findings to report.[/yellow]")
        return

    console.print(f"\n[bold cyan]Saving report to {filename}...[/bold cyan]")

    # 1. Save JSON with timestamp
    report_data = {
        "tool": "CloudGuard AI",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }

    try:
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=4, default=str)
        console.print(f"[bold green]Report saved to {filename}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to save report: {e}[/bold red]")

    # 2. Severity summary table
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        sev = finding.get("severity", "Unknown")
        if sev in counts:
            counts[sev] += 1

    table = Table(title="Findings Summary")
    table.add_column("Severity", justify="left")
    table.add_column("Count", justify="right")

    table.add_row("[bold red]Critical[/bold red]", str(counts["Critical"]))
    table.add_row("[bold yellow]High[/bold yellow]", str(counts["High"]))
    table.add_row("[bright_yellow]Medium[/bright_yellow]", str(counts["Medium"]))
    table.add_row("[green]Low[/green]", str(counts["Low"]))

    console.print(table)

    # 3. Risk score
    score = (counts["Critical"] * 10) + (counts["High"] * 5) + (counts["Medium"] * 2)

    if score >= 50:
        score_color = "bold red"
    elif score >= 20:
        score_color = "bold yellow"
    else:
        score_color = "bold green"

    console.print(f"\n[bold]Overall Risk Score:[/bold] [{score_color}]{score}[/{score_color}]")
    console.print(
        f"[dim]Formula: (Critical x10) + (High x5) + (Medium x2) = "
        f"({counts['Critical']}x10) + ({counts['High']}x5) + ({counts['Medium']}x2) = {score}[/dim]\n"
    )

    # 4. Preview one piece of AI Advice in the terminal nicely formatted
    for finding in findings:
        advice = finding.get("ai_advice", "")
        # Because we split it into a list in ai_advisor, we need to join it back for Markdown rendering
        if isinstance(advice, list):
            advice = "\n\n".join(advice)
            
        if advice and not advice.startswith("Failed ") and not advice.startswith("Skipped "):
            md = Markdown(advice)
            preview_panel = Panel(
                md, 
                title=f"[cyan]AI Explanation & Fix:[/cyan] [bold]{finding.get('resource_name')}[/bold]", 
                border_style="green",
                padding=(1, 2)
            )
            console.print(preview_panel)
            console.print("[dim]... (View cloudguard_report*.json for all findings) ...[/dim]\n")
            break


if __name__ == "__main__":
    generate_report(
        [
            {"severity": "Critical", "resource_name": "test"},
            {"severity": "High", "resource_name": "test2"},
            {"severity": "Medium", "resource_name": "test3"},
        ]
    )
