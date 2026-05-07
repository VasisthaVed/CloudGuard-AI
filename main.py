"""
main.py -- Entry point for CloudGuard AI.

Workflow:
  1. Load .env  ->  2. Connect AWS (or mock)  ->  3. Run scanners
  4. AI advice  ->  5. Generate report
"""

import scanner
import ai_advisor
import report
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from datetime import datetime
import time
import argparse
import chat_mode
import autofix
import html_report
from adapters import get_provider

console = Console()

BANNER = r"""
   ____ _                 _  ____                      _      _    ___ 
  / ___| | ___  _   _  __| |/ ___|_   _  __ _ _ __ __| |    / \  |_ _|
 | |   | |/ _ \| | | |/ _` | |  _| | | |/ _` | '__/ _` |   / _ \  | | 
 | |___| | (_) | |_| | (_| | |_| | |_| | (_| | | | (_| |  / ___ \ | | 
  \____|_|\___/ \__,_|\__,_|\____|\__,_|\__,_|_|  \__,_| /_/   \_\___|
"""

VERSION = "2.0.0"


def _phase_header(step: int, title: str, icon: str = ">"):
    """Print a styled phase header."""
    console.print()
    console.print(Rule(f" {icon}  Step {step}: {title} ", style="bold cyan"))
    console.print()


def main():
    # Load .env (API keys, provider choice, model)
    load_dotenv()

    parser = argparse.ArgumentParser(description="CloudGuard AI - AWS Security Auditor")
    parser.add_argument("--chat", action="store_true", help="Enter chat mode automatically after scan")
    parser.add_argument("--compare", nargs=2, metavar=("MODEL1", "MODEL2"), help="Compare two models side-by-side in chat mode")
    parser.add_argument("--fix", action="store_true", help="Enter Auto-Fix mode to remediate findings")
    parser.add_argument("--export-fix", action="store_true", help="Export AI remediation commands to a .sh script")
    parser.add_argument("--html", action="store_true", help="Generate a visual HTML report (Cyber-Slate dashboard)")
    args = parser.parse_args()

    scan_start = time.time()

    # Banner
    console.print(
        Panel(
            Text(BANNER, style="bold cyan", justify="center"),
            subtitle=f"[bold white]AWS Security Auditor  v{VERSION}[/bold white]",
            border_style="cyan",
        )
    )
    console.print(
        f"[dim]Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]"
    )

    # Step 1: Connect
    _phase_header(1, "AWS Connection", ">>>")
    session = scanner.connect_aws()

    # Step 2: Scan
    _phase_header(2, "Security Scanning", "***")
    all_findings = []

    if isinstance(session, dict) and session.get("mock"):
        console.print(
            Panel(
                "[bold yellow]Running in MOCK mode[/bold yellow]\n"
                "[dim]No AWS costs incurred. Using simulated findings for demo.[/dim]",
                border_style="yellow",
                padding=(0, 2),
            )
        )
        console.print()
        all_findings.extend(scanner.scan_mock_aws())
    else:
        all_findings.extend(scanner.scan_all_regions(session))

    findings_count = len(all_findings)
    if findings_count > 0:
        console.print(
            f"\n[bold]Total misconfigurations found: "
            f"[bold red]{findings_count}[/bold red][/bold]"
        )
    else:
        console.print("\n[bold green]No misconfigurations found![/bold green]")

    # Step 3: AI Advice
    _phase_header(3, "AI Analysis", "###")
    enriched = ai_advisor.get_ai_advice(all_findings)

    # Step 4: Report (saves to a unique timestamped file)
    _phase_header(4, "Report Generation", "+++")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"cloudguard_report_{timestamp}.json"
    report.generate_report(enriched, filename=report_filename)

    # HTML Report (optional)
    if args.html:
        counts  = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in enriched:
            sev = f.get("severity", "Low")
            if sev in counts:
                counts[sev] += 1
        risk_score = counts["Critical"] * 10 + counts["High"] * 5 + counts["Medium"] * 2
        risk_level = "CRITICAL" if risk_score >= 50 else ("ELEVATED" if risk_score >= 20 else "LOW")
        html_filename = f"cloudguard_report_{timestamp}.html"
        out = html_report.generate_html_report(enriched, risk_score=risk_score, risk_level=risk_level, filename=html_filename)
        console.print(f"[bold cyan]HTML Report: [link=file:///{out}]{out}[/link][/bold cyan]")

    # Final Summary
    duration = time.time() - scan_start
    console.print()
    console.print(
        Panel(
            f"[bold green]Scan Complete![/bold green]\n\n"
            f"  [bold]Report:[/bold]    {report_filename}\n"
            f"  [bold]Findings:[/bold]  {findings_count}\n"
            f"  [bold]Duration:[/bold]  {duration:.1f}s",
            title="[bold cyan]CloudGuard AI Summary[/bold cyan]",
            border_style="green",
            padding=(1, 3),
        )
    )
    console.print()

    # Step 5: Auto-Fix Mode (Optional)
    provider = None
    if args.fix or args.export_fix:
        provider = get_provider()
        if args.fix:
            autofix.run_autofix_session(all_findings, provider)
        if args.export_fix:
            autofix.export_remediation_script(all_findings, provider)

    # Step 6: Chat Mode (Optional REPL)
    if args.chat or args.compare:
        # Get provider if not already obtained in fix mode
        if not provider:
            provider = get_provider()
        chat_mode.run_chat(all_findings, provider, compare_models=args.compare)
    else:
        # Only prompt if not in fix mode (to avoid prompt overload)
        if not args.fix:
            choice = console.input("[bold cyan]Enter Chat Mode to discuss findings? (y/n): [/bold cyan]").lower()
            if choice == "y":
                provider = get_provider()
                chat_mode.run_chat(all_findings, provider)

    console.print()


if __name__ == "__main__":
    main()
