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
from datetime import datetime

console = Console()

BANNER = r"""
   ____ _                 _  ____                      _      _    ___ 
  / ___| | ___  _   _  __| |/ ___|_   _  __ _ _ __ __| |    / \  |_ _|
 | |   | |/ _ \| | | |/ _` | |  _| | | |/ _` | '__/ _` |   / _ \  | | 
 | |___| | (_) | |_| | (_| | |_| | |_| | (_| | | | (_| |  / ___ \ | | 
  \____|_|\___/ \__,_|\__,_|\____|\__,_|\__,_|_|  \__,_| /_/   \_\___|
"""


def main():
    # Load .env (API keys, provider choice, model)
    load_dotenv()

    # Banner
    console.print(
        Panel(
            Text(BANNER, style="bold cyan", justify="center"),
            subtitle="[bold white]AWS Security Auditor[/bold white]",
            border_style="cyan",
        )
    )
    console.print("[bold blue]Starting CloudGuard AI scan...[/bold blue]\n")

    # Step 1: Connect
    session = scanner.connect_aws()
    console.print()

    # Step 2: Scan
    all_findings = []

    if isinstance(session, dict) and session.get("mock"):
        console.print(
            "[bold yellow]Running in MOCK mode - no AWS costs.[/bold yellow]\n"
        )
        all_findings.extend(scanner.scan_mock_aws())
    else:
        all_findings.extend(scanner.scan_s3_buckets(session))
        console.print()
        all_findings.extend(scanner.scan_security_groups(session))
        console.print()
        all_findings.extend(scanner.scan_iam(session))

    console.print()

    # Step 3: AI Advice
    enriched = ai_advisor.get_ai_advice(all_findings)

    # Step 4: Report (saves to a unique timestamped file)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"cloudguard_report_{timestamp}.json"
    
    report.generate_report(enriched, filename=report_filename)

    console.print(
        f"[bold magenta]Scan complete. Report saved to "
        f"{report_filename}[/bold magenta]\n"
    )


if __name__ == "__main__":
    main()
