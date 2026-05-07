"""
autofix.py -- Generates and executes AWS CLI remediation commands.
POWERED BY AI. Use with caution.
"""

import subprocess
import json
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.syntax import Syntax

console = Console()

FIX_PROMPT = (
    "You are an AWS Automation Expert. Based on the security finding below, "
    "generate EXACTLY ONE AWS CLI command to fix the issue. "
    "Output ONLY the command string and nothing else. No markdown, no explanations. "
    "Example: aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration ..."
)

def generate_fix_command(finding: dict, provider) -> str:
    """
    Calls the AI provider to generate a ready-to-run AWS CLI command.
    """
    # Create a safe copy for the prompt
    safe_finding = {
        "service": finding.get("service"),
        "resource_name": finding.get("resource_name"),
        "issue": finding.get("issue"),
        "details": finding.get("details"),
        "region": finding.get("region")
    }
    
    prompt = f"Security Finding to Fix:\n{json.dumps(safe_finding, indent=2)}"
    
    with console.status("[bold yellow]Generating AI Fix Command...[/bold yellow]"):
        command = provider.complete(prompt, system_prompt=FIX_PROMPT, max_tokens=200)
    
    return command.strip().replace("`", "")

def apply_fix(command: str) -> bool:
    """
    Executes a shell command. Returns True on success.
    """
    if not command.startswith("aws "):
        console.print("[bold red][!] Security Violation: AI generated command does not start with 'aws '. Execution blocked.[/bold red]")
        return False
        
    try:
        from datetime import datetime, timezone
        with open("cloudguard_audit.log", "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now(timezone.utc).isoformat()}] EXEC: {command}\n")
            
        # We use shell=True to allow complex CLI commands, but we've sanitised 
        # the resource names previously in the pipeline.
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        console.print("[bold green][OK] Fix Applied Successfully![/bold green]")
        if result.stdout:
            console.print(f"[dim]{result.stdout.strip()}[/dim]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red][FAIL] Fix Failed![/bold red]")
        console.print(f"[red]Error: {e.stderr.strip()}[/red]")
        return False
    except Exception as e:
        console.print(f"[bold red][FAIL] Execution Error: {e}[/bold red]")
        return False

def run_autofix_session(findings: list[dict], provider):
    """
    Interactive loop to review and apply fixes for findings.
    """
    if not findings:
        return

    console.print(Panel(
        "[bold red][!] WARNING: AUTO-FIX MODE ENABLED[/bold red]\n\n"
        "CloudGuard AI will now generate and execute AWS CLI commands on your behalf.\n"
        "Executing these commands will modify your real AWS infrastructure.\n"
        "Always review the command before confirming execution.",
        title="[bold yellow]Security Warning[/bold yellow]",
        border_style="red"
    ))

    fixes_applied = 0
    
    for finding in findings:
        if finding.get("severity") not in ("Critical", "High"):
            continue
            
        resource = finding.get("resource_name", "Unknown")
        issue = finding.get("issue", "Unknown")
        
        console.print(f"\n[bold cyan]Target:[/bold cyan] {resource}")
        console.print(f"[bold cyan]Issue: [/bold cyan] {issue}")
        
        should_gen = Confirm.ask("Generate AI fix for this finding?", default=True)
        if not should_gen:
            continue
            
        command = generate_fix_command(finding, provider)
        
        console.print("\n[bold yellow]Proposed Fix (AWS CLI):[/bold yellow]")
        console.print(Syntax(command, "bash", theme="monokai", line_numbers=False))
        console.print()
        
        if Confirm.ask("[bold red]Execute this command now?[/bold red]", default=False):
            if apply_fix(command):
                fixes_applied += 1
        else:
            console.print("[dim]Fix skipped by user.[/dim]")

    console.print(f"\n[bold green]Auto-Fix Session Complete. Total fixes applied: {fixes_applied}[/bold green]")

def export_remediation_script(findings: list[dict], provider, filename: str = None):
    """
    Generates an AI-powered bash script for reviewing and applying fixes.
    """
    if not findings:
        return
        
    from datetime import datetime
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cloudguard_remediate_{timestamp}.sh"
        
    console.print(f"[bold cyan]Exporting remediation script to {filename}...[/bold cyan]")
    
    script_content = [
        "#!/bin/bash",
        "# ================================================================",
        f"# CloudGuard AI - Remediation Script (Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})",
        "# ================================================================",
        "set -e",
        "",
        'echo "[!] WARNING: This script will modify your AWS infrastructure."',
        'read -p "Press Enter to continue or Ctrl+C to cancel..."',
        ""
    ]
    
    exported_count = 0
    for finding in findings:
        if finding.get("severity") not in ("Critical", "High"):
            continue
            
        resource = finding.get("resource_name", "Unknown")
        issue = finding.get("issue", "Unknown")
        
        command = generate_fix_command(finding, provider)
        if not command.startswith("aws "):
             continue
             
        script_content.append(f"# Target: {resource}")
        script_content.append(f"# Issue: {issue}")
        script_content.append(f'echo "----------------------------------------------------------------"')
        script_content.append(f'echo "Proposed Fix: {command}"')
        script_content.append(f'read -p "Apply this fix? (y/n): " choice')
        script_content.append('if [ "$choice" == "y" ]; then')
        script_content.append(f"    {command}")
        script_content.append('    echo "[OK] Fix Applied."')
        script_content.append("else")
        script_content.append('    echo "Skipped."')
        script_content.append("fi")
        script_content.append("")
        exported_count += 1
        
    try:
        with open(filename, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(script_content))
            
        # Try to make it executable (works on Unix-like systems)
        try:
            os.chmod(filename, 0o755)
        except:
            pass
            
        console.print(f"[bold green][OK] Exported {exported_count} fixes to {filename}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to export script: {e}[/bold red]")
