"""
chat_mode.py -- Conversational REPL for CloudGuard AI.
Allows users to ask follow-up questions about their security scan.

Built with LiteLLM: https://github.com/BerriAI/litellm
Full credit to BerriAI for the universal LLM abstraction layer.
"""

import os
import concurrent.futures
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.columns import Columns
from rich.markdown import Markdown
from rich.live import Live
from rich.spinner import Spinner
from rich.rule import Rule

console = Console()

def format_findings_for_context(findings: list[dict]) -> str:
    """
    Formats findings as a numbered readable list for the AI's system prompt.
    """
    if not findings:
        return "No misconfigurations were found."
    
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(
            f"{i}. [{f.get('severity', 'Unknown')}] {f.get('service', 'AWS')}: {f.get('resource_name', 'Unknown')}\n"
            f"   Issue: {f.get('issue', 'Unknown')}\n"
            f"   Region: {f.get('region', 'global')}\n"
            f"   Details: {f.get('details', '')}\n"
        )
    return "\n".join(lines)

def build_system_context(findings: list[dict]) -> str:
    """
    Builds the initial system prompt with scan results as context.
    """
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Unknown")
        if sev in counts:
            counts[sev] += 1
            
    summary = f"Critical: {counts['Critical']}, High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}"
    findings_list = format_findings_for_context(findings)
    
    prompt = (
        "You are CloudGuard AI, a world-class cloud security expert.\n"
        "You just finished scanning an AWS environment and found the following issues:\n\n"
        f"SUMMARY: {summary}\n\n"
        "DETAILED FINDINGS:\n"
        f"{findings_list}\n\n"
        "Answer the user's questions about these findings. Be specific, concise, and provide actionable advice. "
        "If they ask for a fix, provide the AWS CLI command or Terraform code."
    )
    return prompt

def run_chat(findings: list[dict], provider, compare_models: list[str] = None):
    """
    The main REPL loop. Maintains history across turns.
    Supports single model mode and comparison mode (side-by-side).
    """
    system_prompt = build_system_context(findings)
    
    # History for single/primary model
    history = [{"role": "system", "content": system_prompt}]
    # Second history for comparison mode to keep them independent
    history_compare = [{"role": "system", "content": system_prompt}] if compare_models else None

    console.print(Rule(" [bold magenta]CloudGuard Chat Mode[/bold magenta] ", style="magenta"))
    console.print("[dim]Type 'exit' or 'quit' to end the session.[/dim]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]Query[/bold cyan]")
            
            if user_input.lower() in ["exit", "quit"]:
                console.print("[bold yellow]Exiting chat mode. Goodbye![/bold yellow]")
                break

            # Add user message to history
            history.append({"role": "user", "content": user_input})
            if history_compare:
                history_compare.append({"role": "user", "content": user_input})

            if compare_models and len(compare_models) >= 2:
                # Comparison Mode: Side-by-Side
                m1, m2 = compare_models[0], compare_models[1]
                from adapters.litellm_adapter import LiteLLMAdapter
                
                with Live(Spinner("dots", text=f"Querying {m1} and {m2}..."), refresh_per_second=10) as live:
                    # Run both models in parallel
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        f1 = executor.submit(LiteLLMAdapter(model_override=m1).chat, history)
                        f2 = executor.submit(LiteLLMAdapter(model_override=m2).chat, history_compare)
                        
                        ans1 = f1.result()
                        ans2 = f2.result()
                    
                    p1 = Panel(Markdown(ans1), title=f"[bold green]{m1}[/bold green]", border_style="green")
                    p2 = Panel(Markdown(ans2), title=f"[bold blue]{m2}[/bold blue]", border_style="blue")
                    
                    live.update(Columns([p1, p2], equal=True))
                
                # Update histories with assistant responses
                history.append({"role": "assistant", "content": ans1})
                history_compare.append({"role": "assistant", "content": ans2})
                
            else:
                # Standard Mode using the generic provider
                model_name = provider.get_name()
                with console.status(f"[bold green]Thinking ({model_name})...[/bold green]"):
                    answer = provider.chat(history)
                    history.append({"role": "assistant", "content": answer})
                    
                console.print(Panel(Markdown(answer), title=f"[bold green]{model_name}[/bold green]", border_style="green"))
            
            console.print()

        except KeyboardInterrupt:
            console.print("\n[bold yellow]Session interrupted. Goodbye![/bold yellow]")
            break
        except Exception as e:
            console.print(f"[bold red]API Error: {e}[/bold red]")
            # Continue the loop instead of breaking to preserve history
            continue
