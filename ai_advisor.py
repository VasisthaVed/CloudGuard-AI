"""
ai_advisor.py -- Sends each finding to an AI model for plain-English
                  remediation advice.

Supported providers (set AI_PROVIDER in .env):
  - "openrouter"  - default, uses the OpenAI-compatible API at openrouter.ai
  - "anthropic"   - uses the Anthropic Python SDK (claude-3-haiku)

Data safety:
  Before any finding is sent to a third-party API we strip it down to only
  the keys that are needed for the AI to understand the issue. No raw AWS
  account IDs, ARNs, or internal resource names are forwarded.
"""

import json
import os
import re
from rich.console import Console
from rich.panel import Panel

console = Console()

# -- Prompt shared by every provider ------------------------------------
SYSTEM_PROMPT = (
    "You are a cloud security expert. First, explain the given AWS security finding "
    "in 2-3 plain English sentences that a junior engineer can understand. "
    "Press Enter twice to start a new paragraph. "
    "Then, provide 2-3 specific remediation steps formatted as bullet points "
    "with brief AWS CLI or Console instructions."
)

# -- Free model list (for reference) ------------------------------------
FREE_MODELS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "google/gemma-3-27b-it:free",
    "deepseek/deepseek-r1:free",
    "qwen/qwen3-next-80b:free",
    "mistralai/mistral-small-3.1-24b-instruct:free",
    "nvidia/llama-3.1-nemotron-70b-instruct:free",
]

DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct:free"


# -- Data sanitisation --------------------------------------------------
def _sanitise_finding(finding: dict) -> dict:
    """
    Return a COPY of the finding with sensitive info scrubbed so we never
    leak real AWS account IDs, ARNs, or bucket names to a third-party API.
    """
    safe = {
        "service":  finding.get("service", "Unknown"),
        "issue":    finding.get("issue", "Unknown"),
        "severity": finding.get("severity", "Unknown"),
        "details":  finding.get("details", ""),
    }

    # Keep resource_name but mask sensitive patterns
    resource = finding.get("resource_name", "Unknown")
    resource = re.sub(r"\b\d{12}\b", "XXXXXXXXXXXX", resource)
    resource = re.sub(r"arn:aws:[^\"'\s]+", "arn:aws:***REDACTED***", resource)
    safe["resource_name"] = resource

    return safe


# -- Provider helpers ---------------------------------------------------
def _call_anthropic(prompt: str) -> str:
    """Call Anthropic Claude API (lazy import)."""
    from anthropic import Anthropic

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set. Add it to your .env file.")

    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=200,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def _call_openrouter(prompt: str) -> str:
    """Call OpenRouter API (OpenAI-compatible, supports many free models)."""
    from openai import OpenAI

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError(
            "OPENROUTER_API_KEY not set. "
            "Get a free key at https://openrouter.ai and add it to .env"
        )

    model = os.getenv("OPENROUTER_MODEL", DEFAULT_MODEL)

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )
    response = client.chat.completions.create(
        model=model,
        max_tokens=200,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content


# -- Provider registry --------------------------------------------------
_PROVIDERS = {
    "anthropic":  _call_anthropic,
    "openrouter": _call_openrouter,
}


# -- Public API ---------------------------------------------------------
def get_ai_advice(findings_list: list) -> list:
    """
    For each finding dict, call the configured AI provider and append an
    'ai_advice' key with the response.  Returns the mutated list.

    Provider is selected by the AI_PROVIDER env var (default: openrouter).
    """
    if not findings_list:
        console.print("[bold yellow]No findings to send to AI Advisor.[/bold yellow]")
        return findings_list

    provider = os.getenv("AI_PROVIDER", "openrouter").lower().strip()

    call_fn = _PROVIDERS.get(provider)
    if call_fn is None:
        console.print(
            f"[bold red]Unknown AI_PROVIDER='{provider}'. "
            f"Choose 'anthropic' or 'openrouter'.[/bold red]"
        )
        for finding in findings_list:
            finding["ai_advice"] = "Skipped - invalid AI_PROVIDER"
        return findings_list

    # Show what we're using
    model_name = os.getenv("OPENROUTER_MODEL", DEFAULT_MODEL) if provider == "openrouter" else "claude-3-haiku"
    console.print(
        Panel(
            f"Provider: [bold]{provider}[/bold]\n  model: {model_name}",
            title="AI Advisor",
            border_style="yellow",
        )
    )

    total = len(findings_list)
    for i, finding in enumerate(findings_list):
        resource = finding.get("resource_name", "Unknown")
        issue    = finding.get("issue", "Unknown")
        console.print(f"  [{i + 1}/{total}] [cyan]{resource}[/cyan] - {issue}")

        # Sanitise before sending to external API
        safe = _sanitise_finding(finding)
        prompt = f"Finding:\n{json.dumps(safe, indent=2)}"

        try:
            advice = call_fn(prompt)
            # Split by newline so JSON saves it as a readable list instead of one long string with \n
            finding["ai_advice"] = [line.strip() for line in advice.split("\n") if line.strip()]
            console.print("       [green][Advice Generated][/green]")
        except Exception as e:
            error_msg = str(e)
            if len(error_msg) > 200:
                error_msg = error_msg[:200] + "..."
            # Escape brackets so Rich doesn't parse them as markup
            safe_msg = error_msg.replace("[", "\\[").replace("]", "\\]")
            console.print(f"       [bold red][FAIL] {safe_msg}[/bold red]")
            finding["ai_advice"] = f"Failed ({type(e).__name__})"

    console.print("[bold yellow]AI Advisor complete.[/bold yellow]\n")
    return findings_list


# -- Quick test ---------------------------------------------------------
if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()

    test_findings = [
        {
            "service": "S3",
            "resource_name": "my-test-bucket",
            "issue": "Public Read Access Enabled",
            "severity": "Critical",
            "details": "Bucket policy allows s3:GetObject for principal *",
        }
    ]
    results = get_ai_advice(test_findings)
    for r in results:
        console.print(Panel(r.get("ai_advice", "N/A"), title="AI Advice"))
