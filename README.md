# 🛡️ CloudGuard AI — AWS Security Auditor

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-35%20passed-brightgreen)
![AWS Boto3](https://img.shields.io/badge/AWS-boto3-orange)

An open-source, AI-native **Cloud Security Posture Management (CSPM)** CLI tool. It scans your AWS environment for security misconfigurations, explains every finding in plain English, and lets you interactively ask follow-up questions — all powered by your choice of AI model.

---

## What's New in v2.0

| Feature | Description |
|---------|-------------|
| **Hybrid AI Engine** | LiteLLM (100+ providers) + Native SDKs + Custom Enterprise endpoints |
| **Multi-Region Scan** | Automatically discovers and scans every active AWS region |
| **CloudGuard Chat** | Interactive REPL — ask follow-up questions about your findings |
| **Auto-Fix** | AI generates ready-to-run `aws` CLI remediation commands with audit log |
| **Batch Auto-Fix Script** | Export a `.sh` script with automated remediation commands for bulk fixing |
| **HTML Cyber-Slate Report** | Generate a premium interactive web dashboard for risk visualization |
| **Model Comparison** | Run two AI models side-by-side and compare advice |
| **CIS IAM Benchmarks** | Root MFA/usage, password policy, unused access keys (CIS 1.7–1.13) |
| **Network Sanitisation** | Redacts IPs, Account IDs, and ARNs before sending to any external API |
| **35 Unit Tests** | Full pytest coverage across scanners, adapters, chat, and autofix |

---

## Scanners

| Scanner | What it checks | Severity |
|---------|---------------|----------|
| **S3 Buckets** | Public access block, default encryption (SSE), versioning | Critical / High / Medium |
| **Security Groups** | Inbound rules open to `0.0.0.0/0` or `::/0` (all regions) | Critical / High |
| **IAM** | Root MFA/usage, user MFA, key age >90d, password policy, admin access | Critical / High / Medium |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure your environment
cp .env.example .env
# Edit .env — choose an AI provider and add your key

# 3. Run a full scan
python main.py

# 4. Interactive chat after scan
python main.py --chat

# 5. Compare two AI models side-by-side
python main.py --compare anthropic/claude-3-haiku openai/gpt-4o-mini

# 6. AI-powered auto-fix for Critical/High findings
python main.py --fix

# 7. Generate a visual HTML report dashboard
python main.py --html

# 8. Export AI remediation commands to a .sh bash script
python main.py --export-fix

# 9. Run tests
pytest tests/ -v
```

---

## AI Provider Configuration (`.env`)

```dotenv
# Select provider: litellm | auto | anthropic | openai | gemini | ollama | xai | deepseek | custom | openrouter
AI_PROVIDER=litellm

# --- LiteLLM (default, 100+ providers via single interface) ---
LITELLM_MODEL=anthropic/claude-3-haiku-20240307
ANTHROPIC_API_KEY=sk-ant-...

# --- Auto Mode (picks first key found) ---
AI_PROVIDER=auto

# --- Local / Offline (zero data leakage) ---
AI_PROVIDER=ollama
OLLAMA_MODEL=llama3

# --- Enterprise Private Endpoint ---
AI_PROVIDER=custom
CUSTOM_API_URL=https://internal-ai.company.com/v1
CUSTOM_API_KEY=your-internal-key
CUSTOM_REQUEST_FORMAT=openai  # or "anthropic"
```

---

## AWS Credentials (optional)

```bash
aws configure
```

If no AWS credentials are found, CloudGuard AI automatically runs in **mock mode** with sample findings — no AWS account required.

---

## Security Design

- API keys loaded from `.env` — never hardcoded
- `.gitignore` prevents committing `.env`, scan reports, and audit logs
- All findings are **sanitised before any AI call**: Account IDs, ARNs, and IP addresses are redacted
- Auto-Fix commands are **validated** (must start with `aws`) and logged to `cloudguard_audit.log`

```
+---------------------------------------------------------------+
|    ____ _                 _  ____                      _      |
|   / ___| | ___  _   _  __| |/ ___|_   _  __ _ _ __ __| |     |
|  | |   | |/ _ \| | | |/ _` | |  _| | | |/ _` | '__/ _` |    |
|  | |___| | (_) | |_| | (_| | |_| | |_| | (_| | | | (_| |    |
|   \____|_|\___/ \__,_|\__,_|\____|\__,_|\__,_|_|  \__,_|    |
|                           AWS Security Auditor                |
+---------------------------------------------------------------+
Starting CloudGuard AI scan...

Scanning Mock AWS Environment...
Found 5 potential misconfigurations in mock data.

+------------- AI Advisor --------------+
| Provider: openrouter                  |
| model: llama-3.3-70b-instruct:free    |
+---------------------------------------+
  [1/5] s3-bucket-customer-data - Public Read Access Enabled
       [Advice Generated]
  [2/5] s3-logs-archive - No default encryption
       [Advice Generated]
  ...

  Findings Summary
+------------------+
| Severity | Count |
|----------+-------|
| Critical |     2 |
| High     |     2 |
| Medium   |     1 |
| Low      |     0 |
+------------------+

Overall Risk Score: 32

Scan complete. Report saved to cloudguard_report_20260411_141320.json
```
## Screenshot 
<img width="1036" height="747" alt="image" src="https://github.com/user-attachments/assets/8b9c1afa-54ec-4c2e-a0ba-b989e684ef26" />
<img width="1027" height="703" alt="image" src="https://github.com/user-attachments/assets/b0d99836-249d-498f-96d5-43c44c1b0710" />

---

## Project Structure

```
CloudGuard_ai/
  main.py              Entry point — banner, CLI flags, orchestrates all phases
  scanner.py           AWS scanners (S3, Security Groups, IAM) + multi-region + mock mode
  ai_advisor.py        AI remediation advice — comparison mode + judge AI
  chat_mode.py         Conversational REPL using the adapter pattern
  autofix.py           AI-driven CLI command generation with safety guard + audit log
  report.py            JSON report + severity table + risk score
  requirements.txt     Pinned Python dependencies
  .env.example         Template for all environment variables
  adapters/
    __init__.py        Hybrid factory: auto-selects adapter from AI_PROVIDER
    base.py            Abstract base class (BaseAdapter)
    litellm_adapter.py Universal adapter — 100+ providers
    anthropic_adapter.py
    openai_adapter.py
    gemini_adapter.py
    ollama_adapter.py  Local / offline AI
    xai_adapter.py     xAI Grok
    deepseek_adapter.py
    custom_adapter.py  Private enterprise endpoint
  tests/
    test_adapters.py   Factory routing + network sanitisation
    test_chat_mode.py  Context building + system prompt
    test_autofix.py    Severity filter + shell safety guard
    test_scanner.py    Mock data, sanitisation, risk score, report output
  .github/
    workflows/ci.yml   GitHub Actions CI (runs all tests on push/PR)
  BUGS_AND_IMPROVEMENTS.md  Engineering audit log
```

---

## Testing

35 unit tests across 4 files:

```bash
pytest tests/ -v
```

Covers: adapter factory routing, sanitisation, chat context, autofix safety guard, mock findings, risk score, report output, JSON extraction from LLM output.

---

## Future Scope (v2.x roadmap)

| Feature | Description |
|---------|-------------|
| **Multi-Cloud** | Azure and GCP scanner support |
| **Scheduled Scans** | Cron-based automation with Slack/email alerts |
