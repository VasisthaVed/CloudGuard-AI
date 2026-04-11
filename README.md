# 🛡️ CloudGuard AI - AWS Security Auditor

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GitHub Actions build status](https://img.shields.io/badge/build-passing-brightgreen)
![AWS Boto3](https://img.shields.io/badge/AWS-boto3-orange)

An open-source Python CLI tool that scans your AWS environment for critical security misconfigurations and leverages Large Language Models (LLMs) to natively generate plain-English explanations and step-by-step remediation commands.

## Features

| Scanner | What it checks | Severity |
|---------|---------------|----------|
| **S3 Buckets** | Public access block, default encryption (SSE), versioning | Critical / High / Medium |
| **Security Groups** | Inbound rules open to `0.0.0.0/0` or `::/0` (flags SSH/RDP) | Critical / High |
| **IAM** | Root MFA, user MFA, access key age (>90 days), AdministratorAccess | Critical / High |

**AI Providers supported:**
- **OpenRouter** (default) - supports many **free** models, no credit card needed
- **Anthropic Claude** - requires paid API key

**Other features:**
- Risk Score calculation (Critical x10 + High x5 + Medium x2)
- Color-coded terminal output via `rich`
- Timestamped JSON report export
- Mock mode for testing without AWS credentials
- Data sanitisation before sending findings to AI (strips account IDs and ARNs)

## Requirements

- Python 3.8+
- (Optional) AWS CLI configured
- An API key for OpenRouter (free) or Anthropic

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy env template and add your API key
cp .env.example .env
# Edit .env with your OPENROUTER_API_KEY

# 3. Run
python main.py

# 4. Run tests
python -m pytest tests/ -v
```

## Configuration

### `.env` file

```dotenv
# Choose: "anthropic" or "openrouter"
AI_PROVIDER=openrouter

# Get a free key at https://openrouter.ai (no credit card)
OPENROUTER_API_KEY=your-key-here

# Free model options (pick one):
#   meta-llama/llama-3.3-70b-instruct:free
#   google/gemma-3-27b-it:free
#   deepseek/deepseek-r1:free
#   qwen/qwen3-next-80b:free
#   mistralai/mistral-small-3.1-24b-instruct:free
#   nvidia/llama-3.1-nemotron-70b-instruct:free
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free
```

### AWS credentials (optional)

```bash
aws configure
```

If no AWS credentials are found, CloudGuard AI automatically falls back to **mock mode** with sample findings.

## Security

- API keys loaded from `.env` (never hardcoded)
- `.gitignore` prevents committing `.env` and scan reports
- Findings are **sanitised** before being sent to AI APIs (AWS account IDs and ARNs are redacted)
- Reports saved locally only

## Example Output

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

## Project Structure

```
CloudGuard_ai/
  main.py              Entry point - banner, orchestrates all phases
  scanner.py           AWS scanning (S3, Security Groups, IAM) + mock mode
  ai_advisor.py        AI remediation (OpenRouter / Anthropic)
  report.py            JSON report + summary table + risk score
  requirements.txt     Python dependencies
  .env.example         Template for API keys
  .gitignore           Keeps secrets and reports out of git
  tests/
    test_scanner.py    14 unit tests (pytest)
  .github/
    workflows/ci.yml   GitHub Actions CI pipeline
  README.md            This file
  GUIDE.md             Personal walkthrough for understanding the code
```

## Testing

14 unit tests covering:
- Mock findings format validation (correct keys, valid severities)
- AWS connection mock fallback
- Data sanitisation (account ID + ARN redaction)
- Risk score calculation formula
- JSON report output integrity

```bash
python -m pytest tests/ -v
```

Tests also run automatically on every push/PR via GitHub Actions CI.

## Future Scope

| Feature | Description |
|---------|-------------|
| **AI Comparison** | Run findings through multiple AI models, compare advice side-by-side, build confidence scores |
| **Chat Mode** | Conversational follow-ups: "Why is this critical?", "Show me the fix command" |
| **Web Dashboard** | Flask/Streamlit UI with filterable tables, risk gauge, historical trends, PDF export |
| **Auto-Fix** | AI generates ready-to-run AWS CLI commands, one-click apply with confirmation |
| **Scheduled Scans** | Cron/Task Scheduler, diff against previous scan, Slack/email alerts on new Critical findings |
| **Multi-Cloud** | Azure + GCP scanner support |
| **Compliance** | Map findings to CIS Benchmarks, SOC 2, PCI-DSS |

See [GUIDE.md](GUIDE.md) for detailed explanations of each feature idea.
