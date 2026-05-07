# CloudGuard AI v2.0 — Engineering Audit Log

**Last Updated:** 2026-05-07
**Status:** ✅ All critical issues resolved. v2.0 is production-ready.

---

## ✅ Resolved Bugs & Spec Violations

| ID | File | Issue | Status |
| :--- | :--- | :--- | :--- |
| **BUG-01** | `ai_advisor.py` | Comparison mode crashed with `NameError: _call_openrouter` | ✅ Fixed — uses `LiteLLMAdapter` |
| **BUG-02** | `chat_mode.py` | `Rule` imported at bottom of file, causing `NameError` | ✅ Fixed — moved to top |
| **BUG-03** | `chat_mode.py` | Hardcoded `litellm.completion()` bypassed Adapter Pattern | ✅ Fixed — uses `provider.chat()` |
| **BUG-04** | `scanner.py` | Mock findings missing `region` key | ✅ Fixed — all mock dicts have `region` |
| **SPEC-01** | `autofix.py` | Processed Medium/Low findings (blueprint: Critical/High only) | ✅ Fixed — severity filter added |
| **SPEC-03** | `ai_advisor.py` | Stale docstring listing only `openrouter`/`anthropic` | ✅ Fixed — updated to v2.0 architecture |
| **SPEC-04** | `main.py`, `report.py` | Version string `1.1.0` → `2.0.0` | ✅ Fixed |
| **SPEC-05** | `adapters/__init__.py` | Missing `auto` detection mode | ✅ Fixed — checks keys in priority order |
| **SPEC-06** | `adapters/__init__.py` | `openrouter` alias removed, breaking v1 users | ✅ Fixed — alias routes to LiteLLMAdapter |
| **QUAL-01** | `chat_mode.py` | Generic `Exception` → `break` killed chat on API timeout | ✅ Fixed — uses `continue` |
| **QUAL-02** | `autofix.py` | `shell=True` with no command guard | ✅ Fixed — must start with `aws `, logged to audit file |
| **QUAL-04** | `scanner.py` | Bare `except:` in IAM last-used check | ✅ Fixed — `except Exception:` |
| **QUAL-05** | `scanner.py` | `import csv` / `import io` inside function body | ✅ Fixed — moved to module top |
| **QUAL-06** | `ai_advisor.py` | Unbounded `ThreadPoolExecutor(max_workers=len(models))` | ✅ Fixed — capped at 5 |
| **IMP-01** | `tests/` | No unit tests for new v2.0 code | ✅ Fixed — 35 tests, all passing |
| **IMP-03** | `report.py` | Version hardcoded as `1.1.0` | ✅ Fixed — `2.0.0` |
| **IMP-05** | `chat_mode.py` | Comparison mode ran models sequentially | ✅ Fixed — parallel via `ThreadPoolExecutor` |
| **IMP-02** | `autofix.py` | Add `--export-fix` flag for script export (`remediate.sh`) alongside interactive `--fix` | ✅ Fixed |
| **NEW-01** | `html_report.py` | Web dashboard for findings visualisation | ✅ Fixed — Cyber-Slate HTML report generated |
| **NEW-02** | `autofix.py` | `remediate.sh` export with `set -e` and per-block prompts | ✅ Fixed — exported via `--export-fix` |

---

## ✅ Pre-existing Bugs Fixed in v2.0

| Bug | Status |
| :--- | :--- |
| **AI Judge JSON Parsing** | ✅ `_extract_json()` with fence stripping + brace-depth counting |
| **AWS Pagination** | ✅ Paginator used in `describe_security_groups` |
| **Limited IAM Detection** | ✅ Group policies + inline policies now checked |
| **Multi-Region Scanning** | ✅ `scan_all_regions()` orchestrator |
| **IP Redaction** | ✅ `_sanitise_network()` with IPv4/IPv6 regex |
| **Pinned Dependencies** | ✅ `litellm==1.83.14` in `requirements.txt` |

---

## 🟢 Open Improvements (v2.x Roadmap)

| ID | Description | Priority |
| :--- | :--- | :--- |
| **IMP-04** | Update `.env.example` with newer variable comments | Low |
| **IMP-06** | Rotate `cloudguard_audit.log` (currently appends forever) | Low |
| **QUAL-03** | IPv6 regex too narrow — misses compressed forms like `::1`, `fe80::1` | Low |
| **NEW** | Slack/email alert integration for scheduled scans | Future |
