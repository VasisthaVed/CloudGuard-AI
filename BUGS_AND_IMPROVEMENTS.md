# CloudGuard AI - Bugs & Improvements Log

This document tracks identified bugs, edge cases, and proposed architectural improvements for Version 3 and beyond. This is intended for review by an advanced model (like Claude 3.5 Opus) for future development.

## 🐛 Identified Bugs & Edge Cases

### 1. AI Judge JSON Parsing
- **Issue**: `ai_advisor.py` uses `json.loads(raw_judge_output)` assuming the LLM returns pure JSON.
- **Risk**: Some models might include conversational text before/after the JSON or wrap it in ```json blocks, causing a crash.
- **Fix**: Use a regex or a cleaning function to extract the JSON content from the raw string.

### 2. AWS Pagination (Scalability)
- **Issue**: `scanner.py` calls `describe_security_groups()` once without a paginator.
- **Risk**: In extremely large AWS accounts (1000+ security groups), the scanner will only see the first page of results.
- **Fix**: Switch to using the Boto3 `get_paginator('describe_security_groups')` method.

### 3. Limited IAM Detection
- **Issue**: `scan_iam` only checks for `AdministratorAccess` attached **directly** to a user.
- **Risk**: It misses users who have admin rights via **IAM Groups** or **Inline Policies**.
- **Fix**: Enhance the scanner to check `list_groups_for_user`, `list_user_policies` (inline), and group-attached policies.

### 4. OpenRouter JSON Mode
- **Issue**: Version 2 forces `response_format={"type": "json_object"}`.
- **Risk**: Older or smaller free models on OpenRouter may not support this parameter and return a `400 Bad Request`.
- **Fix**: Add a check or a fallback that tries the call without the JSON format parameter if it fails once.

## 🚀 Proposed Improvements (v3 Roadmap)

### 1. Robust Sanitisation
- **Current**: Redacts standard 12-digit Account IDs and ARNs using regex.
- **Improvement**: Add redaction for IPv4/IPv6 addresses (except 0.0.0.0/0) to further protect network topology data before sending to LLMs.

### 2. Detailed JSON Metadata
- **Current**: JSON report contains the findings but lacks the summary metrics.
- **Improvement**: Add an `audit_metadata` section to the JSON including `overall_risk_score`, `severity_counts`, and `duration_seconds`.

### 3. "Self-Correction" Logic
- **Improvement**: If the Judge AI detects that all models provided low-quality or conflicting advice, it should be able to trigger a more powerful (paid) model like GPT-4o or Claude 3.5 Sonnet as a final tie-breaker.

### 4. Pinned Dependencies
- **Improvement**: Update `requirements.txt` to use exact versions (e.g., `boto3==1.34.0`) to ensure the tool doesn't break when library updates are released.

### 5. Multi-Region Scanning
- **Current**: Scans the default region configured in the environment.
- **Improvement**: Add a loop in `main.py` that queries `ec2.describe_regions()` and runs the scanner across every active AWS region.
