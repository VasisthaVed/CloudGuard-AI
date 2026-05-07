"""
tests/test_scanner.py -- Unit tests for CloudGuard AI.

Run with:  python -m pytest tests/ -v
"""

import json
import os
import sys

# Add project root to path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scanner
import ai_advisor
import report


# -----------------------------------------------------------------------
# Test 1: Mock findings have the correct dict format
# -----------------------------------------------------------------------
class TestMockFindings:
    """Every mock finding must have the 5 required keys."""

    REQUIRED_KEYS = {"service", "resource_name", "issue", "severity", "details"}
    VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}

    def test_mock_findings_have_required_keys(self):
        findings = scanner.scan_mock_aws()
        for finding in findings:
            missing = self.REQUIRED_KEYS - set(finding.keys())
            assert not missing, f"Finding missing keys: {missing} -> {finding}"

    def test_mock_findings_have_valid_severity(self):
        findings = scanner.scan_mock_aws()
        for finding in findings:
            assert finding["severity"] in self.VALID_SEVERITIES, (
                f"Invalid severity '{finding['severity']}' in {finding['resource_name']}"
            )

    def test_mock_findings_not_empty(self):
        findings = scanner.scan_mock_aws()
        assert len(findings) > 0, "Mock scanner returned 0 findings"


# -----------------------------------------------------------------------
# Test 2: connect_aws falls back to mock when no AWS creds
# -----------------------------------------------------------------------
class TestConnectAws:
    """Without real AWS credentials, connect_aws should return a mock dict."""

    def test_fallback_to_mock(self):
        session = scanner.connect_aws()
        # In CI/test environments there are no AWS creds, so we expect mock
        if isinstance(session, dict):
            assert session.get("mock") is True
            assert session.get("status") == "connected"
        # If real creds exist (local dev), session is a boto3.Session — that's fine too


# -----------------------------------------------------------------------
# Test 3: Data sanitisation strips sensitive info
# -----------------------------------------------------------------------
class TestSanitisation:
    """_sanitise_finding should redact AWS account IDs and ARNs."""

    def test_redacts_account_id(self):
        finding = {
            "service": "IAM",
            "resource_name": "User in account 123456789012",
            "issue": "MFA not enabled",
            "severity": "High",
            "details": "test",
        }
        safe = ai_advisor._sanitise_finding(finding)
        assert "123456789012" not in safe["resource_name"]
        assert "XXXXXXXXXXXX" in safe["resource_name"]

    def test_redacts_arn(self):
        finding = {
            "service": "IAM",
            "resource_name": "arn:aws:iam::123456789012:user/admin",
            "issue": "Admin access",
            "severity": "Critical",
            "details": "test",
        }
        safe = ai_advisor._sanitise_finding(finding)
        assert "arn:aws:***REDACTED***" in safe["resource_name"]

    def test_preserves_non_sensitive_data(self):
        finding = {
            "service": "S3",
            "resource_name": "my-bucket",
            "issue": "Public access",
            "severity": "Critical",
            "details": "some details",
        }
        safe = ai_advisor._sanitise_finding(finding)
        assert safe["service"] == "S3"
        assert safe["issue"] == "Public access"
        assert safe["severity"] == "Critical"
        assert safe["resource_name"] == "my-bucket"

    def test_returns_copy_not_original(self):
        finding = {"service": "S3", "resource_name": "x", "issue": "y",
                    "severity": "High", "details": "z"}
        safe = ai_advisor._sanitise_finding(finding)
        safe["service"] = "CHANGED"
        assert finding["service"] == "S3", "Sanitise should return a copy"


# -----------------------------------------------------------------------
# Test 4: Risk score calculation
# -----------------------------------------------------------------------
class TestRiskScore:
    """Verify the risk score formula: Critical*10 + High*5 + Medium*2."""

    def _calc_score(self, findings):
        """Mirror the formula from report.py."""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = f.get("severity", "Unknown")
            if sev in counts:
                counts[sev] += 1
        return (counts["Critical"] * 10) + (counts["High"] * 5) + (counts["Medium"] * 2)

    def test_all_critical(self):
        findings = [{"severity": "Critical"}] * 3
        assert self._calc_score(findings) == 30

    def test_mixed_severities(self):
        findings = [
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "High"},
            {"severity": "Medium"},
        ]
        assert self._calc_score(findings) == 10 + 5 + 5 + 2  # = 22

    def test_no_findings(self):
        assert self._calc_score([]) == 0

    def test_mock_findings_score(self):
        """Mock data has 2 Critical + 2 High + 1 Medium = 32."""
        findings = scanner.scan_mock_aws()
        score = self._calc_score(findings)
        assert score == 32, f"Expected 32, got {score}"


# -----------------------------------------------------------------------
# Test 5: Report JSON output
# -----------------------------------------------------------------------
class TestReportOutput:
    """generate_report should create a valid JSON file."""

    def test_json_file_created(self, tmp_path):
        test_file = str(tmp_path / "test_report.json")
        findings = [
            {"service": "S3", "resource_name": "bucket", "issue": "test",
             "severity": "High", "details": "d", "ai_advice": "fix it"},
        ]
        report.generate_report(findings, filename=test_file)

        assert os.path.exists(test_file), "Report file was not created"

        with open(test_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        assert data["tool"] == "CloudGuard AI"
        assert "timestamp" in data
        assert data["total_findings"] == 1
        assert len(data["findings"]) == 1

    def test_json_has_audit_metadata(self, tmp_path):
        """New: report should include audit_metadata section."""
        test_file = str(tmp_path / "test_meta_report.json")
        findings = [
            {"service": "S3", "resource_name": "b", "issue": "i",
             "severity": "Critical", "details": "d", "ai_advice": "fix"},
            {"service": "IAM", "resource_name": "u", "issue": "j",
             "severity": "High", "details": "d", "ai_advice": "fix"},
        ]
        report.generate_report(findings, filename=test_file)

        with open(test_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        assert "audit_metadata" in data
        meta = data["audit_metadata"]
        assert meta["overall_risk_score"] == 15  # 1 Critical(10) + 1 High(5)
        assert meta["risk_level"] in ("LOW", "ELEVATED", "CRITICAL")
        assert meta["severity_counts"]["Critical"] == 1
        assert meta["severity_counts"]["High"] == 1

    def test_empty_findings_no_crash(self, tmp_path):
        test_file = str(tmp_path / "empty_report.json")
        # Should not crash, should just print a message
        report.generate_report([], filename=test_file)
        assert not os.path.exists(test_file), "Should not create file for empty findings"


# -----------------------------------------------------------------------
# Test 6: JSON extraction (Bug #1 fix)
# -----------------------------------------------------------------------
class TestJsonExtraction:
    """_extract_json should handle various LLM output formats."""

    def test_pure_json(self):
        raw = '{"winning_model": "llama", "confidence_score": "High", "reasoning": "good", "best_advice": "do X"}'
        result = ai_advisor._extract_json(raw)
        assert result["winning_model"] == "llama"
        assert result["confidence_score"] == "High"

    def test_json_in_markdown_fence(self):
        raw = '''Here is my analysis:
```json
{"winning_model": "gemma", "confidence_score": "Medium", "reasoning": "ok", "best_advice": "do Y"}
```
Hope this helps!'''
        result = ai_advisor._extract_json(raw)
        assert result["winning_model"] == "gemma"
        assert result["confidence_score"] == "Medium"

    def test_json_in_plain_fence(self):
        raw = '''```
{"winning_model": "mistral", "confidence_score": "Low", "reasoning": "weak", "best_advice": "do Z"}
```'''
        result = ai_advisor._extract_json(raw)
        assert result["winning_model"] == "mistral"

    def test_json_buried_in_text(self):
        raw = 'I have reviewed the advice. {"winning_model": "llama", "confidence_score": "High", "reasoning": "best", "best_advice": "fix it"} That is my verdict.'
        result = ai_advisor._extract_json(raw)
        assert result["winning_model"] == "llama"

    def test_invalid_json_returns_fallback(self):
        raw = "This is not JSON at all, just some random text."
        result = ai_advisor._extract_json(raw)
        assert result["winning_model"].startswith("Unknown")
        assert "best_advice" in result

    def test_empty_string_returns_fallback(self):
        result = ai_advisor._extract_json("")
        assert result["winning_model"].startswith("Unknown")

    def test_none_returns_fallback(self):
        result = ai_advisor._extract_json(None)
        assert result["winning_model"].startswith("Unknown")

    def test_nested_json(self):
        raw = '{"winning_model": "llama", "confidence_score": "High", "reasoning": "good", "best_advice": "run: aws s3api put-bucket-encryption --bucket {\\"Bucket\\": \\"test\\"}"}'
        result = ai_advisor._extract_json(raw)
        assert result["winning_model"] == "llama"
