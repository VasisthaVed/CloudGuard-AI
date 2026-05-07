import pytest
from chat_mode import format_findings_for_context, build_system_context

def test_format_findings_for_context():
    findings = [
        {
            "severity": "Critical",
            "service": "S3",
            "resource_name": "my-bucket",
            "issue": "Public Access",
            "region": "us-east-1",
            "details": "Bucket is public",
        }
    ]
    result = format_findings_for_context(findings)
    assert "1. [Critical] S3: my-bucket" in result
    assert "Issue: Public Access" in result
    assert "Region: us-east-1" in result
    assert "Details: Bucket is public" in result

def test_format_findings_empty():
    assert "No misconfigurations" in format_findings_for_context([])

def test_build_system_context():
    findings = [
        {"severity": "Critical"},
        {"severity": "High"},
        {"severity": "High"},
        {"severity": "Low"},
    ]
    result = build_system_context(findings)
    assert "Critical: 1" in result
    assert "High: 2" in result
    assert "Medium: 0" in result
    assert "Low: 1" in result
    assert "You are CloudGuard AI" in result
