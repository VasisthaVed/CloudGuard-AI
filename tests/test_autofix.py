import pytest
from autofix import apply_fix, run_autofix_session
import os

def test_apply_fix_blocks_non_aws_commands(capsys):
    command = "rm -rf /"
    result = apply_fix(command)
    assert result is False
    captured = capsys.readouterr()
    assert "Security Violation" in captured.out

def test_apply_fix_allows_aws_commands(monkeypatch):
    # Mock subprocess.run to avoid actual execution
    def mock_run(*args, **kwargs):
        class MockResult:
            stdout = "Mock success"
        return MockResult()
    monkeypatch.setattr("subprocess.run", mock_run)
    
    # We also need to avoid writing to the audit log in tests or clean it up
    # Let's just allow it to write to a test log
    monkeypatch.chdir(os.path.dirname(__file__))
    
    command = "aws s3 ls"
    result = apply_fix(command)
    assert result is True
    
    if os.path.exists("cloudguard_audit.log"):
        os.remove("cloudguard_audit.log")

def test_run_autofix_session_skips_low_severity(monkeypatch, capsys):
    findings = [
        {"severity": "Low", "resource_name": "test1"},
        {"severity": "Medium", "resource_name": "test2"}
    ]
    
    # It shouldn't prompt or generate anything
    run_autofix_session(findings, None)
    
    captured = capsys.readouterr()
    # It prints the warning banner, but shouldn't print the Target
    assert "Target: test1" not in captured.out
    assert "Target: test2" not in captured.out
