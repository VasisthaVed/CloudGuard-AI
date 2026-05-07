import os
import pytest
from adapters import get_provider
from adapters.litellm_adapter import LiteLLMAdapter
from adapters.custom_adapter import CustomAdapter
from adapters.anthropic_adapter import AnthropicAdapter
from adapters.openai_adapter import OpenAIAdapter
from adapters.gemini_adapter import GeminiAdapter
from adapters.xai_adapter import xAIAdapter
from adapters.deepseek_adapter import DeepSeekAdapter
from adapters.ollama_adapter import OllamaAdapter
from ai_advisor import _sanitise_network, _sanitise_finding

def test_get_provider_custom(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "custom")
    provider = get_provider()
    assert isinstance(provider, CustomAdapter)

def test_get_provider_native(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    provider = get_provider()
    assert isinstance(provider, AnthropicAdapter)

def test_get_provider_default(monkeypatch):
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    provider = get_provider()
    assert isinstance(provider, LiteLLMAdapter)

def test_get_provider_auto(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "auto")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    provider = get_provider()
    assert isinstance(provider, OpenAIAdapter)

def test_sanitise_network():
    text = "Server IP is 192.168.1.50 and public is 8.8.8.8/32"
    clean = _sanitise_network(text)
    assert "192.168.1.50" not in clean
    assert "8.8.8.8/32" not in clean
    assert "<IPv4_REDACTED>" in clean

def test_sanitise_finding():
    finding = {
        "service": "EC2",
        "resource_name": "arn:aws:ec2:us-east-1:123456789012:instance/i-123456",
        "details": "IP 10.0.0.1 is exposed",
    }
    clean = _sanitise_finding(finding)
    assert "123456789012" not in clean["resource_name"]
    assert "10.0.0.1" not in clean["details"]
    assert "arn:aws:***REDACTED***" in clean["resource_name"]
    
    # Test just an account ID
    finding2 = {"resource_name": "Account 123456789012"}
    clean2 = _sanitise_finding(finding2)
    assert "XXXXXXXXXXXX" in clean2["resource_name"]
