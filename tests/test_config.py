"""Tests for configuration loading and validation."""

import pytest
from pydantic import ValidationError


def test_valid_azure_config(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "azure_openai")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com/")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")

    from config import load_settings
    settings = load_settings()
    assert settings.ai_provider.value == "azure_openai"
    assert settings.azure_openai_endpoint == "https://test.openai.azure.com/"


def test_valid_bedrock_config(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "bedrock_claude")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")

    from config import load_settings
    settings = load_settings()
    assert settings.ai_provider.value == "bedrock_claude"


def test_missing_azure_key_raises(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "azure_openai")
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    # Deliberately omit AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY

    from config import load_settings
    with pytest.raises((ValidationError, ValueError)):
        load_settings()


def test_missing_bedrock_key_raises(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "bedrock_claude")
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    # Deliberately omit AWS credentials

    from config import load_settings
    with pytest.raises((ValidationError, ValueError)):
        load_settings()


def test_invalid_threshold_order_raises(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "azure_openai")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com/")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    monkeypatch.setenv("SUSPICIOUS_THRESHOLD", "70")
    monkeypatch.setenv("PHISHING_THRESHOLD", "40")  # lower than suspicious — invalid

    from config import load_settings
    with pytest.raises((ValidationError, ValueError)):
        load_settings()


def test_default_thresholds(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "azure_openai")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com/")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")

    from config import load_settings
    settings = load_settings()
    assert settings.suspicious_threshold == 31
    assert settings.phishing_threshold == 66
