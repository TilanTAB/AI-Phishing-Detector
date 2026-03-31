"""Shared pytest fixtures for Gmail Phishing Checker tests."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def legitimate_email_raw():
    with open(FIXTURES_DIR / "legitimate_email.json") as f:
        return json.load(f)


@pytest.fixture
def phishing_email_raw():
    with open(FIXTURES_DIR / "phishing_email.json") as f:
        return json.load(f)


@pytest.fixture
def suspicious_email_raw():
    with open(FIXTURES_DIR / "suspicious_email.json") as f:
        return json.load(f)


@pytest.fixture
def mock_gmail_service():
    return MagicMock()


@pytest.fixture
def mock_gmail_client(mock_gmail_service):
    from gmail.client import GmailClient
    return GmailClient(mock_gmail_service)


@pytest.fixture
def phishing_analysis():
    from ai.models import PhishingAnalysis, Verdict, RedFlag, RedFlagCategory, Severity
    return PhishingAnalysis(
        score=85,
        verdict=Verdict.PHISHING,
        reasoning="The email uses a lookalike domain and fails all authentication checks.",
        red_flags=[
            RedFlag(category=RedFlagCategory.SENDER, detail="Lookalike domain paypa1-secure.com", severity=Severity.HIGH),
            RedFlag(category=RedFlagCategory.URGENCY, detail="Account suspension threat with 24-hour deadline", severity=Severity.HIGH),
        ],
        confidence=0.95,
    )


@pytest.fixture
def safe_analysis():
    from ai.models import PhishingAnalysis, Verdict
    return PhishingAnalysis(
        score=5,
        verdict=Verdict.SAFE,
        reasoning="Email is from a known legitimate sender with valid authentication.",
        red_flags=[],
        confidence=0.98,
    )


@pytest.fixture
def minimal_settings(monkeypatch, tmp_path):
    """Minimal valid settings for testing (Azure OpenAI provider)."""
    monkeypatch.setenv("AI_PROVIDER", "azure_openai")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com/")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key-123")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
    monkeypatch.setenv("PUBSUB_VERIFICATION_TOKEN", "test-token")

    from config import load_settings
    return load_settings()
