"""Tests for AI prompt generation and PhishingAnalysis model validation."""

import pytest
from pydantic import ValidationError

from ai.prompt import build_user_prompt, SYSTEM_PROMPT
from ai.models import PhishingAnalysis, Verdict, RedFlag, RedFlagCategory, Severity


SAMPLE_EMAIL_DATA = {
    "sender_email": "security@paypa1-secure.com",
    "sender_display_name": "PayPal Security",
    "reply_to": "support@free-mail-123.tk",
    "recipient": "user@gmail.com",
    "date": "Sat, 29 Mar 2026 09:00:00 +0000",
    "subject": "URGENT: Your account has been suspended",
    "body_text": "Verify your account immediately or it will be deleted.",
    "urls_list": "http://paypal-secure-verify.xyz/verify?id=123456",
    "attachments_list": "(none)",
    "spf_result": "fail",
    "dkim_result": "fail",
    "dmarc_result": "fail",
}


def test_user_prompt_contains_sender():
    prompt = build_user_prompt(SAMPLE_EMAIL_DATA)
    assert "paypa1-secure.com" in prompt


def test_user_prompt_contains_subject():
    prompt = build_user_prompt(SAMPLE_EMAIL_DATA)
    assert "URGENT" in prompt


def test_user_prompt_contains_auth_headers():
    prompt = build_user_prompt(SAMPLE_EMAIL_DATA)
    assert "SPF: fail" in prompt
    assert "DKIM: fail" in prompt
    assert "DMARC: fail" in prompt


def test_user_prompt_contains_urls():
    prompt = build_user_prompt(SAMPLE_EMAIL_DATA)
    assert "paypal-secure-verify.xyz" in prompt


def test_system_prompt_covers_all_dimensions():
    for dimension in ["SENDER", "URL", "URGENCY", "GRAMMAR", "IMPERSONATION", "ATTACHMENT"]:
        assert dimension in SYSTEM_PROMPT


def test_system_prompt_specifies_json_schema():
    assert '"score"' in SYSTEM_PROMPT
    assert '"verdict"' in SYSTEM_PROMPT
    assert '"red_flags"' in SYSTEM_PROMPT


def test_phishing_analysis_valid():
    data = {
        "score": 85,
        "verdict": "phishing",
        "reasoning": "Clear phishing attempt with spoofed sender.",
        "red_flags": [
            {"category": "sender", "detail": "Lookalike domain", "severity": "high"}
        ],
        "confidence": 0.95,
    }
    analysis = PhishingAnalysis.model_validate(data)
    assert analysis.verdict == Verdict.PHISHING
    assert analysis.score == 85
    assert len(analysis.red_flags) == 1


def test_phishing_analysis_score_out_of_range():
    with pytest.raises(ValidationError):
        PhishingAnalysis.model_validate({
            "score": 150,  # Invalid: > 100
            "verdict": "phishing",
            "reasoning": "test",
            "red_flags": [],
            "confidence": 0.9,
        })


def test_phishing_analysis_invalid_verdict():
    with pytest.raises(ValidationError):
        PhishingAnalysis.model_validate({
            "score": 50,
            "verdict": "maybe",  # Invalid verdict
            "reasoning": "test",
            "red_flags": [],
            "confidence": 0.5,
        })


def test_phishing_analysis_empty_red_flags():
    data = {
        "score": 10,
        "verdict": "safe",
        "reasoning": "Legitimate email.",
        "red_flags": [],
        "confidence": 0.99,
    }
    analysis = PhishingAnalysis.model_validate(data)
    assert analysis.red_flags == []
