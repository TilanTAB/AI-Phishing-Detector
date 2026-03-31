"""Tests for email parsing from Gmail API message resources."""

import base64
import pytest
from gmail.parser import parse_message, _parse_email_address, _extract_auth_result


def _encode(text: str) -> str:
    """Helper: base64url-encode a string as Gmail API would."""
    return base64.urlsafe_b64encode(text.encode()).decode()


def test_parse_legitimate_email(legitimate_email_raw):
    parsed = parse_message(legitimate_email_raw)
    assert parsed.message_id == "msg001"
    assert parsed.sender_email == "noreply@github.com"
    assert parsed.sender_display_name == "GitHub"
    assert "pull request" in parsed.subject.lower()
    assert parsed.spf_result == "pass"
    assert parsed.dkim_result == "pass"
    assert parsed.dmarc_result == "pass"


def test_parse_phishing_email(phishing_email_raw):
    parsed = parse_message(phishing_email_raw)
    assert parsed.message_id == "msg002"
    assert "paypa1" in parsed.sender_email
    assert parsed.spf_result == "fail"
    assert parsed.dkim_result == "fail"
    assert parsed.dmarc_result == "fail"
    # Should extract the suspicious URL from the body
    assert any("paypal" in url.lower() for url in parsed.urls)


def test_parse_email_address_with_display_name():
    display, email = _parse_email_address("John Doe <john@example.com>")
    assert display == "John Doe"
    assert email == "john@example.com"


def test_parse_email_address_bare():
    display, email = _parse_email_address("john@example.com")
    assert display == ""
    assert email == "john@example.com"


def test_parse_email_address_quoted_name():
    display, email = _parse_email_address('"PayPal Security" <security@paypal.com>')
    assert display == "PayPal Security"
    assert email == "security@paypal.com"


def test_extract_auth_result_pass():
    header = "mx.google.com; spf=pass smtp.mailfrom=github.com; dkim=pass; dmarc=pass"
    assert _extract_auth_result(header, "spf") == "pass"
    assert _extract_auth_result(header, "dkim") == "pass"
    assert _extract_auth_result(header, "dmarc") == "pass"


def test_extract_auth_result_missing():
    result = _extract_auth_result("", "spf")
    assert result == "unknown"


def test_empty_body_produces_empty_text():
    msg = {
        "id": "empty001",
        "payload": {
            "headers": [
                {"name": "From", "value": "test@example.com"},
                {"name": "Subject", "value": "Empty"},
            ],
            "mimeType": "text/plain",
            "body": {"data": ""},
            "parts": [],
        },
    }
    parsed = parse_message(msg)
    assert parsed.body_text == ""
    assert parsed.urls == []


def test_url_deduplication():
    url = "https://example.com/login"
    body = f"Visit {url} and also {url} again."
    msg = {
        "id": "dup001",
        "payload": {
            "headers": [{"name": "From", "value": "x@example.com"}],
            "mimeType": "text/plain",
            "body": {"data": _encode(body)},
            "parts": [],
        },
    }
    parsed = parse_message(msg)
    assert parsed.urls.count(url) == 1


def test_attachment_names_extracted():
    msg = {
        "id": "att001",
        "payload": {
            "headers": [{"name": "From", "value": "x@example.com"}],
            "mimeType": "multipart/mixed",
            "body": {},
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": _encode("See attached.")},
                    "parts": [],
                },
                {
                    "mimeType": "application/octet-stream",
                    "filename": "invoice.exe",
                    "body": {"attachmentId": "att_123"},
                    "parts": [],
                },
            ],
        },
    }
    parsed = parse_message(msg)
    assert "invoice.exe" in parsed.attachments
