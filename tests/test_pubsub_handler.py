"""Tests for the Pub/Sub webhook endpoint and phishing handler pipeline."""

import base64
import json
from unittest.mock import MagicMock, patch, call

import pytest

from ai.models import PhishingAnalysis, Verdict, RedFlag, RedFlagCategory, Severity
from gmail.parser import ParsedEmail
from pubsub.handler import PhishingHandler
from pubsub.webhook import create_app


# ---------------------------------------------------------------------------
# Webhook tests
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_handler_fn():
    return MagicMock()


@pytest.fixture
def client(mock_handler_fn):
    app = create_app(handler_fn=mock_handler_fn, verification_token="secret-token")
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _make_pubsub_payload(history_id: str, email: str = "user@gmail.com") -> dict:
    """Build a mock Pub/Sub push envelope."""
    notification = json.dumps({"historyId": history_id, "emailAddress": email})
    encoded = base64.b64encode(notification.encode()).decode()
    return {
        "message": {
            "data": encoded,
            "messageId": "123",
            "publishTime": "2026-03-29T10:00:00Z",
        },
        "subscription": "projects/test/subscriptions/gmail-sub",
    }


def test_valid_push_returns_200(client):
    payload = _make_pubsub_payload("99999")
    resp = client.post(
        "/pubsub?token=secret-token",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200


def test_invalid_token_returns_200_but_rejected(client):
    # Returns 200 (not 403) to avoid Pub/Sub retrying a permanent auth failure
    payload = _make_pubsub_payload("99999")
    resp = client.post(
        "/pubsub?token=WRONG",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["status"] == "unauthorized"


def test_malformed_body_returns_200(client):
    resp = client.post(
        "/pubsub?token=secret-token",
        data=b"not-json",
        content_type="application/json",
    )
    assert resp.status_code == 200


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert json.loads(resp.data)["status"] == "ok"


# ---------------------------------------------------------------------------
# Handler pipeline tests
# ---------------------------------------------------------------------------

@pytest.fixture
def handler(tmp_path, monkeypatch):
    """Create a PhishingHandler with all dependencies mocked."""
    monkeypatch.chdir(tmp_path)  # Avoid writing history_state.json to real dir

    settings = MagicMock()
    settings.send_warning_email = True
    settings.suspicious_threshold = 31
    settings.phishing_threshold = 66

    gmail_client = MagicMock()
    label_manager = MagicMock()
    ai_provider = MagicMock()
    warning_fn = MagicMock()

    return PhishingHandler(
        settings=settings,
        gmail_client=gmail_client,
        label_manager=label_manager,
        ai_provider=ai_provider,
        warning_email_fn=warning_fn,
    )


def test_first_run_saves_history_id_and_skips_analysis(handler, tmp_path, monkeypatch):
    """On first run (no saved state), handler should initialize historyId and skip analysis."""
    monkeypatch.chdir(tmp_path)
    handler._last_history_id = None  # Simulate no saved state

    handler.handle_notification("12345")

    # Should NOT call list_history on first run
    handler._gmail.list_history.assert_not_called()


def test_phishing_verdict_applies_phishing_label(handler, phishing_email_raw):
    """A phishing verdict should trigger the PHISHING_DETECTED label."""
    handler._last_history_id = "10000"
    handler._gmail.list_history.return_value = [
        {"messagesAdded": [{"message": {"id": "msg002"}}]}
    ]
    handler._gmail.get_message.return_value = phishing_email_raw

    phishing = PhishingAnalysis(
        score=85,
        verdict=Verdict.PHISHING,
        reasoning="Clear phishing attempt.",
        red_flags=[],
        confidence=0.95,
    )
    handler._ai.analyze.return_value = phishing

    handler.handle_notification("10001")

    handler._labels.apply_phishing_label.assert_called_once_with("msg002")
    handler._labels.apply_suspicious_label.assert_not_called()


def test_suspicious_verdict_applies_suspicious_label(handler, suspicious_email_raw):
    """A suspicious verdict should trigger the SUSPICIOUS label."""
    handler._last_history_id = "10000"
    handler._gmail.list_history.return_value = [
        {"messagesAdded": [{"message": {"id": "msg003"}}]}
    ]
    handler._gmail.get_message.return_value = suspicious_email_raw

    suspicious = PhishingAnalysis(
        score=50,
        verdict=Verdict.SUSPICIOUS,
        reasoning="Some red flags present.",
        red_flags=[],
        confidence=0.7,
    )
    handler._ai.analyze.return_value = suspicious

    handler.handle_notification("10001")

    handler._labels.apply_suspicious_label.assert_called_once_with("msg003")
    handler._labels.apply_phishing_label.assert_not_called()


def test_safe_verdict_applies_no_label(handler, legitimate_email_raw):
    """A safe verdict should not apply any label."""
    handler._last_history_id = "10000"
    handler._gmail.list_history.return_value = [
        {"messagesAdded": [{"message": {"id": "msg001"}}]}
    ]
    handler._gmail.get_message.return_value = legitimate_email_raw

    safe = PhishingAnalysis(
        score=5,
        verdict=Verdict.SAFE,
        reasoning="Legitimate email.",
        red_flags=[],
        confidence=0.99,
    )
    handler._ai.analyze.return_value = safe

    handler.handle_notification("10001")

    handler._labels.apply_phishing_label.assert_not_called()
    handler._labels.apply_suspicious_label.assert_not_called()


def test_ai_failure_labels_as_suspicious(handler, phishing_email_raw):
    """If AI analysis fails, the email should be labeled SUSPICIOUS as a fail-safe."""
    from ai.base import AIAnalysisError

    handler._last_history_id = "10000"
    handler._gmail.list_history.return_value = [
        {"messagesAdded": [{"message": {"id": "msg002"}}]}
    ]
    handler._gmail.get_message.return_value = phishing_email_raw
    handler._ai.analyze.side_effect = AIAnalysisError("Service unavailable")

    handler.handle_notification("10001")

    handler._labels.apply_suspicious_label.assert_called_once_with("msg002")


def test_safe_verdict_does_not_send_warning(handler, legitimate_email_raw):
    """Safe emails should not trigger warning emails."""
    handler._last_history_id = "10000"
    handler._gmail.list_history.return_value = [
        {"messagesAdded": [{"message": {"id": "msg001"}}]}
    ]
    handler._gmail.get_message.return_value = legitimate_email_raw

    safe = PhishingAnalysis(
        score=5, verdict=Verdict.SAFE, reasoning="OK", red_flags=[], confidence=0.99
    )
    handler._ai.analyze.return_value = safe

    handler.handle_notification("10001")

    handler._warning_email_fn.assert_not_called()


def test_phishing_verdict_sends_warning(handler, phishing_email_raw):
    """Phishing emails should trigger a warning email."""
    handler._last_history_id = "10000"
    handler._gmail.list_history.return_value = [
        {"messagesAdded": [{"message": {"id": "msg002"}}]}
    ]
    handler._gmail.get_message.return_value = phishing_email_raw

    phishing = PhishingAnalysis(
        score=85, verdict=Verdict.PHISHING, reasoning="Phishing", red_flags=[], confidence=0.95
    )
    handler._ai.analyze.return_value = phishing

    handler.handle_notification("10001")

    handler._warning_email_fn.assert_called_once()
