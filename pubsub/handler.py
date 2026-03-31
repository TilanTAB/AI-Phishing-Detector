"""
Phishing detection pipeline orchestrator.

Ties together Gmail history polling, email parsing, AI analysis,
label application, and warning email dispatch.
"""

import json
import logging
import os
import time
from typing import Callable

from googleapiclient.errors import HttpError

from ai.base import AIAnalysisError
from ai.models import PhishingAnalysis, Verdict
from config import Settings
from gmail.client import GmailClient
from gmail.labels import LabelManager
from gmail.parser import ParsedEmail, parse_message

logger = logging.getLogger(__name__)

# Path to persist the last processed historyId between restarts
HISTORY_STATE_FILE = "history_state.json"


class PhishingHandler:
    """
    Orchestrates the end-to-end phishing detection pipeline.

    For each new email:
      1. Fetch full message via Gmail API
      2. Parse into structured email data
      3. Run AI phishing analysis
      4. Apply Gmail label based on verdict
      5. Send warning email if configured and verdict is not safe
    """

    def __init__(
        self,
        settings: Settings,
        gmail_client: GmailClient,
        label_manager: LabelManager,
        ai_provider,
        warning_email_fn: Callable[[ParsedEmail, PhishingAnalysis], None] | None = None,
    ):
        self._settings = settings
        self._gmail = gmail_client
        self._labels = label_manager
        self._ai = ai_provider
        self._warning_email_fn = warning_email_fn
        self._last_history_id: str | None = self._load_history_id()

    def handle_notification(self, history_id: str) -> None:
        """
        Process a Pub/Sub push notification for a new historyId.

        Fetches all new messages since the last known historyId, analyzes
        each one, and takes appropriate action.

        Args:
            history_id: The historyId from the Pub/Sub notification payload.
        """
        start_time = time.monotonic()

        if not self._last_history_id:
            # First run — initialize from the notification's historyId
            # and skip backfill (we don't analyze old emails on startup)
            logger.info("Initializing historyId to %s (first run).", history_id)
            self._save_history_id(history_id)
            return

        try:
            history_records = self._gmail.list_history(
                start_history_id=self._last_history_id,
                history_types=["messageAdded"],
            )
        except HttpError as e:
            if e.resp.status == 404:
                # historyId is too old — Gmail only keeps 7 days of history
                logger.warning(
                    "historyId %s is stale (404). Resetting to current: %s",
                    self._last_history_id,
                    history_id,
                )
                self._save_history_id(history_id)
                return
            raise

        # Collect unique message IDs added since last check
        message_ids: list[str] = []
        seen: set[str] = set()
        for record in history_records:
            for added in record.get("messagesAdded", []):
                msg_id = added.get("message", {}).get("id")
                if msg_id and msg_id not in seen:
                    seen.add(msg_id)
                    message_ids.append(msg_id)

        logger.info(
            "historyId %s -> %s | %d new message(s) to analyze.",
            self._last_history_id,
            history_id,
            len(message_ids),
        )

        for msg_id in message_ids:
            self._process_message(msg_id)

        # Always advance the historyId, even if no messages were processed
        self._save_history_id(history_id)

        elapsed = time.monotonic() - start_time
        logger.info("Pipeline complete for historyId=%s in %.2fs.", history_id, elapsed)

    def _process_message(self, message_id: str) -> None:
        """Fetch, analyze, and act on a single email message."""
        logger.info("Processing message %s...", message_id)

        # 1. Fetch the full message
        try:
            raw_message = self._gmail.get_message(message_id)
        except HttpError as e:
            logger.error("Failed to fetch message %s: %s", message_id, e)
            return

        # 2. Parse into structured data
        try:
            parsed = parse_message(raw_message)
        except Exception as e:
            logger.error("Failed to parse message %s: %s", message_id, e, exc_info=True)
            return

        logger.info(
            "Analyzing | from=%s | subject=%s",
            parsed.sender_email,
            parsed.subject[:80],
        )

        # 3. Run AI analysis — fail safe: label as SUSPICIOUS on failure
        try:
            analysis = self._ai.analyze(parsed.to_dict())
        except AIAnalysisError as e:
            logger.error("AI analysis failed for message %s: %s. Labeling as SUSPICIOUS.", message_id, e)
            analysis = PhishingAnalysis(
                score=50,
                verdict=Verdict.SUSPICIOUS,
                reasoning="AI analysis failed — manual review recommended.",
                red_flags=[],
                confidence=0.0,
            )

        logger.info(
            "Analysis result | id=%s | verdict=%s | score=%d | confidence=%.2f",
            message_id,
            analysis.verdict.value,
            analysis.score,
            analysis.confidence,
        )

        # 4. Apply Gmail label based on verdict
        self._apply_label(message_id, analysis)

        # 5. Send warning email if enabled and verdict is not safe
        if (
            self._settings.send_warning_email
            and analysis.verdict != Verdict.SAFE
            and self._warning_email_fn is not None
        ):
            try:
                self._warning_email_fn(parsed, analysis)
            except Exception as e:
                logger.error("Failed to send warning email for message %s: %s", message_id, e)

    def _apply_label(self, message_id: str, analysis: PhishingAnalysis) -> None:
        """Apply the appropriate Gmail label based on the phishing verdict."""
        try:
            if analysis.verdict == Verdict.PHISHING:
                self._labels.apply_phishing_label(message_id)
            elif analysis.verdict == Verdict.SUSPICIOUS:
                self._labels.apply_suspicious_label(message_id)
            # SAFE: no label applied
        except Exception as e:
            logger.error("Failed to apply label to message %s: %s", message_id, e)

    def initialize_history_id(self) -> None:
        """
        Bootstrap the historyId from the current Gmail profile.

        Called on first startup when no history_state.json exists.
        Sets the starting point for monitoring — emails prior to this
        point will NOT be analyzed.
        """
        if not self._last_history_id:
            profile = self._gmail.get_profile()
            current_id = str(profile.get("historyId", ""))
            self._save_history_id(current_id)
            logger.info("Initialized historyId from profile: %s", current_id)

    def _load_history_id(self) -> str | None:
        """Load the last known historyId from disk."""
        if os.path.exists(HISTORY_STATE_FILE):
            try:
                with open(HISTORY_STATE_FILE, "r") as f:
                    data = json.load(f)
                    return data.get("historyId")
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Could not read history state file: %s", e)
        return None

    def _save_history_id(self, history_id: str) -> None:
        """Persist the latest historyId to disk."""
        self._last_history_id = history_id
        try:
            with open(HISTORY_STATE_FILE, "w") as f:
                json.dump({"historyId": history_id}, f)
        except OSError as e:
            logger.error("Failed to save history state: %s", e)
