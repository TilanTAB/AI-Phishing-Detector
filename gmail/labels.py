"""
Gmail label management for phishing detection results.

Creates and manages PHISHING (red) and SUSPICIOUS (orange) labels.
"""

import logging
from typing import Any

from gmail.client import GmailClient

logger = logging.getLogger(__name__)

# Label definitions with colors
LABEL_DEFINITIONS = {
    "PHISHING_DETECTED": {
        "name": "PHISHING_DETECTED",
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
        "color": {
            "backgroundColor": "#cc3a21",  # Red
            "textColor": "#ffffff",        # White
        },
    },
    "SUSPICIOUS": {
        "name": "SUSPICIOUS",
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
        "color": {
            "backgroundColor": "#ff9900",  # Orange
            "textColor": "#000000",        # Black
        },
    },
}


class LabelManager:
    """Manages phishing-related Gmail labels."""

    def __init__(self, gmail_client: GmailClient):
        self._client = gmail_client
        self._label_ids: dict[str, str] = {}

    def ensure_labels_exist(self) -> None:
        """
        Create PHISHING_DETECTED and SUSPICIOUS labels if they don't exist.

        Caches label IDs for later use. Safe to call multiple times.
        """
        existing_labels = self._get_existing_labels()

        for label_name, label_body in LABEL_DEFINITIONS.items():
            if label_name in existing_labels:
                self._label_ids[label_name] = existing_labels[label_name]
                logger.info("Label '%s' already exists (id=%s)", label_name, self._label_ids[label_name])
            else:
                label_id = self._create_label(label_body)
                self._label_ids[label_name] = label_id
                logger.info("Created label '%s' (id=%s)", label_name, label_id)

    def apply_phishing_label(self, message_id: str) -> None:
        """Apply the PHISHING_DETECTED label to a message."""
        label_id = self._label_ids.get("PHISHING_DETECTED")
        if not label_id:
            logger.error("PHISHING_DETECTED label ID not initialized. Call ensure_labels_exist() first.")
            return
        self._client.modify_labels(message_id, add_label_ids=[label_id])
        logger.info("Applied PHISHING_DETECTED label to message %s", message_id)

    def apply_suspicious_label(self, message_id: str) -> None:
        """Apply the SUSPICIOUS label to a message."""
        label_id = self._label_ids.get("SUSPICIOUS")
        if not label_id:
            logger.error("SUSPICIOUS label ID not initialized. Call ensure_labels_exist() first.")
            return
        self._client.modify_labels(message_id, add_label_ids=[label_id])
        logger.info("Applied SUSPICIOUS label to message %s", message_id)

    def get_label_id(self, label_name: str) -> str | None:
        """Get the cached label ID for a given label name."""
        return self._label_ids.get(label_name)

    def _get_existing_labels(self) -> dict[str, str]:
        """Fetch all labels and return a name->id mapping."""
        response = (
            self._client._service.users()
            .labels()
            .list(userId="me")
            .execute()
        )
        labels = response.get("labels", [])
        return {label["name"]: label["id"] for label in labels}

    def _create_label(self, label_body: dict[str, Any]) -> str:
        """Create a new Gmail label and return its ID."""
        result = (
            self._client._service.users()
            .labels()
            .create(userId="me", body=label_body)
            .execute()
        )
        return result["id"]
