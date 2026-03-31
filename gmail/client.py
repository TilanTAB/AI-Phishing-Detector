"""
Gmail API client wrapper.

Provides a clean interface over the Gmail API for operations needed
by the phishing checker: reading messages, listing history, modifying
labels, sending emails, and managing Pub/Sub watches.
"""

import base64
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any

from googleapiclient.discovery import Resource
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception,
)
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


def _is_retryable_http_error(exc: BaseException) -> bool:
    """Return True for HTTP 429 (rate limit) and 5xx (server) errors."""
    if isinstance(exc, HttpError):
        return exc.resp.status in (429, 500, 502, 503, 504)
    return False


class GmailClient:
    """Wrapper around the Gmail API service resource."""

    def __init__(self, service: Resource):
        self._service = service
        self._user_id = "me"

    @retry(
        retry=retry_if_exception(_is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=16),
        reraise=True,
    )
    def get_profile(self) -> dict[str, Any]:
        """Get the user's Gmail profile (email address, historyId, etc.)."""
        return (
            self._service.users()
            .getProfile(userId=self._user_id)
            .execute()
        )

    @retry(
        retry=retry_if_exception(_is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=16),
        reraise=True,
    )
    def get_message(self, message_id: str, fmt: str = "full") -> dict[str, Any]:
        """
        Fetch a single email message.

        Args:
            message_id: The Gmail message ID.
            fmt: Response format — 'full', 'metadata', 'minimal', or 'raw'.

        Returns:
            Gmail API message resource.
        """
        return (
            self._service.users()
            .messages()
            .get(userId=self._user_id, id=message_id, format=fmt)
            .execute()
        )

    @retry(
        retry=retry_if_exception(_is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=16),
        reraise=True,
    )
    def list_history(
        self,
        start_history_id: str,
        history_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        List history records since the given historyId.

        Args:
            start_history_id: The historyId to start listing from.
            history_types: Filter by history type (e.g., ['messageAdded']).

        Returns:
            List of history records. Empty list if no new history.
        """
        kwargs: dict[str, Any] = {
            "userId": self._user_id,
            "startHistoryId": start_history_id,
        }
        if history_types:
            kwargs["historyTypes"] = history_types

        results: list[dict[str, Any]] = []
        request = self._service.users().history().list(**kwargs)

        while request is not None:
            response = request.execute()
            history = response.get("history", [])
            results.extend(history)
            request = self._service.users().history().list_next(request, response)

        return results

    @retry(
        retry=retry_if_exception(_is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=16),
        reraise=True,
    )
    def modify_labels(
        self,
        message_id: str,
        add_label_ids: list[str] | None = None,
        remove_label_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add or remove labels from a message."""
        body: dict[str, Any] = {}
        if add_label_ids:
            body["addLabelIds"] = add_label_ids
        if remove_label_ids:
            body["removeLabelIds"] = remove_label_ids

        return (
            self._service.users()
            .messages()
            .modify(userId=self._user_id, id=message_id, body=body)
            .execute()
        )

    @retry(
        retry=retry_if_exception(_is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=16),
        reraise=True,
    )
    def send_message(self, to: str, subject: str, body_html: str, body_text: str) -> dict[str, Any]:
        """
        Send an email message from the authenticated user's account.

        Args:
            to: Recipient email address.
            subject: Email subject line.
            body_html: HTML body content.
            body_text: Plain text body content.

        Returns:
            Gmail API send response.
        """
        message = MIMEMultipart("alternative")
        message["to"] = to
        message["subject"] = subject

        message.attach(MIMEText(body_text, "plain"))
        message.attach(MIMEText(body_html, "html"))

        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
        return (
            self._service.users()
            .messages()
            .send(userId=self._user_id, body={"raw": raw})
            .execute()
        )

    @retry(
        retry=retry_if_exception(_is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=16),
        reraise=True,
    )
    def watch(self, topic_name: str) -> dict[str, Any]:
        """
        Set up a Pub/Sub watch on the user's mailbox.

        The watch expires after 7 days and must be renewed.

        Args:
            topic_name: Full Pub/Sub topic name (projects/{project}/topics/{topic}).

        Returns:
            Watch response containing historyId and expiration.
        """
        body = {
            "topicName": topic_name,
            "labelIds": ["INBOX"],
        }
        response = (
            self._service.users()
            .watch(userId=self._user_id, body=body)
            .execute()
        )
        logger.info(
            "Gmail watch established. Expires at: %s",
            response.get("expiration"),
        )
        return response

    def stop_watch(self) -> None:
        """Stop the current Pub/Sub watch on the mailbox."""
        self._service.users().stop(userId=self._user_id).execute()
        logger.info("Gmail watch stopped.")
