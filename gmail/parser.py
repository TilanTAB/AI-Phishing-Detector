"""
Email parser.

Extracts structured data from a Gmail API message resource:
sender, reply-to, subject, date, body text, URLs, attachments,
and authentication headers (SPF, DKIM, DMARC).
"""

import base64
import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from io import StringIO
from typing import Any

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Regex for extracting URLs from plain text
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'\)\]]+',
    re.IGNORECASE,
)

# Regex for extracting email from "Display Name <email@domain.com>" format
EMAIL_PATTERN = re.compile(r"<([^>]+)>")


@dataclass
class ParsedEmail:
    """Structured representation of an email for phishing analysis."""

    message_id: str = ""
    sender_email: str = ""
    sender_display_name: str = ""
    reply_to: str = ""
    to: str = ""
    date: str = ""
    subject: str = ""
    body_text: str = ""
    urls: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    spf_result: str = "unknown"
    dkim_result: str = "unknown"
    dmarc_result: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for AI prompt formatting."""
        return {
            "message_id": self.message_id,
            "sender_email": self.sender_email,
            "sender_display_name": self.sender_display_name,
            "reply_to": self.reply_to,
            "recipient": self.to,
            "date": self.date,
            "subject": self.subject,
            "body_text": self.body_text[:5000],  # Truncate very long bodies
            "urls_list": "\n".join(self.urls) if self.urls else "(none)",
            "attachments_list": "\n".join(self.attachments) if self.attachments else "(none)",
            "spf_result": self.spf_result,
            "dkim_result": self.dkim_result,
            "dmarc_result": self.dmarc_result,
        }


def parse_message(message: dict[str, Any]) -> ParsedEmail:
    """
    Parse a Gmail API message resource into a structured ParsedEmail.

    Args:
        message: The full Gmail API message response (format='full').

    Returns:
        ParsedEmail with extracted fields.
    """
    parsed = ParsedEmail(message_id=message.get("id", ""))

    payload = message.get("payload", {})
    headers = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}

    # --- Sender ---
    from_header = headers.get("from", "")
    parsed.sender_display_name, parsed.sender_email = _parse_email_address(from_header)

    # --- Reply-To ---
    parsed.reply_to = headers.get("reply-to", parsed.sender_email)

    # --- Recipient ---
    parsed.to = headers.get("to", "")

    # --- Date ---
    parsed.date = headers.get("date", "")

    # --- Subject ---
    parsed.subject = headers.get("subject", "(no subject)")

    # --- Authentication headers ---
    auth_results = headers.get("authentication-results", "")
    parsed.spf_result = _extract_auth_result(auth_results, "spf")
    parsed.dkim_result = _extract_auth_result(auth_results, "dkim")
    parsed.dmarc_result = _extract_auth_result(auth_results, "dmarc")

    # --- Body and URLs ---
    body_parts = _extract_body_parts(payload)
    parsed.body_text = body_parts["text"]
    parsed.urls = body_parts["urls"]

    # --- Attachments ---
    parsed.attachments = _extract_attachment_names(payload)

    return parsed


def _parse_email_address(raw: str) -> tuple[str, str]:
    """
    Parse 'Display Name <email@domain.com>' into (display_name, email).

    Returns:
        Tuple of (display_name, email). If no angle brackets, returns ("", raw).
    """
    match = EMAIL_PATTERN.search(raw)
    if match:
        email = match.group(1).strip()
        display_name = raw[: match.start()].strip().strip('"')
        return display_name, email
    return "", raw.strip()


def _extract_auth_result(auth_header: str, mechanism: str) -> str:
    """Extract SPF/DKIM/DMARC result from the Authentication-Results header."""
    pattern = re.compile(rf"{mechanism}=(\w+)", re.IGNORECASE)
    match = pattern.search(auth_header)
    return match.group(1) if match else "unknown"


def _extract_body_parts(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively extract body text and URLs from the message payload.

    Prefers plain text; falls back to HTML (converted to text).
    URLs are extracted from both plain text and HTML href attributes.
    """
    plain_text = ""
    html_text = ""
    urls: list[str] = []

    def _walk_parts(part: dict[str, Any]) -> None:
        nonlocal plain_text, html_text

        mime_type = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data", "")

        if data:
            decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")

            if mime_type == "text/plain" and not plain_text:
                plain_text = decoded
                urls.extend(URL_PATTERN.findall(decoded))

            elif mime_type == "text/html" and not html_text:
                html_text = decoded
                urls.extend(_extract_urls_from_html(decoded))

        for sub_part in part.get("parts", []):
            _walk_parts(sub_part)

    _walk_parts(payload)

    # Prefer plain text; fall back to HTML-to-text
    if plain_text:
        body = plain_text
    elif html_text:
        body = _html_to_text(html_text)
        # Also extract plain text URLs from the converted text
        urls.extend(URL_PATTERN.findall(body))
    else:
        body = ""

    # Deduplicate URLs while preserving order
    seen: set[str] = set()
    unique_urls: list[str] = []
    for url in urls:
        # Strip trailing punctuation that may have been captured
        url = url.rstrip(".,;:!?)")
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    return {"text": body, "urls": unique_urls}


def _extract_urls_from_html(html: str) -> list[str]:
    """Extract URLs from href attributes in HTML content."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        urls = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith(("http://", "https://")):
                urls.append(href)
        return urls
    except Exception:
        logger.warning("Failed to parse HTML for URL extraction", exc_info=True)
        return []


def _html_to_text(html: str) -> str:
    """Convert HTML to plain text, preserving basic structure."""
    try:
        soup = BeautifulSoup(html, "html.parser")

        # Remove script and style elements
        for element in soup(["script", "style"]):
            element.decompose()

        text = soup.get_text(separator="\n")

        # Collapse multiple blank lines
        lines = [line.strip() for line in text.splitlines()]
        return "\n".join(line for line in lines if line)
    except Exception:
        logger.warning("Failed to convert HTML to text", exc_info=True)
        return html


def _extract_attachment_names(payload: dict[str, Any]) -> list[str]:
    """Recursively extract attachment filenames from the message payload."""
    attachments: list[str] = []

    def _walk(part: dict[str, Any]) -> None:
        filename = part.get("filename", "")
        if filename:
            attachments.append(filename)
        for sub_part in part.get("parts", []):
            _walk(sub_part)

    _walk(payload)
    return attachments
