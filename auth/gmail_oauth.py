"""
Gmail OAuth2 authentication.

Handles the initial consent flow (interactive, one-time) and automatic
token refresh for subsequent runs.
"""

import logging
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build, Resource

logger = logging.getLogger(__name__)

# Full mailbox access is required to read messages, modify labels, send emails,
# and set up Pub/Sub watches.
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]


def get_credentials(credentials_file: str, token_file: str) -> Credentials:
    """
    Load or create OAuth2 credentials.

    On first run, opens a browser for user consent and saves the token.
    On subsequent runs, loads the saved token and refreshes if expired.

    Args:
        credentials_file: Path to the OAuth client credentials JSON from GCP Console.
        token_file: Path where the refresh token is persisted.

    Returns:
        Valid Google OAuth2 Credentials.

    Raises:
        FileNotFoundError: If credentials_file does not exist.
        google.auth.exceptions.RefreshError: If token refresh fails (re-auth needed).
    """
    if not os.path.exists(credentials_file):
        raise FileNotFoundError(
            f"OAuth credentials file not found: {credentials_file}. "
            f"Download it from the GCP Console (APIs & Services > Credentials)."
        )

    creds = None

    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
        logger.info("Loaded existing OAuth token from %s", token_file)

    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        logger.info("Token expired, refreshing...")
        creds.refresh(Request())
        _save_token(creds, token_file)
        logger.info("Token refreshed successfully.")
        return creds

    # No valid token — run the interactive consent flow
    logger.info("No valid token found. Starting OAuth consent flow...")
    flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
    creds = flow.run_local_server(port=0)
    _save_token(creds, token_file)
    logger.info("OAuth consent completed. Token saved to %s", token_file)
    return creds


def build_gmail_service(credentials_file: str, token_file: str) -> Resource:
    """
    Build and return an authenticated Gmail API service.

    Args:
        credentials_file: Path to the OAuth client credentials JSON.
        token_file: Path to the persisted token.

    Returns:
        Gmail API service resource.
    """
    creds = get_credentials(credentials_file, token_file)
    service = build("gmail", "v1", credentials=creds)
    logger.info("Gmail API service built successfully.")
    return service


def _save_token(creds: Credentials, token_file: str) -> None:
    """Persist credentials to disk."""
    with open(token_file, "w") as f:
        f.write(creds.to_json())
