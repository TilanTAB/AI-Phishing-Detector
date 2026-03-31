"""
Gmail Phishing Checker — Entry Point.

Initializes all components and starts the Flask webhook server
to receive Pub/Sub push notifications from Gmail.
"""

import logging
import sys
import threading
import time

from config import load_settings, configure_logging

logger = logging.getLogger(__name__)


def main() -> None:
    # --- Load and validate configuration ---
    try:
        settings = load_settings()
    except Exception as e:
        print(f"[FATAL] Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    configure_logging(settings)
    logger.info("Starting Gmail Phishing Checker...")
    logger.info("AI provider: %s", settings.ai_provider.value)

    # --- Build Gmail service (triggers OAuth consent on first run) ---
    from auth.gmail_oauth import build_gmail_service

    try:
        gmail_service = build_gmail_service(
            settings.google_credentials_file,
            settings.google_token_file,
        )
    except FileNotFoundError as e:
        logger.fatal("%s", e)
        sys.exit(1)

    # --- Initialize Gmail client and labels ---
    from gmail.client import GmailClient
    from gmail.labels import LabelManager

    gmail_client = GmailClient(gmail_service)
    label_manager = LabelManager(gmail_client)

    try:
        label_manager.ensure_labels_exist()
    except Exception as e:
        logger.error("Failed to initialize Gmail labels: %s", e)
        # Non-fatal — continue without labels; handler will log label errors

    # --- Initialize AI provider ---
    from ai import get_provider

    ai_provider = get_provider(settings)
    logger.info("AI provider initialized: %s", type(ai_provider).__name__)

    # --- Initialize notifications ---
    warning_email_fn = None
    if settings.send_warning_email:
        from notifications.warning_email import build_warning_email_fn
        warning_email_fn = build_warning_email_fn(gmail_client, settings)

    # --- Initialize phishing handler ---
    from pubsub.handler import PhishingHandler

    handler = PhishingHandler(
        settings=settings,
        gmail_client=gmail_client,
        label_manager=label_manager,
        ai_provider=ai_provider,
        warning_email_fn=warning_email_fn,
    )

    # Bootstrap historyId if this is first run
    handler.initialize_history_id()

    # --- Register Gmail Pub/Sub watch ---
    topic_name = f"projects/{settings.gcp_project_id}/topics/{settings.pubsub_topic}"
    try:
        watch_response = gmail_client.watch(topic_name)
        expiration_ms = int(watch_response.get("expiration", 0))
        logger.info(
            "Gmail watch registered. Expires at epoch ms: %d", expiration_ms
        )
        # Schedule watch renewal before it expires (renew every 6 days)
        _schedule_watch_renewal(gmail_client, topic_name, interval_seconds=6 * 24 * 3600)
    except Exception as e:
        logger.fatal("Failed to register Gmail watch: %s", e)
        sys.exit(1)

    # --- Create and start Flask webhook server ---
    from pubsub.webhook import create_app

    app = create_app(
        handler_fn=handler.handle_notification,
        verification_token=settings.pubsub_verification_token,
    )

    logger.info(
        "Webhook server starting on %s:%d ...",
        settings.webhook_host,
        settings.webhook_port,
    )

    # Use waitress (cross-platform WSGI server — works on Windows)
    from waitress import serve

    serve(app, host=settings.webhook_host, port=settings.webhook_port)


def _schedule_watch_renewal(gmail_client, topic_name: str, interval_seconds: int) -> None:
    """
    Renew the Gmail Pub/Sub watch every `interval_seconds` in a daemon thread.

    The watch expires after 7 days. Renewing every 6 days ensures continuity.
    """
    def _renewal_loop():
        while True:
            time.sleep(interval_seconds)
            try:
                gmail_client.watch(topic_name)
                logger.info("Gmail watch renewed successfully.")
            except Exception as e:
                logger.error("Gmail watch renewal failed: %s", e)

    thread = threading.Thread(target=_renewal_loop, daemon=True, name="watch-renewal")
    thread.start()
    logger.info("Watch renewal scheduled every %d hours.", interval_seconds // 3600)


if __name__ == "__main__":
    main()
