"""
Flask webhook server for Google Cloud Pub/Sub push notifications.

Receives push notifications when new emails arrive in the monitored
Gmail inbox. Always returns 200 OK to prevent Pub/Sub from retrying
permanently-failed messages endlessly.
"""

import base64
import json
import logging
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request, jsonify

logger = logging.getLogger(__name__)

# Background thread pool for async processing
# (Pub/Sub expects a response within ~10s; AI calls can take longer)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="phishing-worker")


def create_app(handler_fn, verification_token: str | None = None) -> Flask:
    """
    Create the Flask application with the Pub/Sub webhook endpoint.

    Args:
        handler_fn: Callable that accepts a historyId string. This is the
                    main pipeline function from pubsub/handler.py.
        verification_token: Optional shared secret to validate push requests.
                            If set, the request must include ?token=<value>.

    Returns:
        Configured Flask application.
    """
    app = Flask(__name__)

    @app.route("/pubsub", methods=["POST"])
    def pubsub_push():
        """
        Handle Pub/Sub push notifications.

        Decodes the base64-encoded message data, extracts the historyId,
        and dispatches processing to a background thread immediately so
        we can return 200 within Pub/Sub's ack deadline.
        """
        # --- Optional token verification ---
        if verification_token:
            token = request.args.get("token", "")
            if token != verification_token:
                logger.warning("Pub/Sub push rejected: invalid verification token.")
                # Return 200 to prevent infinite retry on a permanent auth failure
                return jsonify({"status": "unauthorized"}), 200

        # --- Parse the Pub/Sub envelope ---
        envelope = request.get_json(silent=True)
        if not envelope or "message" not in envelope:
            logger.error("Malformed Pub/Sub push: missing 'message' field. Body: %s", request.data[:200])
            return jsonify({"status": "malformed"}), 200

        message = envelope["message"]
        encoded_data = message.get("data", "")

        if not encoded_data:
            logger.warning("Pub/Sub message has no data payload.")
            return jsonify({"status": "no_data"}), 200

        # --- Decode the notification payload ---
        try:
            decoded = base64.b64decode(encoded_data).decode("utf-8")
            notification = json.loads(decoded)
        except Exception as e:
            logger.error("Failed to decode Pub/Sub message data: %s", e)
            return jsonify({"status": "decode_error"}), 200

        history_id = notification.get("historyId")
        email_address = notification.get("emailAddress", "unknown")

        if not history_id:
            logger.warning("Pub/Sub notification missing historyId: %s", notification)
            return jsonify({"status": "no_history_id"}), 200

        logger.info(
            "Pub/Sub push received | email=%s | historyId=%s | messageId=%s",
            email_address,
            history_id,
            message.get("messageId", "unknown"),
        )

        # --- Dispatch to background thread and return immediately ---
        _executor.submit(_safe_handle, handler_fn, str(history_id))

        return jsonify({"status": "accepted"}), 200

    @app.route("/health", methods=["GET"])
    def health():
        """Simple health check endpoint."""
        return jsonify({"status": "ok"}), 200

    return app


def _safe_handle(handler_fn, history_id: str) -> None:
    """Wrap handler_fn to catch and log all exceptions in the background thread."""
    try:
        handler_fn(history_id)
    except Exception as e:
        logger.error("Unhandled exception in phishing pipeline for historyId=%s: %s", history_id, e, exc_info=True)
