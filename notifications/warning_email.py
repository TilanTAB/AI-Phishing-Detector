"""
Warning email composer and sender.

When a phishing or suspicious email is detected, sends a warning summary
email to the user's own Gmail account via the Gmail API.
"""

import logging
from typing import Callable

from config import Settings
from gmail.client import GmailClient
from gmail.parser import ParsedEmail
from ai.models import PhishingAnalysis, Verdict, Severity

logger = logging.getLogger(__name__)

# Severity badge colors for HTML email
SEVERITY_COLORS = {
    Severity.HIGH: "#cc3a21",
    Severity.MEDIUM: "#ff9900",
    Severity.LOW: "#2da44e",
}

VERDICT_COLORS = {
    Verdict.PHISHING: "#cc3a21",
    Verdict.SUSPICIOUS: "#ff9900",
    Verdict.SAFE: "#2da44e",
}


def build_warning_email_fn(
    gmail_client: GmailClient,
    settings: Settings,
) -> Callable[[ParsedEmail, PhishingAnalysis], None]:
    """
    Factory that returns a callable for sending warning emails.

    Args:
        gmail_client: Authenticated Gmail API client.
        settings: Application settings (used to get the user's email address).

    Returns:
        Callable that accepts (ParsedEmail, PhishingAnalysis) and sends the warning.
    """
    # Get the user's own email address once at startup
    try:
        profile = gmail_client.get_profile()
        user_email = profile.get("emailAddress", "me")
    except Exception as e:
        logger.warning("Could not fetch user email for warning notifications: %s", e)
        user_email = "me"

    def send_warning(parsed: ParsedEmail, analysis: PhishingAnalysis) -> None:
        """Compose and send a phishing warning email to the user."""
        subject = _build_subject(parsed, analysis)
        body_text = _build_plain_text(parsed, analysis)
        body_html = _build_html(parsed, analysis)

        try:
            gmail_client.send_message(
                to=user_email,
                subject=subject,
                body_html=body_html,
                body_text=body_text,
            )
            logger.info(
                "Warning email sent for message %s (verdict=%s)",
                parsed.message_id,
                analysis.verdict.value,
            )
        except Exception as e:
            logger.error(
                "Failed to send warning email for message %s: %s",
                parsed.message_id,
                e,
            )

    return send_warning


def _build_subject(parsed: ParsedEmail, analysis: PhishingAnalysis) -> str:
    verdict_label = "PHISHING ALERT" if analysis.verdict == Verdict.PHISHING else "SUSPICIOUS EMAIL"
    return f"[{verdict_label}] {parsed.subject[:60]}"


def _build_plain_text(parsed: ParsedEmail, analysis: PhishingAnalysis) -> str:
    lines = [
        f"{'=' * 60}",
        f"PHISHING DETECTION ALERT",
        f"{'=' * 60}",
        f"",
        f"VERDICT:    {analysis.verdict.value.upper()}",
        f"SCORE:      {analysis.score}/100",
        f"CONFIDENCE: {analysis.confidence * 100:.0f}%",
        f"",
        f"ORIGINAL EMAIL",
        f"--------------",
        f"From:    {parsed.sender_display_name} <{parsed.sender_email}>",
        f"Subject: {parsed.subject}",
        f"Date:    {parsed.date}",
        f"",
        f"ASSESSMENT",
        f"----------",
        parsed.reasoning if hasattr(parsed, 'reasoning') else analysis.reasoning,
        f"",
    ]

    if analysis.red_flags:
        lines.append("RED FLAGS DETECTED")
        lines.append("-" * 18)
        for flag in analysis.red_flags:
            lines.append(f"  [{flag.severity.value.upper()}] {flag.category.value.upper()}: {flag.detail}")
        lines.append("")

    lines += [
        "RECOMMENDATIONS",
        "---------------",
        "  - Do NOT click any links in this email.",
        "  - Do NOT open any attachments.",
        "  - Do NOT reply or provide any personal information.",
        "  - If in doubt, contact the claimed sender through official channels.",
        "",
        "This alert was generated automatically by Gmail Phishing Checker.",
    ]

    return "\n".join(lines)


def _build_html(parsed: ParsedEmail, analysis: PhishingAnalysis) -> str:
    verdict_color = VERDICT_COLORS.get(analysis.verdict, "#666")
    verdict_label = analysis.verdict.value.upper()

    red_flags_html = ""
    if analysis.red_flags:
        rows = ""
        for flag in analysis.red_flags:
            color = SEVERITY_COLORS.get(flag.severity, "#666")
            rows += f"""
            <tr>
                <td style="padding:6px 8px; border-bottom:1px solid #eee;">
                    <span style="background:{color};color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:bold;">
                        {flag.severity.value.upper()}
                    </span>
                </td>
                <td style="padding:6px 8px; border-bottom:1px solid #eee; font-weight:bold; text-transform:uppercase; font-size:12px; color:#555;">
                    {flag.category.value}
                </td>
                <td style="padding:6px 8px; border-bottom:1px solid #eee; font-size:13px;">
                    {_html_escape(flag.detail)}
                </td>
            </tr>"""

        red_flags_html = f"""
        <h3 style="color:#333; margin-top:24px;">Red Flags Detected</h3>
        <table style="width:100%; border-collapse:collapse; font-family:sans-serif;">
            <thead>
                <tr style="background:#f5f5f5;">
                    <th style="padding:8px; text-align:left; font-size:12px; color:#666;">SEVERITY</th>
                    <th style="padding:8px; text-align:left; font-size:12px; color:#666;">CATEGORY</th>
                    <th style="padding:8px; text-align:left; font-size:12px; color:#666;">DETAIL</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    return f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial, sans-serif; max-width:700px; margin:0 auto; padding:20px; color:#333;">

    <div style="background:{verdict_color}; color:#fff; padding:16px 20px; border-radius:6px; margin-bottom:20px;">
        <h2 style="margin:0; font-size:20px;">&#9888; Phishing Detection Alert</h2>
        <p style="margin:6px 0 0 0; font-size:14px; opacity:0.9;">
            Gmail Phishing Checker has flagged an email as <strong>{verdict_label}</strong>.
        </p>
    </div>

    <div style="display:flex; gap:12px; margin-bottom:20px; flex-wrap:wrap;">
        <div style="flex:1; background:#f9f9f9; border:1px solid #ddd; border-radius:6px; padding:14px; min-width:120px; text-align:center;">
            <div style="font-size:11px; color:#888; text-transform:uppercase; letter-spacing:1px;">Verdict</div>
            <div style="font-size:22px; font-weight:bold; color:{verdict_color}; margin-top:4px;">{verdict_label}</div>
        </div>
        <div style="flex:1; background:#f9f9f9; border:1px solid #ddd; border-radius:6px; padding:14px; min-width:120px; text-align:center;">
            <div style="font-size:11px; color:#888; text-transform:uppercase; letter-spacing:1px;">Phishing Score</div>
            <div style="font-size:22px; font-weight:bold; color:{verdict_color}; margin-top:4px;">{analysis.score}<span style="font-size:13px; color:#999;">/100</span></div>
        </div>
        <div style="flex:1; background:#f9f9f9; border:1px solid #ddd; border-radius:6px; padding:14px; min-width:120px; text-align:center;">
            <div style="font-size:11px; color:#888; text-transform:uppercase; letter-spacing:1px;">Confidence</div>
            <div style="font-size:22px; font-weight:bold; color:#333; margin-top:4px;">{analysis.confidence * 100:.0f}<span style="font-size:13px; color:#999;">%</span></div>
        </div>
    </div>

    <h3 style="color:#333; margin-top:0;">Original Email Details</h3>
    <table style="width:100%; font-size:13px; border-collapse:collapse;">
        <tr><td style="padding:5px 10px 5px 0; color:#888; width:70px;">From</td><td style="padding:5px 0;"><strong>{_html_escape(parsed.sender_display_name)}</strong> &lt;{_html_escape(parsed.sender_email)}&gt;</td></tr>
        <tr><td style="padding:5px 10px 5px 0; color:#888;">Subject</td><td style="padding:5px 0;">{_html_escape(parsed.subject)}</td></tr>
        <tr><td style="padding:5px 10px 5px 0; color:#888;">Date</td><td style="padding:5px 0;">{_html_escape(parsed.date)}</td></tr>
        <tr><td style="padding:5px 10px 5px 0; color:#888;">SPF</td><td style="padding:5px 0;">{_html_escape(parsed.spf_result)}</td></tr>
        <tr><td style="padding:5px 10px 5px 0; color:#888;">DKIM</td><td style="padding:5px 0;">{_html_escape(parsed.dkim_result)}</td></tr>
        <tr><td style="padding:5px 10px 5px 0; color:#888;">DMARC</td><td style="padding:5px 0;">{_html_escape(parsed.dmarc_result)}</td></tr>
    </table>

    <h3 style="color:#333; margin-top:20px;">Assessment</h3>
    <p style="font-size:13px; line-height:1.6; background:#f9f9f9; padding:12px; border-left:3px solid {verdict_color}; border-radius:0 4px 4px 0;">
        {_html_escape(analysis.reasoning)}
    </p>

    {red_flags_html}

    <div style="background:#fff8e1; border:1px solid #ffe082; border-radius:6px; padding:16px; margin-top:24px;">
        <h3 style="margin-top:0; color:#e65100; font-size:15px;">&#9888; Recommendations</h3>
        <ul style="margin:0; padding-left:20px; font-size:13px; line-height:1.8;">
            <li>Do <strong>NOT</strong> click any links in this email.</li>
            <li>Do <strong>NOT</strong> open any attachments.</li>
            <li>Do <strong>NOT</strong> reply or provide any personal information.</li>
            <li>If in doubt, contact the claimed sender through official channels.</li>
        </ul>
    </div>

    <p style="font-size:11px; color:#aaa; margin-top:24px; border-top:1px solid #eee; padding-top:12px;">
        This alert was generated automatically by Gmail Phishing Checker.
    </p>
</body>
</html>"""


def _html_escape(text: str) -> str:
    """Escape HTML special characters to prevent XSS in email body."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
