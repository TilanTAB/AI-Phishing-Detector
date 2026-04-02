# Privacy Policy — AI Phishing Detector

_Last updated: April 2, 2026_

## What This Add-on Does

AI Phishing Detector is a Gmail add-on that analyzes emails you explicitly open and trigger for analysis. It checks for phishing indicators such as suspicious URLs, sender spoofing, urgency tactics, and grammar anomalies.

## Data We Access

When you click **Analyze for Phishing**, the add-on reads the following from the currently open email:

- Sender name and email address
- Email subject
- Email body text (plain text only, up to 5,000 characters)
- URLs found in the email body
- SPF, DKIM, and DMARC authentication headers
- Attachment filenames (not attachment contents)

## Data We Do NOT Collect

- We do **not** store, log, or transmit your email content to any server we operate.
- We do **not** read emails you have not opened and triggered for analysis.
- We do **not** share your data with third parties beyond the AI provider you configure.

## Third-Party AI Providers

Email content is sent to the AI provider you configure in Script Properties. You control which provider is used:

| Provider | Privacy Policy |
|---|---|
| Google Gemini | https://policies.google.com/privacy |
| Google Vertex AI | https://cloud.google.com/terms/cloud-privacy-notice |
| Amazon Bedrock (Claude) | https://aws.amazon.com/privacy/ |
| Azure OpenAI | https://privacy.microsoft.com/privacystatement |

You are responsible for reviewing the privacy policy of your chosen AI provider. Email data sent for analysis is subject to that provider's terms.

## API Keys and Credentials

API keys are stored in Google Apps Script Script Properties, which are encrypted at rest by Google. Keys are never exposed in the add-on UI or logs.

## No Analytics or Tracking

This add-on does not use any analytics, tracking pixels, or telemetry of any kind.

## Contact

For questions or concerns, open an issue at:
https://github.com/TilanTAB/AI-Phishing-Detector/issues
