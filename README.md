# AI Phishing Detector

Real-time Gmail phishing detection powered by AI. Two complementary modes:

- **Gmail Add-on** — a sidebar card you trigger manually on any open email
- **Python Backend** — automated background monitor that watches your inbox via Google Cloud Pub/Sub and acts automatically

Supports **4 AI providers** switchable by config: Azure OpenAI, Amazon Bedrock Claude, Google Gemini API, and Google Vertex AI.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Gmail Add-on — Setup Guide](#gmail-add-on-setup-guide)
3. [Python Backend — Setup Guide](#python-backend-setup-guide)
4. [AI Provider Configuration](#ai-provider-configuration)
5. [Phishing Score Reference](#phishing-score-reference)
6. [Project Structure](#project-structure)
7. [Running Tests](#running-tests)
8. [Security Notes](#security-notes)

---

## How It Works

### Gmail Add-on (Manual Mode)

```
Open Email in Gmail
  → Click "Phishing Checker" sidebar icon
  → Click "Analyze This Email"
  → AI analyzes sender / URLs / content / auth headers
  → Results card: Verdict · Score · Red Flags · Confidence
  → Optional: Apply PHISHING or SUSPICIOUS label
```

### Python Backend (Automatic Mode)

```
New Email Arrives → Gmail → Cloud Pub/Sub Push Notification
  → Flask Webhook → Gmail API (fetch full email)
  → Parser (sender, URLs, SPF/DKIM/DMARC, attachments)
  → AI Analysis (6 dimensions)
  → Label email (PHISHING_DETECTED / SUSPICIOUS)
  → Send warning email to yourself
```

---

## Screenshots

### Gmail Add-on Sidebar

| Home Card | Analysis Results |
|-----------|-----------------|
| ![Home Card](docs/screenshots/addon_home_card.png) | ![Results Card](docs/screenshots/addon_results_card.png) |

### Gmail Labels Applied

![Gmail Labels](docs/screenshots/gmail_labels.png)

### Apps Script — Script Properties Setup

![Script Properties](docs/screenshots/script_properties.png)

### Apps Script — Project Settings

![Project Settings](docs/screenshots/apps_script_project_settings.png)

### GCP Console — Pub/Sub Topic

![Pub/Sub Topic](docs/screenshots/gcp_pubsub_topic.png)

### GCP Console — OAuth Credentials

![OAuth Credentials](docs/screenshots/gcp_oauth_credentials.png)

> **Note:** To add your own screenshots, take them and save to `docs/screenshots/` using the filenames above.

---

## Gmail Add-on — Setup Guide

The Gmail Add-on runs entirely inside Google Apps Script — no server, no Python, no cloud infrastructure needed. You configure it once via Script Properties and it works for any email you open in Gmail.

### Prerequisites

- A Google account (Gmail)
- [Node.js](https://nodejs.org) (for `clasp` CLI)
- One AI provider credential (see [AI Provider Configuration](#ai-provider-configuration))

### Step 1: Install clasp

[clasp](https://github.com/google/clasp) is Google's CLI for managing Apps Script projects locally.

```bash
npm install -g @google/clasp
clasp login
```

`clasp login` opens a browser — sign in with your Google account.

### Step 2: Clone This Repo

```bash
git clone https://github.com/TilanTAB/AI-Phsishing-Detector.git
cd AI-Phsishing-Detector
```

### Step 3: Create an Apps Script Project

1. Go to [script.google.com](https://script.google.com)
2. Click **New Project**
3. Click the project title (top-left, currently "Untitled project") and rename it to **Phishing Checker**
4. Copy the **Script ID** from the URL: `https://script.google.com/home/projects/SCRIPT_ID_HERE/edit`

Now link your local clone to this project:

```bash
cd addon
```

Edit `addon/.clasp.json` and replace the `scriptId` value:

```json
{
  "scriptId": "YOUR_SCRIPT_ID_HERE",
  "rootDir": "."
}
```

### Step 4: Push Code to Apps Script

```bash
cd addon
npx clasp push
```

You should see all 13 files uploaded:

```
Pushed 13 files.
└─ AIProvider.gs   └─ AzureOpenAI.gs   └─ BedrockClaude.gs
└─ Card.gs         └─ Code.gs          └─ Config.gs
└─ GeminiAI.gs     └─ GmailHelper.gs   └─ Models.gs
└─ Prompt.gs       └─ Utils.gs         └─ VertexAI.gs
└─ appsscript.json
```

### Step 5: Configure Script Properties

Script Properties are the add-on's environment variables — they hold your API keys and provider selection. **Never hardcode secrets in the source files.**

1. In the Apps Script Editor, click the gear icon (**Project Settings**)
2. Scroll down to **Script Properties**
3. Click **Add script property** for each key below

#### Required Properties (All Providers)

| Property | Value | Description |
|---|---|---|
| `AI_PROVIDER` | `gemini` | Active AI provider. Options: `azure_openai`, `bedrock_claude`, `gemini`, `vertex_ai` |

#### Azure OpenAI Provider

| Property | Example Value | Description |
|---|---|---|
| `AZURE_ENDPOINT` | `https://my-resource.openai.azure.com/` | Your Azure OpenAI resource endpoint |
| `AZURE_API_KEY` | `abc123...` | API key from Azure Portal |
| `AZURE_DEPLOYMENT` | `gpt-4o` | Deployed model name |
| `AZURE_API_VERSION` | `2024-10-21` | API version |

#### Amazon Bedrock Claude Provider

| Property | Example Value | Description |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | `AKIA...` | IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | `abc123...` | IAM user secret key |
| `AWS_REGION` | `us-east-1` | AWS region where Bedrock is enabled |
| `BEDROCK_MODEL_ID` | `us.anthropic.claude-haiku-4-5-20251001-v1:0` | Inference profile ID (must use `us.` prefix for Claude 4.x) |

> **Important:** Claude 4.x models on Bedrock require an **inference profile ID**, not the bare model ID. Use `us.anthropic.claude-...` format.

#### Google Gemini API Provider

| Property | Example Value | Description |
|---|---|---|
| `GEMINI_API_KEY` | `AIza...` | API key from [Google AI Studio](https://aistudio.google.com) |
| `GEMINI_MODEL` | `gemini-1.5-pro` | Model name |

#### Google Vertex AI Provider

| Property | Example Value | Description |
|---|---|---|
| `VERTEX_PROJECT_ID` | `my-gcp-project` | GCP project ID |
| `VERTEX_LOCATION` | `us-central1` | Region |
| `VERTEX_MODEL` | `gemini-1.5-pro` | Model name |

> **Note:** Vertex AI uses `ScriptApp.getOAuthToken()` for authentication — no service account key needed, as long as the add-on is running under a Google account with Vertex AI access.

#### Optional Properties

| Property | Default | Description |
|---|---|---|
| `TEST_MODE` | `false` | Set to `true` to return a mock result without calling any AI API (useful for UI testing) |
| `ANALYSIS_TIMEOUT_SECONDS` | `25` | Max seconds to wait for AI response (5–28, must stay under Apps Script's 30s limit) |

![Script Properties Screenshot](docs/screenshots/script_properties.png)

### Step 6: Deploy as Gmail Add-on

1. In the Apps Script Editor, click **Deploy → Test deployments**
2. Under **Gmail Add-on**, click **Install**
3. Authorize the requested permissions (Gmail read, labels, external requests)
4. Open Gmail — you should see the **Phishing Checker** shield icon in the right sidebar

### Step 7: Analyze Your First Email

1. Open any email in Gmail
2. Click the **Phishing Checker** icon in the right sidebar
3. Click **Analyze This Email**
4. Wait ~5 seconds — the results card appears with:
   - **Verdict**: SAFE / SUSPICIOUS / PHISHING
   - **Score**: 0–100
   - **Confidence**: how certain the AI is
   - **Red Flags**: specific issues detected (category, severity, description)
5. Optionally click **Apply Label** to tag the email in Gmail

---

## Python Backend — Setup Guide

The Python backend automates everything. It watches your inbox 24/7 via Google Cloud Pub/Sub push notifications and labels + alerts you without any manual action.

### Prerequisites

- Python 3.11+
- A Google Cloud Platform (GCP) project
- One AI provider credential (Azure OpenAI or Amazon Bedrock)
- A public HTTPS URL for the webhook (use [ngrok](https://ngrok.com) for local dev)

### Step 1: Set Up Google Cloud Platform

#### 1.1 Create a GCP Project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Click the project selector at the top → **New Project**
3. Name it `gmail-phishing-checker` → **Create**
4. Note your **Project ID**

#### 1.2 Enable Required APIs

Enable both of these in your GCP project:

- **Gmail API**: search "Gmail API" in the [API Library](https://console.cloud.google.com/apis/library) → **Enable**
- **Cloud Pub/Sub API**: search "Cloud Pub/Sub" → **Enable**

#### 1.3 Create OAuth 2.0 Credentials

1. Go to **APIs & Services → Credentials → + Create Credentials → OAuth client ID**
2. Configure the OAuth consent screen first if prompted:
   - User type: **External**
   - App name: `Gmail Phishing Checker`
   - Add your Gmail as a test user
   - Scopes: `gmail.modify`, `gmail.send`
3. Application type: **Desktop app** → **Create**
4. Click **Download JSON** → save as `credentials.json` in the project root
5. **NEVER commit `credentials.json`** (it's in `.gitignore`)

![GCP OAuth Screenshot](docs/screenshots/gcp_oauth_credentials.png)

#### 1.4 Create a Pub/Sub Topic

```bash
gcloud config set project YOUR_PROJECT_ID
gcloud pubsub topics create gmail-notifications
```

#### 1.5 Grant Gmail Push Permission

```bash
gcloud pubsub topics add-iam-policy-binding gmail-notifications \
  --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
  --role="roles/pubsub.publisher"
```

#### 1.6 Create a Push Subscription

```bash
gcloud pubsub subscriptions create gmail-notifications-sub \
  --topic=gmail-notifications \
  --push-endpoint=https://YOUR_WEBHOOK_URL/pubsub?token=YOUR_SECRET_TOKEN \
  --ack-deadline=30
```

Replace `YOUR_WEBHOOK_URL` with your public HTTPS URL (see ngrok below) and `YOUR_SECRET_TOKEN` with a random string you'll also put in `.env`.

![GCP Pub/Sub Screenshot](docs/screenshots/gcp_pubsub_topic.png)

### Step 2: Set Up ngrok (Local Development)

```bash
# Install ngrok from https://ngrok.com/download
ngrok http 8080
```

Copy the `https://xxxx.ngrok-free.app` URL. Update your Pub/Sub subscription whenever your ngrok URL changes:

```bash
gcloud pubsub subscriptions modify-push-config gmail-notifications-sub \
  --push-endpoint=https://xxxx.ngrok-free.app/pubsub?token=YOUR_SECRET_TOKEN
```

### Step 3: Install and Configure

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate
# Activate (Mac/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
```

Edit `.env` with your values:

```env
AI_PROVIDER=bedrock_claude     # azure_openai | bedrock_claude

# Amazon Bedrock
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
BEDROCK_MODEL_ID=us.anthropic.claude-haiku-4-5-20251001-v1:0

# OR Azure OpenAI
# AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
# AZURE_OPENAI_API_KEY=your-key
# AZURE_OPENAI_DEPLOYMENT=gpt-4o
# AZURE_OPENAI_API_VERSION=2024-10-21

# Google Cloud
GCP_PROJECT_ID=your-gcp-project-id
PUBSUB_TOPIC=gmail-notifications
PUBSUB_VERIFICATION_TOKEN=your-secret-token

# Server
WEBHOOK_HOST=0.0.0.0
WEBHOOK_PORT=8080
SEND_WARNING_EMAIL=true
```

### Step 4: First Run (OAuth Consent)

```bash
python main.py
```

A browser window opens asking you to authorize Gmail access. This happens **once** — the token is saved to `token.json` and reused automatically.

After authorization, you'll see:

```
INFO | main | Starting Gmail Phishing Checker...
INFO | main | AI provider: bedrock_claude
INFO | gmail.labels | Label 'PHISHING_DETECTED' created (red)
INFO | gmail.labels | Label 'SUSPICIOUS' created (orange)
INFO | gmail.client | Gmail watch established. Expires at: ...
INFO | main | Webhook server starting on 0.0.0.0:8080 ...
```

Now any incoming email is analyzed automatically. Phishing emails get labeled + you receive a warning email.

---

## AI Provider Configuration

### Switching Providers

**Gmail Add-on:** Change the `AI_PROVIDER` Script Property in Apps Script → Project Settings → Script Properties.

**Python backend:** Change `AI_PROVIDER` in your `.env` file and restart.

### Provider Comparison

| Provider | Best For | Notes |
|---|---|---|
| **Gemini API** | Quick start, free tier | Get key at [aistudio.google.com](https://aistudio.google.com). Add-on default. |
| **Vertex AI** | GCP-native, no API key mgmt | Requires GCP project with Vertex AI enabled. Uses your Google OAuth token. |
| **Azure OpenAI** | GPT-4o quality | Requires Azure subscription + deployed model. |
| **Amazon Bedrock Claude** | Claude quality, AWS-native | Requires IAM user + Bedrock model access. Use inference profile IDs for Claude 4.x (`us.anthropic.claude-...`). |

### Bedrock Model IDs (Claude 4.x Inference Profiles)

| Model | Inference Profile ID |
|---|---|
| Claude Haiku 4.5 | `us.anthropic.claude-haiku-4-5-20251001-v1:0` |
| Claude Sonnet 4.5 | `us.anthropic.claude-sonnet-4-5-20251001-v1:0` |
| Claude 3.5 Sonnet v2 | `us.anthropic.claude-3-5-sonnet-20241022-v2:0` |

> Claude 4.x requires inference profile IDs (with `us.` prefix). Direct model IDs return HTTP 400.

---

## Phishing Score Reference

The AI scores every email 0–100 across 6 dimensions:

1. Sender legitimacy (domain reputation, spoofing indicators)
2. URL analysis (redirects, lookalike domains, suspicious TLDs)
3. Urgency and manipulation tactics (fear, pressure, deadlines)
4. Grammar and language anomalies
5. Impersonation indicators (brand spoofing, executive impersonation)
6. Attachment risk signals

| Score | Verdict | Action Taken |
|---|---|---|
| 0–30 | ✅ SAFE | No action |
| 31–65 | ⚠️ SUSPICIOUS | Orange label + warning email (backend) |
| 66–100 | 🚨 PHISHING | Red label + warning email (backend) |

Thresholds are configurable via `SUSPICIOUS_THRESHOLD` and `PHISHING_THRESHOLD` in `.env` (Python backend only).

---

## Project Structure

```
AI-Phishing-Detector/
│
├── addon/                          # Gmail Add-on (Google Apps Script)
│   ├── appsscript.json             # Manifest: scopes, triggers, add-on metadata
│   ├── Code.gs                     # Entry points: onGmailMessage, analyzeEmailAction
│   ├── Card.gs                     # UI cards: Home, Results, Error, Settings
│   ├── Config.gs                   # Script Properties reader + validation
│   ├── AIProvider.gs               # Provider factory + TEST_MODE mock
│   ├── AzureOpenAI.gs              # Azure OpenAI REST implementation
│   ├── BedrockClaude.gs            # Amazon Bedrock + AWS Sig V4 signing
│   ├── GeminiAI.gs                 # Gemini API REST implementation
│   ├── VertexAI.gs                 # Vertex AI (uses OAuth token, no svc account)
│   ├── GmailHelper.gs              # Email fetch, raw header parsing, label helpers
│   ├── Models.gs                   # JSON response parsing + PhishingAnalysis model
│   ├── Prompt.gs                   # System prompt + user prompt builder
│   ├── Utils.gs                    # HMAC-SHA256, HTTP fetch, URL extraction
│   └── .clasp.json                 # clasp project link (set your scriptId here)
│
├── ai/                             # Python backend — AI providers
│   ├── base.py                     # Abstract AIProvider base class
│   ├── models.py                   # PhishingAnalysis Pydantic models
│   ├── prompt.py                   # Phishing analysis prompts
│   ├── azure_openai.py             # Azure OpenAI implementation
│   ├── bedrock_claude.py           # Amazon Bedrock Claude (boto3)
│   └── __init__.py                 # Provider factory: get_provider(config)
│
├── auth/
│   └── gmail_oauth.py              # OAuth2 flow + token persistence + auto-refresh
│
├── gmail/
│   ├── client.py                   # Gmail API wrapper with tenacity retry
│   ├── labels.py                   # PHISHING_DETECTED / SUSPICIOUS label management
│   └── parser.py                   # Email extraction: sender, URLs, auth headers
│
├── pubsub/
│   ├── webhook.py                  # Flask POST /pubsub endpoint
│   └── handler.py                  # Full pipeline orchestrator
│
├── notifications/
│   └── warning_email.py            # HTML + plain text warning email composer
│
├── tests/
│   ├── conftest.py
│   ├── test_config.py
│   ├── test_gmail_parser.py
│   ├── test_ai_prompt.py
│   ├── test_pubsub_handler.py
│   └── fixtures/
│       ├── legitimate_email.json
│       ├── phishing_email.json
│       └── suspicious_email.json
│
├── docs/
│   └── screenshots/                # UI screenshots referenced in this README
│
├── main.py                         # Entry point + watch renewal daemon
├── config.py                       # Pydantic BaseSettings + per-provider validation
├── requirements.txt
├── .env.example                    # Environment variable template
└── .gitignore
```

---

## Running Tests

Tests cover the Python backend. All Gmail API and AI calls are mocked — no external services needed.

```bash
# Activate virtual environment first
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows

pytest tests/ -v
```

Expected output: **37 tests passing**.

---

## Security Notes

- `credentials.json`, `token.json`, and `.env` are in `.gitignore` — **never commit them**
- Script Properties in Apps Script are encrypted at rest by Google — safe for API keys
- Use a strong random string for `PUBSUB_VERIFICATION_TOKEN`
- For production AWS, prefer IAM roles over long-lived access keys
- For production webhook, use a proper TLS certificate (not ngrok)
- The Vertex AI provider uses `ScriptApp.getOAuthToken()` (short-lived OAuth token) — no long-lived service account key stored anywhere

---

## Troubleshooting

### Gmail Add-on

| Symptom | Fix |
|---|---|
| "Missing Script Properties" error | Go to Project Settings → Script Properties, add all required keys for your provider |
| Analysis times out | Increase `ANALYSIS_TIMEOUT_SECONDS` or switch to a faster model (Haiku, Gemini Flash) |
| Bedrock HTTP 400 "inference profile" error | Use inference profile ID format: `us.anthropic.claude-...` instead of bare model ID |
| Add-on not appearing in Gmail | In Apps Script Editor → Deploy → Test deployments → Install the Gmail Add-on |

### Python Backend

| Symptom | Fix |
|---|---|
| `credentials.json` not found | Download it from GCP Console → APIs & Services → Credentials |
| Pub/Sub not delivering | Ensure ngrok is running and the push endpoint URL is up to date |
| Watch expired | The watch renewal daemon runs every 6 days automatically; restart `main.py` if it was stopped |
| AI API errors | Check `.env` values; run `pytest tests/ -v` to validate config |

---

## License

MIT
