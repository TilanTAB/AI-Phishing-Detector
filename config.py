"""
Central configuration for the Gmail Phishing Checker.

Loads settings from environment variables / .env file using Pydantic.
Validates that provider-specific settings are present based on AI_PROVIDER choice.
"""

import logging
from enum import Enum
from typing import Optional

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AIProviderType(str, Enum):
    AZURE_OPENAI = "azure_openai"
    BEDROCK_CLAUDE = "bedrock_claude"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # --- AI Provider ---
    ai_provider: AIProviderType = AIProviderType.AZURE_OPENAI

    # --- Azure OpenAI ---
    azure_openai_endpoint: Optional[str] = None
    azure_openai_api_key: Optional[str] = None
    azure_openai_deployment: str = "gpt-4o"
    azure_openai_api_version: str = "2024-10-21"

    # --- Amazon Bedrock ---
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    bedrock_model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"

    # --- Gmail OAuth ---
    google_credentials_file: str = "credentials.json"
    google_token_file: str = "token.json"

    # --- Google Cloud Pub/Sub ---
    gcp_project_id: str
    pubsub_topic: str = "gmail-notifications"
    pubsub_verification_token: Optional[str] = None

    # --- Server ---
    webhook_host: str = "0.0.0.0"
    webhook_port: int = Field(default=8080, ge=1, le=65535)

    # --- Behavior ---
    send_warning_email: bool = True
    suspicious_threshold: int = Field(default=31, ge=0, le=100)
    phishing_threshold: int = Field(default=66, ge=0, le=100)

    # --- Logging ---
    log_level: str = "INFO"

    @model_validator(mode="after")
    def validate_provider_settings(self) -> "Settings":
        if self.ai_provider == AIProviderType.AZURE_OPENAI:
            if not self.azure_openai_endpoint:
                raise ValueError(
                    "AZURE_OPENAI_ENDPOINT is required when AI_PROVIDER=azure_openai"
                )
            if not self.azure_openai_api_key:
                raise ValueError(
                    "AZURE_OPENAI_API_KEY is required when AI_PROVIDER=azure_openai"
                )

        elif self.ai_provider == AIProviderType.BEDROCK_CLAUDE:
            if not self.aws_access_key_id:
                raise ValueError(
                    "AWS_ACCESS_KEY_ID is required when AI_PROVIDER=bedrock_claude"
                )
            if not self.aws_secret_access_key:
                raise ValueError(
                    "AWS_SECRET_ACCESS_KEY is required when AI_PROVIDER=bedrock_claude"
                )

        if self.suspicious_threshold >= self.phishing_threshold:
            raise ValueError(
                f"SUSPICIOUS_THRESHOLD ({self.suspicious_threshold}) must be "
                f"less than PHISHING_THRESHOLD ({self.phishing_threshold})"
            )

        return self


def load_settings() -> Settings:
    """Load and validate settings. Raises ValidationError on invalid config."""
    return Settings()


def configure_logging(settings: Settings) -> None:
    """Configure root logger based on settings."""
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
