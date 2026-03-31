"""
Azure OpenAI phishing analysis provider.

Uses the OpenAI Python SDK with AzureOpenAI client to send email data
for phishing analysis and parse the structured JSON response.
"""

import json
import logging

from openai import AzureOpenAI
from pydantic import ValidationError
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from config import Settings
from .base import AIProvider, AIAnalysisError
from .models import PhishingAnalysis
from .prompt import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger(__name__)


class AzureOpenAIProvider(AIProvider):
    """Phishing analysis using Azure OpenAI."""

    def __init__(self, settings: Settings):
        self._client = AzureOpenAI(
            azure_endpoint=settings.azure_openai_endpoint,
            api_key=settings.azure_openai_api_key,
            api_version=settings.azure_openai_api_version,
        )
        self._deployment = settings.azure_openai_deployment

    @retry(
        retry=retry_if_exception_type((ConnectionError, TimeoutError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=16),
        reraise=True,
    )
    def analyze(self, email_data: dict) -> PhishingAnalysis:
        """
        Send email data to Azure OpenAI for phishing analysis.

        Args:
            email_data: Dictionary from ParsedEmail.to_dict().

        Returns:
            Validated PhishingAnalysis result.

        Raises:
            AIAnalysisError: On persistent failure or invalid response.
        """
        user_prompt = build_user_prompt(email_data)

        try:
            response = self._client.chat.completions.create(
                model=self._deployment,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=1024,
            )

            content = response.choices[0].message.content
            if not content:
                raise AIAnalysisError("Azure OpenAI returned empty response content.")

            return self._parse_response(content)

        except (ConnectionError, TimeoutError):
            raise  # Let tenacity handle retries
        except AIAnalysisError:
            raise
        except Exception as e:
            logger.error("Azure OpenAI analysis failed: %s", e, exc_info=True)
            raise AIAnalysisError(f"Azure OpenAI analysis failed: {e}") from e

    def _parse_response(self, content: str) -> PhishingAnalysis:
        """Parse and validate the JSON response from Azure OpenAI."""
        try:
            data = json.loads(content)
            return PhishingAnalysis.model_validate(data)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Azure OpenAI JSON response: %s", content[:500])
            raise AIAnalysisError(f"Invalid JSON from Azure OpenAI: {e}") from e
        except ValidationError as e:
            logger.error("Azure OpenAI response failed validation: %s", e)
            raise AIAnalysisError(f"Response validation failed: {e}") from e
