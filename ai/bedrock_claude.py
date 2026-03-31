"""
Amazon Bedrock Claude phishing analysis provider.

Uses boto3 bedrock-runtime to invoke the Claude model on Bedrock
for email phishing analysis.
"""

import json
import logging

import boto3
from botocore.exceptions import ClientError
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


class BedrockClaudeProvider(AIProvider):
    """Phishing analysis using Amazon Bedrock Claude."""

    def __init__(self, settings: Settings):
        self._client = boto3.client(
            "bedrock-runtime",
            region_name=settings.aws_region,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
        )
        self._model_id = settings.bedrock_model_id

    @retry(
        retry=retry_if_exception_type(ClientError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=16),
        before_sleep=lambda retry_state: logger.warning(
            "Bedrock request failed, retrying (attempt %d)...",
            retry_state.attempt_number,
        ),
        reraise=True,
    )
    def analyze(self, email_data: dict) -> PhishingAnalysis:
        """
        Send email data to Bedrock Claude for phishing analysis.

        Args:
            email_data: Dictionary from ParsedEmail.to_dict().

        Returns:
            Validated PhishingAnalysis result.

        Raises:
            AIAnalysisError: On persistent failure or invalid response.
        """
        user_prompt = build_user_prompt(email_data)

        try:
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1024,
                "temperature": 0.1,
                "system": SYSTEM_PROMPT,
                "messages": [
                    {"role": "user", "content": user_prompt},
                ],
            }

            response = self._client.invoke_model(
                modelId=self._model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(request_body),
            )

            response_body = json.loads(response["body"].read())
            content_blocks = response_body.get("content", [])

            if not content_blocks:
                raise AIAnalysisError("Bedrock Claude returned empty content.")

            # Claude returns content as a list of blocks; get the text block
            text_content = ""
            for block in content_blocks:
                if block.get("type") == "text":
                    text_content = block.get("text", "")
                    break

            if not text_content:
                raise AIAnalysisError("No text content in Bedrock Claude response.")

            return self._parse_response(text_content)

        except ClientError:
            raise  # Let tenacity handle retries
        except AIAnalysisError:
            raise
        except Exception as e:
            logger.error("Bedrock Claude analysis failed: %s", e, exc_info=True)
            raise AIAnalysisError(f"Bedrock Claude analysis failed: {e}") from e

    def _parse_response(self, content: str) -> PhishingAnalysis:
        """Parse and validate the JSON response from Bedrock Claude."""
        # Claude may wrap JSON in markdown code blocks — strip them
        cleaned = content.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            # Remove first and last lines (```json and ```)
            lines = [l for l in lines if not l.strip().startswith("```")]
            cleaned = "\n".join(lines)

        try:
            data = json.loads(cleaned)
            return PhishingAnalysis.model_validate(data)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Bedrock Claude JSON response: %s", content[:500])
            raise AIAnalysisError(f"Invalid JSON from Bedrock Claude: {e}") from e
        except ValidationError as e:
            logger.error("Bedrock Claude response failed validation: %s", e)
            raise AIAnalysisError(f"Response validation failed: {e}") from e
