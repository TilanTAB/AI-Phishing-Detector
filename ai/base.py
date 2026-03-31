"""
Abstract base class for AI phishing analysis providers.

All providers implement the same interface so they can be swapped
via configuration without changing the calling code.
"""

from abc import ABC, abstractmethod

from .models import PhishingAnalysis


class AIProvider(ABC):
    """Base class for AI-powered phishing analysis providers."""

    @abstractmethod
    def analyze(self, email_data: dict) -> PhishingAnalysis:
        """
        Analyze email content for phishing indicators.

        Args:
            email_data: Dictionary from ParsedEmail.to_dict() containing
                all extracted email fields.

        Returns:
            PhishingAnalysis with score, verdict, reasoning, and red flags.

        Raises:
            AIAnalysisError: If the analysis fails after all retries.
        """
        ...


class AIAnalysisError(Exception):
    """Raised when AI analysis fails after all retry attempts."""

    pass
