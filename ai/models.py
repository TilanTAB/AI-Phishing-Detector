"""
Pydantic models for AI phishing analysis responses.

These models define the structured output expected from the AI providers
and are used to validate and parse the JSON responses.
"""

from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RedFlagCategory(str, Enum):
    SENDER = "sender"
    URL = "url"
    URGENCY = "urgency"
    GRAMMAR = "grammar"
    IMPERSONATION = "impersonation"
    ATTACHMENT = "attachment"


class RedFlag(BaseModel):
    category: RedFlagCategory
    detail: str
    severity: Severity


class PhishingAnalysis(BaseModel):
    """Structured result from AI phishing analysis."""

    score: int = Field(ge=0, le=100, description="Phishing score: 0 = safe, 100 = certain phishing")
    verdict: Verdict = Field(description="Overall verdict: safe, suspicious, or phishing")
    reasoning: str = Field(description="2-3 sentence summary of the assessment")
    red_flags: list[RedFlag] = Field(default_factory=list, description="Specific phishing indicators found")
    confidence: float = Field(ge=0.0, le=1.0, description="AI confidence in its assessment")
