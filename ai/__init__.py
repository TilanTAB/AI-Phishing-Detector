"""
AI provider factory.

Returns the appropriate AI provider based on configuration.
"""

from config import AIProviderType, Settings

from .base import AIProvider


def get_provider(settings: Settings) -> AIProvider:
    """Create and return the configured AI provider instance."""
    if settings.ai_provider == AIProviderType.AZURE_OPENAI:
        from .azure_openai import AzureOpenAIProvider

        return AzureOpenAIProvider(settings)

    elif settings.ai_provider == AIProviderType.BEDROCK_CLAUDE:
        from .bedrock_claude import BedrockClaudeProvider

        return BedrockClaudeProvider(settings)

    raise ValueError(f"Unknown AI provider: {settings.ai_provider}")
