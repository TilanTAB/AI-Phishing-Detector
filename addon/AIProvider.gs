/**
 * AIProvider.gs
 * Factory that routes analyze() calls to the correct AI provider
 * based on the AI_PROVIDER Script Property.
 *
 * In TEST_MODE=true, returns a hardcoded result without any real API call,
 * enabling fast Card.gs UI development without burning API credits.
 */

/**
 * Analyzes email data using the configured AI provider.
 * Never throws — wraps failures in fallbackResult() so the card always renders.
 *
 * @param {Object} emailData - From GmailHelper.getEmailData()
 * @returns {Object} PhishingResult: {score, verdict, reasoning, redFlags[], confidence, isFallback}
 */
function analyzeWithAI(emailData) {
  // Test mode — return hardcoded result immediately, no API call
  if (isTestMode()) {
    console.log('TEST_MODE active — returning mock phishing result');
    return {
      score:      82,
      verdict:    'phishing',
      reasoning:  '[TEST MODE] This is a mock phishing result for UI development. No real AI call was made.',
      redFlags: [
        { category: 'sender',      detail: 'Mock: lookalike domain detected', severity: 'high' },
        { category: 'urgency',     detail: 'Mock: 24-hour account suspension threat', severity: 'high' },
        { category: 'url',         detail: 'Mock: suspicious .xyz TLD in link', severity: 'medium' }
      ],
      confidence: 0.95,
      isFallback: false
    };
  }

  var provider;
  try {
    provider = getProvider();
    validateConfig(provider);
  } catch (e) {
    return fallbackResult('Configuration error: ' + e.message);
  }

  console.log('AIProvider: using provider=' + provider + ' for message ' + emailData.messageId);

  try {
    switch (provider) {
      case 'gemini':        return geminiAnalyze(emailData);
      case 'azure_openai':  return azureOpenAIAnalyze(emailData);
      case 'bedrock_claude': return bedrockClaudeAnalyze(emailData);
      case 'vertex_ai':     return vertexAIAnalyze(emailData);
      default:
        return fallbackResult('Unknown provider: ' + provider);
    }
  } catch (e) {
    console.error('AIProvider error for provider=' + provider + ': ' + e.message);
    return fallbackResult(e.message);
  }
}
