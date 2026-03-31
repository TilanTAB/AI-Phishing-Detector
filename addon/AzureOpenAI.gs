/**
 * AzureOpenAI.gs
 * Phishing analysis using Azure OpenAI chat completions REST API.
 *
 * Required Script Properties:
 *   AZURE_ENDPOINT      — e.g. https://your-resource.openai.azure.com/
 *   AZURE_API_KEY       — API key from Azure Portal
 *   AZURE_DEPLOYMENT    — deployment name, e.g. "gpt-4o"
 *   AZURE_API_VERSION   — e.g. "2024-10-21"
 */

/**
 * Analyzes email data for phishing using Azure OpenAI.
 *
 * @param {Object} emailData - From GmailHelper.getEmailData()
 * @returns {Object} PhishingResult from Models.parseAnalysis()
 */
function azureOpenAIAnalyze(emailData) {
  var endpoint   = getProp('AZURE_ENDPOINT').replace(/\/$/, '');
  var deployment = getProp('AZURE_DEPLOYMENT');
  var apiVersion = getProp('AZURE_API_VERSION') || '2024-10-21';
  var apiKey     = getProp('AZURE_API_KEY');

  var url = endpoint +
    '/openai/deployments/' + deployment +
    '/chat/completions?api-version=' + apiVersion;

  var payload = JSON.stringify({
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user',   content: buildUserPrompt(emailData) }
    ],
    response_format: { type: 'json_object' },
    temperature: 0.1,
    max_tokens: 1024
  });

  console.log('AzureOpenAI: calling deployment=' + deployment + ' for message ' + emailData.messageId);

  var result = httpFetch(url, {
    method: 'post',
    contentType: 'application/json',
    headers: { 'api-key': apiKey },
    payload: payload
  });

  if (!result.ok) {
    throw new Error('Azure OpenAI error: ' + result.error);
  }

  var response = JSON.parse(result.text);
  var content  = response.choices &&
                 response.choices[0] &&
                 response.choices[0].message &&
                 response.choices[0].message.content;

  if (!content) {
    throw new Error('Azure OpenAI returned empty content. Response: ' + result.text.substring(0, 300));
  }

  return parseAnalysis(content);
}
