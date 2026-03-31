/**
 * GeminiAI.gs
 * Phishing analysis using Google Gemini API (API key auth).
 * Simplest provider — REST call with API key in URL.
 *
 * Required Script Properties:
 *   GEMINI_API_KEY  — API key from aistudio.google.com
 *   GEMINI_MODEL    — e.g. "gemini-1.5-pro" or "gemini-1.5-flash"
 */

var GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/models/';

/**
 * Analyzes email data for phishing using Gemini API.
 * Returns a parsed PhishingResult object.
 *
 * @param {Object} emailData - From GmailHelper.getEmailData()
 * @returns {Object} PhishingResult from Models.parseAnalysis()
 */
function geminiAnalyze(emailData) {
  var apiKey = getProp('GEMINI_API_KEY');
  var model  = getProp('GEMINI_MODEL') || 'gemini-1.5-flash';
  var url    = GEMINI_BASE_URL + model + ':generateContent?key=' + apiKey;

  var payload = JSON.stringify({
    systemInstruction: {
      parts: [{ text: SYSTEM_PROMPT }]
    },
    contents: [{
      role: 'user',
      parts: [{ text: buildUserPrompt(emailData) }]
    }],
    generationConfig: {
      temperature: 0.1,
      maxOutputTokens: 1024,
      responseMimeType: 'application/json'
    }
  });

  console.log('GeminiAI: calling ' + model + ' for message ' + emailData.messageId);

  var result = httpFetch(url, {
    method: 'post',
    contentType: 'application/json',
    payload: payload
  });

  if (!result.ok) {
    throw new Error('Gemini API error: ' + result.error);
  }

  var response = JSON.parse(result.text);
  var content  = response.candidates &&
                 response.candidates[0] &&
                 response.candidates[0].content &&
                 response.candidates[0].content.parts &&
                 response.candidates[0].content.parts[0] &&
                 response.candidates[0].content.parts[0].text;

  if (!content) {
    throw new Error('Gemini returned empty content. Full response: ' + result.text.substring(0, 300));
  }

  return parseAnalysis(content);
}
