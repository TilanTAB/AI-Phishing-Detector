/**
 * VertexAI.gs
 * Phishing analysis using Google Vertex AI (Gemini models on Vertex).
 *
 * Auth: Uses ScriptApp.getOAuthToken() — the OAuth token of the user running
 * the add-on. This requires:
 *   1. The Apps Script project to be linked to a GCP project
 *   2. The Vertex AI API to be enabled on that GCP project
 *   3. The user to have roles/aiplatform.user on the project
 *
 * No service account key needed. Far simpler than JWT signing.
 *
 * Required Script Properties:
 *   VERTEX_PROJECT_ID — GCP project ID
 *   VERTEX_LOCATION   — e.g. "us-central1"
 *   VERTEX_MODEL      — e.g. "gemini-1.5-pro"
 */

var VERTEX_BASE_URL = 'https://{LOCATION}-aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/{LOCATION}/publishers/google/models/{MODEL}:generateContent';

/**
 * Analyzes email data for phishing using Vertex AI.
 *
 * @param {Object} emailData - From GmailHelper.getEmailData()
 * @returns {Object} PhishingResult from Models.parseAnalysis()
 */
function vertexAIAnalyze(emailData) {
  var projectId = getProp('VERTEX_PROJECT_ID');
  var location  = getProp('VERTEX_LOCATION') || 'us-central1';
  var model     = getProp('VERTEX_MODEL') || 'gemini-1.5-pro';

  var url = VERTEX_BASE_URL
    .replace(/{LOCATION}/g, location)
    .replace('{PROJECT}', projectId)
    .replace('{MODEL}', model);

  // Get the user's OAuth2 token — no service account needed
  var token = ScriptApp.getOAuthToken();

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

  console.log('VertexAI: calling model=' + model + ' project=' + projectId + ' for message ' + emailData.messageId);

  var result = httpFetch(url, {
    method: 'post',
    contentType: 'application/json',
    headers: { 'Authorization': 'Bearer ' + token },
    payload: payload
  });

  if (!result.ok) {
    throw new Error('Vertex AI error: ' + result.error);
  }

  var response = JSON.parse(result.text);
  var content  = response.candidates &&
                 response.candidates[0] &&
                 response.candidates[0].content &&
                 response.candidates[0].content.parts &&
                 response.candidates[0].content.parts[0] &&
                 response.candidates[0].content.parts[0].text;

  if (!content) {
    throw new Error('Vertex AI returned empty content. Response: ' + result.text.substring(0, 300));
  }

  return parseAnalysis(content);
}
