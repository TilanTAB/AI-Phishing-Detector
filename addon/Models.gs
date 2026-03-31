/**
 * Models.gs
 * Parses and validates the JSON response from any AI provider
 * into a consistent PhishingResult object.
 */

var VALID_CATEGORIES = Object.freeze(['sender', 'url', 'urgency', 'grammar', 'impersonation', 'attachment']);
var VALID_SEVERITIES  = Object.freeze(['low', 'medium', 'high']);
var VALID_VERDICTS    = Object.freeze(['safe', 'suspicious', 'phishing']);

/**
 * Parses raw AI response text into a PhishingResult object.
 * Robustly handles markdown code fences and trailing text by extracting
 * the first complete JSON object (from first '{' to last '}').
 *
 * @param {string} rawText - Raw text response from AI provider
 * @returns {{score: number, verdict: string, reasoning: string, redFlags: Array, confidence: number}}
 * @throws {Error} If JSON is invalid or required fields are missing/invalid
 */
function parseAnalysis(rawText) {
  // Log full response to Cloud Logging for debugging
  console.log('AI raw response (' + rawText.length + ' chars): ' + rawText.substring(0, 500));

  var text = rawText.trim();

  // Robustly extract JSON: find first '{' and last '}' to handle:
  // - markdown code fences (```json ... ```)
  // - trailing text after the closing brace
  var firstBrace = text.indexOf('{');
  var lastBrace  = text.lastIndexOf('}');

  if (firstBrace === -1 || lastBrace <= firstBrace) {
    throw new Error('No JSON object found in AI response. Got: ' + text.substring(0, 200));
  }

  text = text.substring(firstBrace, lastBrace + 1);

  var data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new Error('AI returned invalid JSON: ' + e.message + '. Extracted: ' + text.substring(0, 300));
  }

  // --- Validate score ---
  if (typeof data.score !== 'number' || data.score < 0 || data.score > 100) {
    throw new Error('Invalid or missing "score" (expected integer 0-100). Got: ' + data.score);
  }

  // --- Validate verdict ---
  if (VALID_VERDICTS.indexOf(data.verdict) === -1) {
    throw new Error('Invalid "verdict": "' + data.verdict + '". Expected: safe | suspicious | phishing');
  }

  // --- Validate reasoning ---
  if (typeof data.reasoning !== 'string' || data.reasoning.trim().length === 0) {
    throw new Error('Missing or empty "reasoning" in AI response.');
  }

  // --- Validate & filter red_flags ---
  var rawFlags = Array.isArray(data.red_flags) ? data.red_flags : [];
  var redFlags = rawFlags.filter(function(f) {
    return f &&
      typeof f.detail === 'string' && f.detail.trim().length > 0 &&
      VALID_CATEGORIES.indexOf(f.category) !== -1 &&
      VALID_SEVERITIES.indexOf(f.severity) !== -1;
  }).slice(0, 20); // Cap at 20 to stay within card widget limits

  // --- Validate & clamp confidence ---
  var confidence = (typeof data.confidence === 'number')
    ? Math.max(0.0, Math.min(1.0, data.confidence))
    : 0.5;

  return {
    score:      Math.round(data.score),
    verdict:    data.verdict,
    reasoning:  data.reasoning.trim(),
    redFlags:   redFlags,
    confidence: confidence,
    isFallback: false
  };
}

/**
 * Returns a safe fallback result when AI analysis fails.
 * Always marks as SUSPICIOUS (score=50) to ensure manual review.
 * Card.gs uses isFallback=true to show a distinct "Analysis Failed" banner.
 *
 * @param {string} errorMessage
 * @returns {Object}
 */
function fallbackResult(errorMessage) {
  console.error('AI analysis fallback triggered: ' + errorMessage);
  return {
    score:      50,
    verdict:    'suspicious',
    reasoning:  'AI analysis failed — manual review recommended.',
    redFlags:   [],
    confidence: 0.0,
    isFallback: true,
    error:      errorMessage
  };
}
