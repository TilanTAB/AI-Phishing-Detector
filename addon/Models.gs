/**
 * Models.gs
 * Parses and validates the JSON response from any AI provider
 * into a consistent PhishingResult object.
 */

var VALID_CATEGORIES = Object.freeze(['sender', 'url', 'urgency', 'grammar', 'impersonation', 'attachment', 'manipulation']);
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
  console.log('AI response received (' + rawText.length + ' chars).');

  var text = rawText.trim();

  // Robustly extract JSON: find first '{' and last '}' to handle:
  // - markdown code fences (```json ... ```)
  // - trailing text after the closing brace
  var firstBrace = text.indexOf('{');
  var lastBrace  = text.lastIndexOf('}');

  if (firstBrace === -1 || lastBrace <= firstBrace) {
    throw new Error('No JSON object found in AI response.');
  }

  text = text.substring(firstBrace, lastBrace + 1);

  var data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new Error('AI returned invalid JSON: ' + sanitizeLogValue(e.message));
  }

  // --- Validate score ---
  if (typeof data.score !== 'number' || data.score < 0 || data.score > 100) {
    throw new Error('Invalid or missing "score" (expected integer 0-100). Got: ' + data.score);
  }
  var score = Math.round(data.score);

  // --- Validate verdict enum (model's claimed verdict) ---
  if (VALID_VERDICTS.indexOf(data.verdict) === -1) {
    throw new Error('Invalid "verdict": "' + data.verdict + '". Expected: safe | suspicious | phishing');
  }

  // --- Validate reasoning ---
  if (typeof data.reasoning !== 'string' || data.reasoning.trim().length === 0) {
    throw new Error('Missing or empty "reasoning" in AI response.');
  }

  // --- Validate & filter red_flags ---
  // Normalize category/severity casing + whitespace BEFORE validating. The producer is an LLM
  // whose output casing is not guaranteed, and the Layer-4 floor below depends on a
  // 'manipulation' flag surviving this filter. Exact-match would let "Manipulation" or "High"
  // silently drop the flag and bypass the floor.
  var rawFlags = Array.isArray(data.red_flags) ? data.red_flags : [];
  var redFlags = rawFlags.map(function(f) {
    if (!f || typeof f.category !== 'string' || typeof f.severity !== 'string' || typeof f.detail !== 'string') {
      return null;
    }
    return {
      category: f.category.toLowerCase().trim(),
      severity: f.severity.toLowerCase().trim(),
      detail:   f.detail
    };
  }).filter(function(f) {
    return f && f.detail.trim().length > 0 &&
      VALID_CATEGORIES.indexOf(f.category) !== -1 &&
      VALID_SEVERITIES.indexOf(f.severity) !== -1;
  }).slice(0, 20); // Cap at 20 to stay within card widget limits

  // --- Layer 4 backstop: a detected analyzer-manipulation attempt can never resolve to SAFE,
  // even if the (attacker-influenced) score is low. Depends on 'manipulation' being a member of
  // VALID_CATEGORIES above — do not remove it without removing this block. ---
  var injectionDetected = redFlags.some(function(f) { return f.category === 'manipulation'; });
  if (injectionDetected) {
    var floored = Math.max(score, 66);
    if (floored !== score) {
      console.warn('Manipulation flag present; flooring score ' + score + ' -> ' + floored);
    }
    score = floored;
  }

  // --- Derive verdict from the (possibly floored) score ---
  var derivedVerdict = verdictFromScore(score);
  if (data.verdict !== derivedVerdict) {
    console.warn(
      'AI verdict mismatch corrected: score=' + score +
      ' model_verdict=' + sanitizeLogValue(data.verdict) +
      ' derived_verdict=' + derivedVerdict
    );
  }

  // --- Validate & clamp confidence ---
  var confidence = (typeof data.confidence === 'number')
    ? Math.max(0.0, Math.min(1.0, data.confidence))
    : 0.5;

  return {
    score:      score,
    verdict:    derivedVerdict,
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
  var safeError = sanitizeLogValue(errorMessage).substring(0, 160);
  console.error('AI analysis fallback triggered: ' + safeError);
  return {
    score:      50,
    verdict:    'suspicious',
    reasoning:  'AI analysis failed — manual review recommended.',
    redFlags:   [],
    confidence: 0.0,
    isFallback: true,
    error:      safeError
  };
}

/**
 * Derives the verdict from the local score thresholds.
 * @param {number} score
 * @returns {string}
 */
function verdictFromScore(score) {
  if (score <= 30) return 'safe';
  if (score <= 65) return 'suspicious';
  return 'phishing';
}

/**
 * Editor-runnable test for the Layer-4 injection score floor in parseAnalysis().
 * Run from the Apps Script editor; check the Execution log for "ALL PASSED".
 * Pure logic — no network or AI calls.
 */
function test_injectionFloor() {
  function check(name, obj, expectedScore, expectedVerdict) {
    var r = parseAnalysis(JSON.stringify(obj));
    if (r.score !== expectedScore || r.verdict !== expectedVerdict) {
      throw new Error('FAIL ' + name + ': got score=' + r.score + ' verdict=' + r.verdict +
        ' (expected score=' + expectedScore + ' verdict=' + expectedVerdict + ')');
    }
    console.log('PASS ' + name);
  }

  // manipulation flag + low score -> floored to 66 (phishing)
  check('low_score_manipulation',
    { score: 10, verdict: 'safe', reasoning: 'x',
      red_flags: [{ category: 'manipulation', detail: 'tried to override analyzer', severity: 'high' }],
      confidence: 0.9 }, 66, 'phishing');

  // manipulation flag + already-high score -> unchanged
  check('high_score_manipulation',
    { score: 90, verdict: 'phishing', reasoning: 'x',
      red_flags: [{ category: 'manipulation', detail: 'override attempt', severity: 'high' }],
      confidence: 0.9 }, 90, 'phishing');

  // non-manipulation low score -> no floor
  check('low_score_url_flag',
    { score: 10, verdict: 'safe', reasoning: 'x',
      red_flags: [{ category: 'url', detail: 'shortened link', severity: 'low' }],
      confidence: 0.9 }, 10, 'safe');

  // clean email -> safe
  check('clean_email',
    { score: 0, verdict: 'safe', reasoning: 'x', red_flags: [], confidence: 0.9 }, 0, 'safe');

  // manipulation flag with INVALID severity -> filtered out -> no floor
  // (documents the dependency: a manipulation flag must pass validation to trigger the floor)
  check('manipulation_invalid_severity_filtered',
    { score: 10, verdict: 'safe', reasoning: 'x',
      red_flags: [{ category: 'manipulation', detail: 'x', severity: 'critical' }],
      confidence: 0.9 }, 10, 'safe');

  // manipulation flag with non-lowercase category/severity -> normalized -> still floors.
  // Guards the deterministic backstop against case/whitespace drift from the (LLM) producer.
  check('manipulation_mixed_casing',
    { score: 10, verdict: 'safe', reasoning: 'x',
      red_flags: [{ category: ' Manipulation ', detail: 'override attempt', severity: 'High' }],
      confidence: 0.9 }, 66, 'phishing');

  console.log('test_injectionFloor: ALL PASSED');
}
