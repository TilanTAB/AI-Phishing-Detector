/**
 * Config.gs
 * Reads AI provider selection and credentials from Script Properties.
 * Script Properties act as environment variables — never hardcode secrets.
 *
 * To configure: Apps Script Editor → Project Settings → Script Properties
 */

// Immutable provider list
var VALID_PROVIDERS = Object.freeze(['azure_openai', 'bedrock_claude', 'gemini', 'vertex_ai']);

// Required Script Properties per provider (only non-secret ones surfaced in UI)
var PROVIDER_REQUIRED_KEYS = Object.freeze({
  azure_openai:  ['AZURE_ENDPOINT', 'AZURE_API_KEY', 'AZURE_DEPLOYMENT', 'AZURE_API_VERSION'],
  bedrock_claude: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION', 'BEDROCK_MODEL_ID'],
  gemini:        ['GEMINI_API_KEY', 'GEMINI_MODEL'],
  vertex_ai:     ['VERTEX_PROJECT_ID', 'VERTEX_LOCATION', 'VERTEX_MODEL']
  // Note: vertex_ai uses ScriptApp.getOAuthToken() — no service account key needed
});

// Safe-to-display keys (non-secret) for the Settings card
var PROVIDER_DISPLAY_KEYS = Object.freeze({
  azure_openai:  ['AZURE_ENDPOINT', 'AZURE_DEPLOYMENT', 'AZURE_API_VERSION'],
  bedrock_claude: ['AWS_REGION', 'BEDROCK_MODEL_ID'],
  gemini:        ['GEMINI_MODEL'],
  vertex_ai:     ['VERTEX_PROJECT_ID', 'VERTEX_LOCATION', 'VERTEX_MODEL']
});

/**
 * Returns a single Script Property value.
 * Caches ALL properties on first call within a single execution to avoid
 * repeated RPC calls to PropertiesService.
 * @param {string} key
 * @returns {string|null}
 */
var _propCache = null;
function getProp(key) {
  if (!_propCache) {
    _propCache = PropertiesService.getScriptProperties().getProperties();
  }
  return _propCache[key] || null;
}

/**
 * Returns the configured AI provider name. Defaults to 'gemini'.
 * @returns {string}
 */
function getProvider() {
  var provider = getProp('AI_PROVIDER') || 'gemini';
  if (VALID_PROVIDERS.indexOf(provider) === -1) {
    throw new Error(
      'Invalid AI_PROVIDER: "' + provider + '". Must be one of: ' + VALID_PROVIDERS.join(', ')
    );
  }
  return provider;
}

/**
 * Returns true if TEST_MODE=true is set in Script Properties.
 * In test mode, AI providers return a hardcoded result without making real API calls.
 * Useful for Card.gs UI development without burning API credits.
 * @returns {boolean}
 */
function isTestMode() {
  return getProp('TEST_MODE') === 'true';
}

/**
 * Returns the analysis timeout in seconds. Defaults to 25.
 * Kept below Apps Script's 30s card action limit.
 * @returns {number}
 */
function getTimeoutSeconds() {
  var val = parseInt(getProp('ANALYSIS_TIMEOUT_SECONDS'), 10);
  return (isNaN(val) || val < 5 || val > 28) ? 25 : val;
}

/**
 * Validates that all required properties exist for the given provider.
 * Throws a descriptive error listing exactly which properties are missing.
 * @param {string} provider
 */
function validateConfig(provider) {
  var allProps = PropertiesService.getScriptProperties().getProperties();
  var keys = PROVIDER_REQUIRED_KEYS[provider] || [];
  var missing = keys.filter(function(key) { return !allProps[key]; });

  if (missing.length > 0) {
    throw new Error(
      'Missing Script Properties for provider "' + provider + '":\n  ' +
      missing.join('\n  ') +
      '\n\nGo to: Apps Script Editor → Project Settings → Script Properties'
    );
  }
}

/**
 * Returns only the safe-to-display (non-secret) config values for the Settings card.
 * Never returns API keys or secrets.
 * @returns {Object}
 */
function getSafeDisplayConfig() {
  var provider = getProvider();
  var safeKeys = PROVIDER_DISPLAY_KEYS[provider] || [];
  var result = { AI_PROVIDER: provider };
  safeKeys.forEach(function(key) {
    result[key] = getProp(key) || '(not set)';
  });
  return result;
}
