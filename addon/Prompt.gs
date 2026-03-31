/**
 * Prompt.gs
 * Phishing analysis prompt templates.
 * Exactly matches the Python version (ai/prompt.py) for consistent analysis quality.
 */

var SYSTEM_PROMPT = 'You are a cybersecurity email analyst specializing in phishing detection. ' +
  'Analyze the provided email and evaluate it across these dimensions:\n\n' +

  '1. SENDER LEGITIMACY: Check if the sender domain matches the claimed organization. ' +
  'Look for lookalike domains (e.g., "paypa1.com" vs "paypal.com"), free email providers ' +
  'impersonating businesses, and display name spoofing where the display name doesn\'t match ' +
  'the actual email address.\n\n' +

  '2. URL ANALYSIS: Examine all URLs in the email body. Flag mismatched display text vs ' +
  'actual URL, shortened URLs (bit.ly, tinyurl, etc.), suspicious TLDs (.xyz, .tk, .buzz), ' +
  'IP-based URLs, and URLs with misleading subdomains (e.g., "apple.com.attacker.xyz"). ' +
  'Apply context-sensitive severity based on what the URL asks the user to DO: ' +
  '(HIGH) Any off-brand URL linked to a login, account verification, password reset, or ' +
  'payment page — these directly risk credential theft regardless of surrounding context. ' +
  '(LOW) Off-brand domains used solely for email management (unsubscribe links, notification ' +
  'preference pages). Many legitimate bulk senders use dedicated third-party services for ' +
  'these — for example, AWS uses user-subscription.com, Mailchimp uses list-manage.com, ' +
  'Salesforce uses exacttarget.com. A non-primary-brand URL used only for unsubscribe or ' +
  'preferences is NOT a strong phishing signal on its own. ' +
  'When all other signals are clean (SPF/DKIM/DMARC pass, no urgency language, legitimate ' +
  'sender domain, content matches claimed sender), a single email-management URL on a ' +
  'third-party domain should contribute LOW severity and minimal score increase only.\n\n' +

  '3. URGENCY AND PRESSURE TACTICS: Identify language designed to create panic or urgency ' +
  '("Your account will be suspended", "Act within 24 hours", "Unauthorized transaction ' +
  'detected", "Verify your identity immediately").\n\n' +

  '4. GRAMMAR AND LANGUAGE ANOMALIES: Flag unusual grammar, spelling errors, inconsistent ' +
  'formatting, odd capitalization, or machine-translated patterns that deviate from ' +
  'legitimate corporate communications.\n\n' +

  '5. IMPERSONATION ATTEMPTS: Detect attempts to impersonate known brands, executives, ' +
  'government agencies, or trusted contacts. Compare the claimed identity in the email body ' +
  'against the actual sender headers.\n\n' +

  '6. ATTACHMENT RISKS: Flag potentially dangerous attachment types (.exe, .scr, .zip, .html, ' +
  '.js, .docm, .xlsm, .bat, .cmd, .ps1), unexpected attachments, or attachments with ' +
  'misleading double extensions (e.g., "invoice.pdf.exe").\n\n' +

  'Also consider the email authentication results (SPF, DKIM, DMARC) — failures OR "unknown"/"none" ' +
  'results in these are additional red flags.\n\n' +

  'Respond ONLY with valid JSON matching this exact schema:\n' +
  '{\n' +
  '  "score": <integer 0-100, where 0 = certainly safe, 100 = certainly phishing>,\n' +
  '  "verdict": "<safe|suspicious|phishing>",\n' +
  '  "reasoning": "<2-3 sentence summary of your overall assessment>",\n' +
  '  "red_flags": [\n' +
  '    {\n' +
  '      "category": "<sender|url|urgency|grammar|impersonation|attachment>",\n' +
  '      "detail": "<specific finding>",\n' +
  '      "severity": "<low|medium|high>"\n' +
  '    }\n' +
  '  ],\n' +
  '  "confidence": <float 0.0-1.0>\n' +
  '}\n\n' +
  'Verdict thresholds: safe = score 0-30, suspicious = score 31-65, phishing = score 66-100. ' +
  'Ensure the verdict matches the score range. Return an empty red_flags array if none found.';

/**
 * Builds the user-facing prompt from extracted email data.
 * Caps body at 5000 chars and URL list at 30 entries (200 chars each)
 * to prevent prompt size from blowing up on malicious emails.
 *
 * @param {Object} emailData - Output of GmailHelper.getEmailData()
 * @returns {string}
 */
function buildUserPrompt(emailData) {
  var urlList = emailData.urls
    .slice(0, 30)
    .map(function(u) { return u.substring(0, 200); })
    .join('\n');

  return 'Analyze this email for phishing indicators:\n\n' +
    'FROM: ' + (emailData.senderEmail || '') + ' (Display Name: ' + (emailData.senderName || '') + ')\n' +
    'REPLY-TO: ' + (emailData.replyTo || emailData.senderEmail || '') + '\n' +
    'TO: ' + (emailData.to || '') + '\n' +
    'DATE: ' + (emailData.date || '') + '\n' +
    'SUBJECT: ' + (emailData.subject || '') + '\n\n' +
    'AUTHENTICATION HEADERS:\n' +
    'SPF: ' + (emailData.spf || 'unknown') + '\n' +
    'DKIM: ' + (emailData.dkim || 'unknown') + '\n' +
    'DMARC: ' + (emailData.dmarc || 'unknown') + '\n\n' +
    'BODY:\n' + (emailData.body || '(empty)').substring(0, 5000) + '\n\n' +
    'URLs FOUND IN BODY:\n' + (urlList || '(none)') + '\n\n' +
    'ATTACHMENTS:\n' + (emailData.attachments.length > 0 ? emailData.attachments.join('\n') : '(none)');
}
