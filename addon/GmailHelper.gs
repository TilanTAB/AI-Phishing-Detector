/**
 * GmailHelper.gs
 * Extracts structured email data from a Gmail message ID,
 * and manages phishing-related Gmail labels.
 */

var LABEL_PHISHING   = 'PHISHING_DETECTED';
var LABEL_SUSPICIOUS = 'SUSPICIOUS';

// Label color definitions
var LABEL_COLORS = Object.freeze({
  PHISHING_DETECTED: { backgroundColor: '#cc3a21', textColor: '#ffffff' },
  SUSPICIOUS:        { backgroundColor: '#ff9900', textColor: '#000000' }
});

/**
 * Extracts all relevant phishing-analysis fields from a Gmail message.
 * Uses GmailApp.getMessageById() to get full message including raw headers.
 *
 * @param {string} messageId - Gmail message ID from the add-on event
 * @returns {{
 *   messageId: string,
 *   subject: string,
 *   senderName: string,
 *   senderEmail: string,
 *   replyTo: string,
 *   to: string,
 *   date: string,
 *   body: string,
 *   urls: string[],
 *   attachments: string[],
 *   spf: string,
 *   dkim: string,
 *   dmarc: string
 * }}
 */
function getEmailData(messageId) {
  var message = GmailApp.getMessageById(messageId);
  if (!message) {
    throw new Error('Message not found: ' + messageId);
  }

  // Parse sender
  var from = parseEmailAddress(message.getFrom());

  // Get reply-to (GmailApp doesn't expose it directly; fall back to sender)
  var replyTo = '';
  try {
    var rawContent = message.getRawContent();
    var replyToMatch = rawContent.match(/^Reply-To:\s*(.+)$/mi);
    if (replyToMatch) {
      var rt = parseEmailAddress(replyToMatch[1].trim());
      replyTo = rt.email || rt.name;
    }
    // Extract authentication headers from raw content
    var authHeader = '';
    var authMatch = rawContent.match(/^Authentication-Results:[\s\S]*?(?=\n\S|\n\n)/mi);
    if (authMatch) authHeader = authMatch[0];

    var spf  = extractAuthResult(authHeader, 'spf');
    var dkim = extractAuthResult(authHeader, 'dkim');
    var dmarc = extractAuthResult(authHeader, 'dmarc');
  } catch (e) {
    // getRawContent() may fail under some scope configurations — degrade gracefully
    console.warn('Could not read raw content for message ' + messageId + ': ' + e.message);
    var spf = 'unknown', dkim = 'unknown', dmarc = 'unknown';
  }

  // Get body — prefer plain text, fall back to HTML-to-text
  var body = message.getPlainBody();
  if (!body || body.trim().length === 0) {
    body = htmlToText(message.getBody());
  }

  // Extract URLs from body
  var urls = extractUrls(body);

  // Extract attachment names
  var attachments = [];
  try {
    message.getAttachments().forEach(function(att) {
      attachments.push(att.getName());
    });
  } catch (e) {
    console.warn('Could not read attachments: ' + e.message);
  }

  console.log('getEmailData: id=' + messageId + ' from=' + from.email + ' urls=' + urls.length);

  return {
    messageId:   messageId,
    subject:     message.getSubject() || '(no subject)',
    senderName:  from.name,
    senderEmail: from.email,
    replyTo:     replyTo,
    to:          message.getTo() || '',
    date:        message.getDate() ? message.getDate().toUTCString() : '',
    body:        body || '',
    urls:        urls,
    attachments: attachments,
    spf:         spf  || 'unknown',
    dkim:        dkim || 'unknown',
    dmarc:       dmarc || 'unknown'
  };
}

/**
 * Applies the appropriate Gmail label based on the verdict.
 * Creates labels if they don't exist yet.
 *
 * @param {string} messageId
 * @param {string} verdict - 'phishing' | 'suspicious'
 */
function applyLabel(messageId, verdict) {
  var labelName = (verdict === 'phishing') ? LABEL_PHISHING : LABEL_SUSPICIOUS;
  var label = ensureLabel(labelName);
  var message = GmailApp.getMessageById(messageId);
  if (message) {
    message.getThread().addLabel(label);
    console.log('Applied label "' + labelName + '" to message ' + messageId);
  }
}

/**
 * Ensures a Gmail label exists with the correct color, creating it if needed.
 * Returns the GmailLabel object.
 *
 * @param {string} labelName
 * @returns {GmailLabel}
 */
function ensureLabel(labelName) {
  var label = GmailApp.getUserLabelByName(labelName);
  if (!label) {
    label = GmailApp.createLabel(labelName);
    console.log('Created Gmail label: ' + labelName);
    // Note: GmailApp.createLabel() doesn't support color assignment.
    // Label colors require the Gmail REST API (gmail.labels.patch).
    // Color is set as a nice-to-have via Gmail REST in Code.gs startup,
    // but the add-on functions correctly without it.
  }
  return label;
}

/**
 * Returns true if the message already has the phishing or suspicious label applied.
 * Used by Card.gs to decide whether to show the "Apply Label" button.
 *
 * @param {string} messageId
 * @returns {boolean}
 */
function isAlreadyLabeled(messageId) {
  try {
    var message = GmailApp.getMessageById(messageId);
    var thread  = message.getThread();
    var labels  = thread.getLabels();
    for (var i = 0; i < labels.length; i++) {
      var name = labels[i].getName();
      if (name === LABEL_PHISHING || name === LABEL_SUSPICIOUS) return true;
    }
  } catch (e) {
    console.warn('isAlreadyLabeled error: ' + e.message);
  }
  return false;
}
