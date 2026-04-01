/**
 * Card.gs
 * Builds all Gmail Add-on sidebar cards.
 * Uses Google Workspace Add-on Card Service API.
 *
 * Cards:
 *   buildHomeCard(emailData)       — shown when email is opened
 *   buildResultsCard(result, msgId) — shown after analysis
 *   buildErrorCard(errorMsg)        — shown on unrecoverable error
 *   buildSettingsCard()             — shown from universal action menu
 */

// Verdict display config
var VERDICT_CONFIG = Object.freeze({
  safe: {
    icon:  '✅',
    label: 'SAFE',
    color: '#2da44e'
  },
  suspicious: {
    icon:  '⚠️',
    label: 'SUSPICIOUS',
    color: '#ff9900'
  },
  phishing: {
    icon:  '🚨',
    label: 'PHISHING DETECTED',
    color: '#cc3a21'
  }
});

var SEVERITY_ICONS = Object.freeze({
  high:   '🔴',
  medium: '🟡',
  low:    '🟢'
});

// ---------------------------------------------------------------------------
// Home Card
// ---------------------------------------------------------------------------

/**
 * Builds the home card shown when the user opens an email.
 * Shows email summary and the "Analyze for Phishing" button.
 *
 * @param {Object} emailData - From GmailHelper.getEmailData()
 * @param {string} messageId
 * @returns {Card}
 */
function buildHomeCard(emailData, messageId) {
  var provider   = _safeGetProvider();
  var alreadyDone = isAlreadyLabeled(messageId);

  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('🔍 Phishing Checker')
      .setSubtitle('Provider: ' + provider));

  // Email summary section
  var summarySection = CardService.newCardSection()
    .setHeader('Email Summary');

  summarySection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('From')
      .setText('<b>' + _escape(emailData.senderName || emailData.senderEmail) + '</b> &lt;' + _escape(emailData.senderEmail) + '&gt;')
  );

  summarySection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Subject')
      .setText(_escape(emailData.subject).substring(0, 120))
  );

  summarySection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Authentication')
      .setText('SPF: ' + emailData.spf + ' | DKIM: ' + emailData.dkim + ' | DMARC: ' + emailData.dmarc)
  );

  if (emailData.urls.length > 0) {
    summarySection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('URLs Found')
        .setText(emailData.urls.length + ' URL(s) detected')
    );
  }

  if (emailData.attachments.length > 0) {
    summarySection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Attachments')
        .setText(emailData.attachments.join(', ').substring(0, 100))
    );
  }

  card.addSection(summarySection);

  // Action section
  var actionSection = CardService.newCardSection();

  if (alreadyDone) {
    actionSection.addWidget(
      CardService.newTextParagraph()
        .setText('<font color="#888888"><i>This email has already been labeled.</i></font>')
    );
  }

  actionSection.addWidget(
    CardService.newTextButton()
      .setText(alreadyDone ? '🔍 Re-Analyze' : '🔍 Analyze for Phishing')
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName('analyzeEmailAction')
          .setParameters({ messageId: messageId })
      )
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
  );

  card.addSection(actionSection);

  return card.build();
}

// ---------------------------------------------------------------------------
// Results Card
// ---------------------------------------------------------------------------

/**
 * Builds the results card after AI analysis completes.
 *
 * @param {Object} result   - PhishingResult from AIProvider.analyzeWithAI()
 * @param {string} messageId
 * @returns {Card}
 */
function buildResultsCard(result, messageId) {
  var cfg = VERDICT_CONFIG[result.verdict] || VERDICT_CONFIG.suspicious;

  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(cfg.icon + ' ' + cfg.label)
      .setSubtitle('Score: ' + result.score + '/100  |  Confidence: ' + Math.round(result.confidence * 100) + '%'));

  // Fallback warning
  if (result.isFallback) {
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText('<font color="#cc3a21"><b>⚠ Analysis Failed</b></font><br>' +
              '<font color="#555">' + _escape(result.error || 'Unknown error') + '</font><br><br>' +
              'Email labeled as SUSPICIOUS for manual review.')
        )
    );
  }

  // Assessment section
  var assessSection = CardService.newCardSection().setHeader('Assessment');
  assessSection.addWidget(
    CardService.newTextParagraph()
      .setText(_escape(result.reasoning))
  );
  card.addSection(assessSection);

  // Red flags section (only if any found)
  if (result.redFlags && result.redFlags.length > 0) {
    var flagSection = CardService.newCardSection()
      .setHeader('Red Flags (' + result.redFlags.length + ')');

    result.redFlags.forEach(function(flag) {
      var icon  = SEVERITY_ICONS[flag.severity] || '⚪';
      var label = flag.category.toUpperCase();
      flagSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(icon + ' ' + label + ' [' + flag.severity.toUpperCase() + ']')
          .setText(_escape(flag.detail))
          .setWrapText(true)
      );
    });

    card.addSection(flagSection);
  }

  // Action section — label button + back button
  var actionSection = CardService.newCardSection();

  if (result.verdict !== 'safe') {
    var labelText = result.verdict === 'phishing'
      ? '🏷 Apply PHISHING Label'
      : '🏷 Apply SUSPICIOUS Label';

    actionSection.addWidget(
      CardService.newTextButton()
        .setText(labelText)
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName('applyLabelAction')
            .setParameters({ messageId: messageId, verdict: result.verdict })
        )
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    );
  } else {
    actionSection.addWidget(
      CardService.newTextParagraph()
        .setText('<font color="#2da44e">✅ This email appears safe. No action needed.</font>')
    );
  }

  actionSection.addWidget(
    CardService.newTextButton()
      .setText('← Back')
      .setOnClickAction(CardService.newAction().setFunctionName('onGmailMessage'))
  );

  card.addSection(actionSection);
  return card.build();
}

// ---------------------------------------------------------------------------
// Error Card
// ---------------------------------------------------------------------------

/**
 * Builds an error card for unrecoverable failures (e.g. message not found).
 *
 * @param {string} errorMessage
 * @param {string} [messageId]
 * @returns {Card}
 */
function buildAccessDeniedCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('🔒 Access Restricted')
      .setSubtitle('Phishing Checker'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText(
              'Your account (<b>' + Session.getActiveUser().getEmail() + '</b>) ' +
              'is not authorised to use this add-on.\n\n' +
              'Contact the owner to request access.'
            )
        )
    )
    .build();
}

function buildErrorCard(errorMessage, messageId) {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('❌ Error')
      .setSubtitle('Something went wrong'));

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph()
      .setText('<font color="#cc3a21">' + _escape(errorMessage) + '</font>')
  );

  if (messageId) {
    section.addWidget(
      CardService.newTextButton()
        .setText('🔄 Retry')
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName('onGmailMessage')
        )
    );
  }

  section.addWidget(
    CardService.newTextButton()
      .setText('⚙ Open Settings')
      .setOnClickAction(CardService.newAction().setFunctionName('buildSettingsCard'))
  );

  card.addSection(section);
  return card.build();
}

// ---------------------------------------------------------------------------
// Settings Card
// ---------------------------------------------------------------------------

/**
 * Builds the settings card shown from the universal action menu.
 * Displays current (non-secret) config values and setup instructions.
 *
 * @returns {Card}
 */
function buildSettingsCard() {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('⚙ Settings')
      .setSubtitle('Phishing Checker Configuration'));

  // Current config section (safe values only — no secrets)
  var configSection = CardService.newCardSection().setHeader('Current Configuration');
  var safeConfig = getSafeDisplayConfig();
  Object.keys(safeConfig).forEach(function(key) {
    configSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel(key)
        .setText(String(safeConfig[key]))
    );
  });
  card.addSection(configSection);

  // How to configure
  var helpSection = CardService.newCardSection().setHeader('How to Configure');
  helpSection.addWidget(
    CardService.newTextParagraph()
      .setText(
        '1. Open Apps Script Editor (Extensions → Apps Script)\n' +
        '2. Click Project Settings (⚙ icon)\n' +
        '3. Scroll to <b>Script Properties</b>\n' +
        '4. Set <b>AI_PROVIDER</b> to one of:\n' +
        '   • gemini\n' +
        '   • azure_openai\n' +
        '   • bedrock_claude\n' +
        '   • vertex_ai\n' +
        '5. Set the required credentials for your chosen provider\n' +
        '6. Set <b>TEST_MODE=true</b> to test the UI without real API calls'
      )
  );
  card.addSection(helpSection);

  return card.build();
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Safely gets the provider name for display, returning 'unknown' on error.
 * @returns {string}
 */
function _safeGetProvider() {
  try { return getProvider(); } catch (e) { return 'not configured'; }
}

/**
 * Escapes HTML special characters to prevent injection in card text.
 * @param {string} text
 * @returns {string}
 */
function _escape(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
