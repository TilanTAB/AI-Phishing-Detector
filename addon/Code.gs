/**
 * Code.gs
 * Entry points for the Gmail Add-on.
 *
 * Functions referenced in appsscript.json or triggered by card actions:
 *   onGmailMessage(e)      — contextual trigger when email is opened
 *   buildAddOn(e)          — homepage trigger (no email context)
 *   analyzeEmailAction(e)  — card action: run AI analysis
 *   applyLabelAction(e)    — card action: apply Gmail label
 *   buildSettingsCard(e)   — universal action: show settings
 */

/**
 * Gmail contextual trigger — fires when user opens an email.
 * Builds and returns the home card showing email summary + Analyze button.
 *
 * @param {Object} e - Add-on event object
 * @returns {Card|Card[]}
 */
function onGmailMessage(e) {
  try {
    var messageId = e && e.gmail && e.gmail.messageId;
    if (!messageId) {
      return buildErrorCard('No message context found. Please open an email first.');
    }

    var emailData = getEmailData(messageId);
    return buildHomeCard(emailData, messageId);

  } catch (err) {
    console.error('onGmailMessage error: ' + err.message);
    return buildErrorCard('Failed to load email: ' + err.message);
  }
}

/**
 * Homepage trigger — fires when user opens the add-on outside of an email.
 * Shows a welcome card with instructions.
 *
 * @param {Object} e - Add-on event object
 * @returns {Card}
 */
function buildAddOn(e) {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('🔍 Phishing Checker')
      .setSubtitle('AI-powered email security'));

  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newTextParagraph()
          .setText(
            'Open any email in Gmail to analyze it for phishing indicators.\n\n' +
            'The add-on will check:\n' +
            '• Sender legitimacy & domain spoofing\n' +
            '• Suspicious URLs & shortened links\n' +
            '• Urgency & pressure tactics\n' +
            '• Grammar anomalies\n' +
            '• Impersonation attempts\n' +
            '• Dangerous attachment types\n\n' +
            'Results are shown instantly in this sidebar.'
          )
      )
      .addWidget(
        CardService.newTextButton()
          .setText('⚙ Configure Provider')
          .setOnClickAction(CardService.newAction().setFunctionName('buildSettingsCard'))
      )
  );

  return card.build();
}

/**
 * Card action — triggered when user clicks "Analyze for Phishing".
 * Fetches full email data, runs AI analysis, and pushes the results card.
 *
 * NOTE: This must complete within ~30 seconds (Apps Script card action limit).
 * AI analysis is one-shot with no retries to stay within this budget.
 *
 * @param {Object} e - Action event with e.parameters.messageId
 * @returns {ActionResponse}
 */
function analyzeEmailAction(e) {
  var messageId = e.parameters && e.parameters.messageId;

  if (!messageId) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Error: No message ID found.'))
      .build();
  }

  try {
    // Fetch email data
    var emailData = getEmailData(messageId);

    // Run AI analysis (one-shot, no retry — must finish within timeout)
    var result = analyzeWithAI(emailData);

    console.log(
      'Analysis complete | id=' + messageId +
      ' | verdict=' + result.verdict +
      ' | score=' + result.score +
      ' | provider=' + (isTestMode() ? 'TEST_MODE' : _safeGetProviderName())
    );

    // Push results card onto the navigation stack
    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().pushCard(buildResultsCard(result, messageId))
      )
      .build();

  } catch (err) {
    console.error('analyzeEmailAction error for ' + messageId + ': ' + err.message);
    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().pushCard(buildErrorCard('Analysis failed: ' + err.message, messageId))
      )
      .build();
  }
}

/**
 * Card action — triggered when user clicks "Apply Label".
 * Applies the PHISHING_DETECTED or SUSPICIOUS label to the email thread.
 *
 * @param {Object} e - Action event with e.parameters.messageId and e.parameters.verdict
 * @returns {ActionResponse}
 */
function applyLabelAction(e) {
  var messageId = e.parameters && e.parameters.messageId;
  var verdict   = e.parameters && e.parameters.verdict;

  if (!messageId || !verdict) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Error: Missing parameters.'))
      .build();
  }

  try {
    applyLabel(messageId, verdict);

    var labelName = verdict === 'phishing' ? 'PHISHING_DETECTED' : 'SUSPICIOUS';
    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification().setText('✅ Label "' + labelName + '" applied successfully.')
      )
      .build();

  } catch (err) {
    console.error('applyLabelAction error: ' + err.message);
    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification().setText('Failed to apply label: ' + err.message)
      )
      .build();
  }
}

/**
 * Helper to safely get provider name for logging without throwing.
 * @returns {string}
 */
function _safeGetProviderName() {
  try { return getProvider(); } catch (e) { return 'unknown'; }
}
