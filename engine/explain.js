/**
 * engine/explain.js
 * 
 * Generates transparent, human-readable plain-language explanations for prompt governance decisions.
 * Ensures employees understand WHY an action was taken (allow / redact / block),
 * what sensitive content was detected, and what next step they can take.
 */

/**
 * Converts a policy decision result into a structured user-facing explanation message.
 * 
 * @param {Object} policyResult - The decision object returned from evaluatePolicy()
 * @returns {string} Plain-language explanation string
 */
function generateExplanation(policyResult) {
  if (!policyResult) {
    return 'No policy decision available.';
  }

  const { action, riskScore, reasons = [], fixedFloorTriggered, fileName } = policyResult;
  const subjectText = fileName ? `File '${fileName}'` : 'This message';

  if (action === 'allow' && reasons.length === 0) {
    return `${subjectText} was allowed (risk score ${riskScore}/100): no sensitive patterns or policy risks were detected. You may proceed.`;
  }

  // Summarize main reasons into readable clauses
  const reasonDescriptions = reasons.map(r => r.description);
  let primaryReasonText = '';

  if (reasonDescriptions.length === 1) {
    primaryReasonText = reasonDescriptions[0];
  } else if (reasonDescriptions.length > 1) {
    primaryReasonText = `${reasonDescriptions[0]} (and ${reasonDescriptions.length - 1} other item${reasonDescriptions.length > 2 ? 's' : ''})`;
  } else {
    primaryReasonText = `exceed risk threshold limits (score ${riskScore}/100)`;
  }

  // Action-specific user next steps
  let nextStepText = '';
  if (action === 'block') {
    if (fixedFloorTriggered) {
      nextStepText = fileName 
        ? 'remove high-risk content or unscannable formats before attaching. Non-negotiable security floor policy enforced.'
        : 'remove all high-risk items (such as credit cards or API keys) before resending. Non-negotiable security floor policy enforced.';
    } else {
      nextStepText = 'review and remove sensitive details or consult your security team for policy exception approval.';
    }
  } else if (action === 'redact') {
    nextStepText = fileName
      ? 'review flagged sections before attaching, or replace sensitive data with sanitized placeholders.'
      : 'click "Remove Flagged Data" to automatically strip sensitive values, or edit your prompt before sending.';
  } else {
    nextStepText = 'proceed cautiously with your submission.';
  }

  return `${subjectText} was ${action.toUpperCase()} (risk score ${riskScore}/100): it appears to ${primaryReasonText}. You can ${nextStepText}`;
}

// Support both ES Modules and script environment exports
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { generateExplanation };
} else if (typeof globalThis !== 'undefined') {
  globalThis.generateExplanation = generateExplanation;
}
