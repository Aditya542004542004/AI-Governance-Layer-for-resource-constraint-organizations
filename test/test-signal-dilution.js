/**
 * test/test-signal-dilution.js
 * 
 * Regression unit test verifying that a Fixed Floor pattern (e.g., API key, Credit Card, PIN)
 * embedded mid-paragraph produces the EXACT SAME Fixed Floor BLOCK decision as the pattern alone.
 * Proves that regex signal is NEVER diluted or averaged down by surrounding text or LLM reads.
 */

const assert = require('assert');
const { runRegexChecks } = require('../detectors/regex.js');
const { calculateRiskScore } = require('../engine/risk-score.js');
const { evaluatePolicy } = require('../engine/policy.js');

function testEmbeddedSecretSignalPreservation() {
  console.log('\n--- Running Embedded Secret Signal-Preservation Regression Test ---');

  const rawSecret = 'sk-abc12345678901234567890123456789';
  const standalonePrompt = rawSecret;
  const embeddedPrompt = `Here is our general Q3 team status update. We have completed 80% of sprint tasks and all deployment benchmarks look great. For staging testing, please use master secret ${rawSecret} to authenticate with the internal gateway. Let me know if you run into any permission issues during integration.`;

  // 1. Standalone Secret Evaluation
  const standaloneMatches = runRegexChecks(standalonePrompt);
  const standaloneRisk = calculateRiskScore({
    regexMatches: standaloneMatches,
    llmResult: { sensitive: true, category: 'proprietary', confidence: 0.95 },
    userRole: 'engineering',
    destinationDomain: 'chatgpt.com'
  });
  const standalonePolicy = evaluatePolicy({
    regexMatches: standaloneMatches,
    llmResult: { sensitive: true, category: 'proprietary', confidence: 0.95 },
    riskAnalysis: standaloneRisk,
    customPolicyConfig: { blockThreshold: 75, redactThreshold: 45 }
  });

  // 2. Embedded Secret Evaluation (surrounded by 300+ characters of benign text)
  const embeddedMatches = runRegexChecks(embeddedPrompt);
  const embeddedRisk = calculateRiskScore({
    regexMatches: embeddedMatches,
    llmResult: { sensitive: false, category: null, confidence: 0.2 }, // Low LLM confidence read of paragraph
    userRole: 'engineering',
    destinationDomain: 'chatgpt.com'
  });
  const embeddedPolicy = evaluatePolicy({
    regexMatches: embeddedMatches,
    llmResult: { sensitive: false, category: null, confidence: 0.2 },
    riskAnalysis: embeddedRisk,
    customPolicyConfig: { blockThreshold: 75, redactThreshold: 45 }
  });

  // VERIFICATION: Embedded prompt MUST produce the exact same Fixed Floor BLOCK decision as standalone!
  assert.strictEqual(standalonePolicy.action, 'block', 'Standalone secret MUST be BLOCKED');
  assert.strictEqual(embeddedPolicy.action, 'block', 'Embedded secret MUST ALSO be BLOCKED');
  assert.strictEqual(embeddedPolicy.fixedFloorTriggered, true, 'Embedded secret MUST trigger Fixed Floor');
  assert.strictEqual(embeddedRisk.score >= 95, true, 'Embedded secret risk score MUST be >= 95 (NOT diluted to ~62%)');

  console.log('  ✓ Standalone API Key Action:', standalonePolicy.action, '| Score:', standaloneRisk.score);
  console.log('  ✓ Embedded API Key Action:  ', embeddedPolicy.action,  '| Score:', embeddedRisk.score);
  console.log('  ✓ Verified: Embedded secret produced identical Fixed Floor BLOCK decision without score dilution.');

  console.log('--- Embedded Secret Signal-Preservation Test Passed Successfully! ---\n');
}

if (require.main === module) {
  testEmbeddedSecretSignalPreservation();
}

module.exports = { testEmbeddedSecretSignalPreservation };
