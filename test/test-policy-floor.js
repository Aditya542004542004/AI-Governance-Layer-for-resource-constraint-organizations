/**
 * test/test-policy-floor.js
 * 
 * Unit tests proving that the Fixed Security Floor is immutable
 * and cannot be bypassed even when user policy configuration is set to "allow everything".
 */

const assert = require('assert');
const { runRegexChecks } = require('../detectors/regex.js');
const { calculateRiskScore } = require('../engine/risk-score.js');
const { evaluatePolicy } = require('../engine/policy.js');

function testFixedFloorBypassProtection() {
  console.log('\n--- Running Policy Fixed Security Floor Tests ---');

  // Permissive configuration trying to allow everything
  const ultraPermissiveConfig = {
    blockThreshold: 99,
    redactThreshold: 99,
    enableRegex: true,
    enableLLM: true
  };

  // Test Case 1: Valid Credit Card Number in Prompt
  const cardPrompt = 'Here is my valid card number 4532-0150-0000-0007, please complete order.';
  const ccRegexMatches = runRegexChecks(cardPrompt);
  const ccRiskAnalysis = calculateRiskScore({
    regexMatches: ccRegexMatches,
    llmResult: { sensitive: false, category: null, confidence: 0, skipped: true },
    userRole: 'default',
    destinationDomain: 'chatgpt.com'
  });

  const ccPolicyResult = evaluatePolicy({
    regexMatches: ccRegexMatches,
    llmResult: { sensitive: false, category: null, confidence: 0, skipped: true },
    riskAnalysis: ccRiskAnalysis,
    customPolicyConfig: ultraPermissiveConfig
  });

  assert.strictEqual(ccPolicyResult.action, 'block', 'Credit Card MUST be BLOCKED even with permissive config');
  assert.strictEqual(ccPolicyResult.fixedFloorTriggered, true, 'Must indicate Fixed Floor triggered');
  console.log('  ✓ Verified: Credit Card prompt blocked by Fixed Floor under permissive config.');

  // Test Case 2: API Secret Key in Prompt
  const keyPrompt = 'Use secret token sk-abc12345678901234567890123456789 in prompt';
  const keyRegexMatches = runRegexChecks(keyPrompt);
  const keyRiskAnalysis = calculateRiskScore({
    regexMatches: keyRegexMatches,
    llmResult: { sensitive: false, category: null, confidence: 0, skipped: true },
    userRole: 'default',
    destinationDomain: 'chatgpt.com'
  });

  const keyPolicyResult = evaluatePolicy({
    regexMatches: keyRegexMatches,
    llmResult: { sensitive: false, category: null, confidence: 0, skipped: true },
    riskAnalysis: keyRiskAnalysis,
    customPolicyConfig: ultraPermissiveConfig
  });

  assert.strictEqual(keyPolicyResult.action, 'block', 'API Key MUST be BLOCKED even with permissive config');
  assert.strictEqual(keyPolicyResult.fixedFloorTriggered, true, 'Must indicate Fixed Floor triggered');
  console.log('  ✓ Verified: API Key prompt blocked by Fixed Floor under permissive config.');

  // Test Case 3: Extreme Risk Score (>= 90)
  const highRiskAnalysis = { score: 95, breakdown: {} };
  const highRiskPolicyResult = evaluatePolicy({
    regexMatches: [],
    llmResult: { sensitive: true, category: 'medical', confidence: 0.95 },
    riskAnalysis: highRiskAnalysis,
    customPolicyConfig: ultraPermissiveConfig
  });

  assert.strictEqual(highRiskPolicyResult.action, 'block', 'Critical risk >= 90 MUST be BLOCKED even with permissive config');
  assert.strictEqual(highRiskPolicyResult.fixedFloorTriggered, true, 'Must indicate Fixed Floor triggered');
  console.log('  ✓ Verified: Critical risk score >= 90 blocked by Fixed Floor under permissive config.');

  console.log('--- All Fixed Security Floor Tests Passed Successfully! ---\n');
}

if (require.main === module) {
  testFixedFloorBypassProtection();
}

module.exports = { testFixedFloorBypassProtection };
