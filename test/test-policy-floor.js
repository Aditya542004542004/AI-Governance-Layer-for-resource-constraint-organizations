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

  // Test Case 4: Database Connection URI in Prompt
  const dbUriPrompt = 'Connect to database at postgres://admin:Password123@localhost:5432/production_db';
  const dbRegexMatches = runRegexChecks(dbUriPrompt);
  assert.strictEqual(dbRegexMatches.some(m => m.category === 'database_url'), true, 'Should detect database_url pattern');
  const dbRiskAnalysis = calculateRiskScore({ regexMatches: dbRegexMatches, destinationDomain: 'chatgpt.com' });
  const dbPolicyResult = evaluatePolicy({ regexMatches: dbRegexMatches, riskAnalysis: dbRiskAnalysis, customPolicyConfig: ultraPermissiveConfig });

  assert.strictEqual(dbPolicyResult.action, 'block', 'Database Connection URI MUST be BLOCKED by Fixed Floor');
  assert.strictEqual(dbPolicyResult.fixedFloorTriggered, true, 'Must indicate Fixed Floor triggered for database_url');
  console.log('  ✓ Verified: Database Connection URI blocked by Fixed Floor under permissive config.');

  // Test Case 5: Google / Gemini OAuth Token (ya29... & AQ...)
  const ya29Token = 'ya29.a0ARW5m75_X9Y8Z7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2H1G0F9E8D7C6B5A4';
  const geminiTokenMatches = runRegexChecks(`Auth header: Bearer ${ya29Token}`);
  assert.strictEqual(geminiTokenMatches.some(m => m.category === 'api_key'), true, 'Should detect ya29. Google OAuth token as api_key');
  const geminiTokenPolicy = evaluatePolicy({ regexMatches: geminiTokenMatches, riskAnalysis: calculateRiskScore({ regexMatches: geminiTokenMatches }) });
  assert.strictEqual(geminiTokenPolicy.action, 'block', 'Google OAuth token MUST be BLOCKED by Fixed Floor');
  console.log('  ✓ Verified: Google/Gemini OAuth token (ya29...) blocked by Fixed Floor.');

  // Test Case 6: Email Redaction Verification (student@vit.edu)
  const emailPrompt = 'Contact student at student@vit.edu for details.';
  const emailMatches = runRegexChecks(emailPrompt);
  assert.strictEqual(emailMatches.some(m => m.category === 'email'), true, 'Should detect email pattern');
  const emailPolicy = evaluatePolicy({ promptText: emailPrompt, regexMatches: emailMatches, riskAnalysis: calculateRiskScore({ regexMatches: emailMatches }) });
  assert.strictEqual(emailPolicy.action, 'redact', 'Email address MUST produce redact action');
  assert.strictEqual(emailPolicy.redactedText.includes('[REDACTED_EMAIL]'), true, 'Email address MUST be replaced with [REDACTED_EMAIL]');
  console.log('  ✓ Verified: Email address student@vit.edu produced mandatory [REDACTED_EMAIL] redaction.');

  console.log('--- All Fixed Security Floor Tests Passed Successfully! ---\n');
}

if (require.main === module) {
  testFixedFloorBypassProtection();
}

module.exports = { testFixedFloorBypassProtection };
