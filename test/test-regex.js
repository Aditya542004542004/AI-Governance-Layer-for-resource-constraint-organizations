/**
 * test/test-regex.js
 * 
 * Unit tests for structured regex detection patterns and Luhn algorithm validation.
 */

const assert = require('assert');
const { runRegexChecks, luhnCheck } = require('../detectors/regex.js');
const { calculateRiskScore } = require('../engine/risk-score.js');
const { evaluatePolicy } = require('../engine/policy.js');

function testLuhnAlgorithm() {
  console.log('Testing Luhn Algorithm verification...');
  
  // Valid credit card numbers (Luhn checksum passes)
  assert.strictEqual(luhnCheck('4532015000000007'), true, 'Valid Visa should pass Luhn check');
  assert.strictEqual(luhnCheck('4111111111111111'), true, 'Valid Visa 16-digit should pass Luhn check');

  // Invalid credit card numbers (Luhn checksum fails)
  assert.strictEqual(luhnCheck('4532015000000008'), false, 'Invalid checksum card should fail Luhn check');
  assert.strictEqual(luhnCheck('1234567890123456'), false, 'Arbitrary digits should fail Luhn check');

  console.log('  ✓ Luhn Algorithm tests passed.');
}

function testRegexCategories() {
  console.log('Testing Regex Category pattern matching...');

  // 1. Credit Cards
  const ccResult = runRegexChecks('Please process refund to 4532-0150-0000-0007 card.');
  assert.strictEqual(ccResult.length, 1, 'Should detect valid credit card pattern');
  assert.strictEqual(ccResult[0].category, 'credit_card');

  // Invalid CC should NOT be matched
  const invalidCcResult = runRegexChecks('Card number 1234-5678-9012-3456 fails Luhn check');
  const ccMatches = invalidCcResult.filter(m => m.category === 'credit_card');
  assert.strictEqual(ccMatches.length, 0, 'Invalid Luhn card must not be flagged as credit_card');

  // 2. Email Addresses
  const emailResult = runRegexChecks('Contact john.doe@example.com for assistance.');
  assert.strictEqual(emailResult.length, 1, 'Should detect email pattern');
  assert.strictEqual(emailResult[0].category, 'email');

  // 3. API Keys (Structured & Vendor Prefixes)
  const apiKeyResult1 = runRegexChecks('Use token sk-abc12345678901234567890123456789 for auth.');
  assert.strictEqual(apiKeyResult1.some(m => m.category === 'api_key'), true, 'Should detect sk- OpenAI API key');

  const apiKeyResult2 = runRegexChecks('AWS Access Key: AKIAIOSFODNN7EXAMPLE.');
  assert.strictEqual(apiKeyResult2.some(m => m.category === 'api_key'), true, 'Should detect AWS AKIA key');

  const structuredKeyResult = runRegexChecks("api_key = 'sk-proj-123456789012345678901234'");
  assert.strictEqual(structuredKeyResult.some(m => m.category === 'api_key'), true, 'Should detect structured api_key assignment');

  // 4. National Identity (SSN)
  const ssnResult = runRegexChecks('Employee SSN is 123-45-6789.');
  assert.strictEqual(ssnResult.some(m => m.category === 'national_id'), true, 'Should detect SSN pattern');

  // 5. Passwords / Passcodes (Explicit Assignment)
  const passwordResult = runRegexChecks('my pin is 2901');
  assert.strictEqual(passwordResult.some(m => m.category === 'pin_passcode'), true, 'Should detect explicit PIN assignment pattern');

  console.log('  ✓ Regex Category pattern tests passed.');
}

function testSoftHeuristicCredentialDetection() {
  console.log('Testing Continuous Risk Scoring via Soft Heuristic Credential Detection...');

  // 1. Conversational prompt with unverified token
  const conversationalText = 'this is my api key duiwhdigdbqu8238bhd';
  const matches = runRegexChecks(conversationalText);

  assert.strictEqual(matches.some(m => m.category === 'potential_credential'), true, 'Conversational key leak must trigger potential_credential category');
  assert.strictEqual(matches.some(m => m.category === 'api_key'), false, 'Conversational key leak MUST NOT trigger rigid api_key Fixed Floor rule');

  const riskAnalysisTrusted = calculateRiskScore({ regexMatches: matches, destinationDomain: 'chatgpt.com' });
  assert.strictEqual(riskAnalysisTrusted.score, 30, 'Soft heuristic credential detection on trusted domain must produce base score of 30');

  const riskAnalysisUnknown = calculateRiskScore({ regexMatches: matches, destinationDomain: 'unknown' });
  assert.strictEqual(riskAnalysisUnknown.score, 38, 'Soft heuristic credential detection on unknown domain produces 38 (30 * 1.25 multiplier)');
  assert.strictEqual(riskAnalysisUnknown.score < 45, true, 'Score must remain strictly below redactThreshold of 45');

  const policyResult = evaluatePolicy({ regexMatches: matches, riskAnalysis: riskAnalysisTrusted });
  assert.strictEqual(policyResult.action, 'allow', 'Intermediate score MUST result in allow action (below 45 redact threshold)');
  assert.strictEqual(policyResult.fixedFloorTriggered, false, 'Soft heuristic detection MUST NOT trigger Fixed Security Floor');

  // 2. Academic paper snippet MUST NOT trigger potential_credential
  const academicText = 'The RESTful API is implemented using Flask. Research on one-time PIN generation in 2022.';
  const academicMatches = runRegexChecks(academicText);
  assert.strictEqual(academicMatches.length, 0, 'Academic text with Flask and 2022 MUST produce 0 regex matches');

  console.log('  ✓ Continuous Risk Scoring & Soft Heuristic Credential Detection tests passed.');
}

function testAcademicPaperFalsePositiveRegression() {
  console.log('Testing Academic & Technical Document False-Positive Regression...');

  const academicText = `
    CIFER: Secure File Storage and Sharing System Using AES-256 Encryption and OTP-Based Authentication.
    The RESTful API is implemented using Flask. The encryption key is imported from a secured environment variable.
    A 32-byte token is attached to the encrypted payload. According to research on one-time PIN generation in 2022,
    the PIN entry process is masked using several mathematical operations.
  `;

  const matches = runRegexChecks(academicText);
  const falsePositives = matches.filter(m => m.category === 'api_key' || m.category === 'pin_passcode');

  assert.strictEqual(
    falsePositives.length,
    0,
    `Academic paper snippet must produce ZERO false positive detections for api_key or pin_passcode (Found: ${falsePositives.map(m => `${m.category}: "${m.match}"`).join(', ')})`
  );

  console.log('  ✓ Academic & Technical Document False-Positive Regression test passed (0 false positives).');
}

function runAllRegexTests() {
  console.log('\n--- Running Regex Detector Unit Tests ---');
  testLuhnAlgorithm();
  testRegexCategories();
  testSoftHeuristicCredentialDetection();
  testAcademicPaperFalsePositiveRegression();
  console.log('--- All Regex Detector Tests Passed Successfully! ---\n');
}

if (require.main === module) {
  runAllRegexTests();
}

module.exports = { runAllRegexTests };
