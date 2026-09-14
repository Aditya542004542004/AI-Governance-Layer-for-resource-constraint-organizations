/**
 * test/test-regex.js
 * 
 * Unit tests for structured regex detection patterns and Luhn algorithm validation.
 */

const assert = require('assert');
const { runRegexChecks, luhnCheck } = require('../detectors/regex.js');

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

  // 3. API Keys
  const apiKeyResult1 = runRegexChecks('Use token sk-abc12345678901234567890123456789 for auth.');
  assert.strictEqual(apiKeyResult1.some(m => m.category === 'api_key'), true, 'Should detect sk- OpenAI API key');

  const apiKeyResult2 = runRegexChecks('AWS Access Key: AKIAIOSFODNN7EXAMPLE.');
  assert.strictEqual(apiKeyResult2.some(m => m.category === 'api_key'), true, 'Should detect AWS AKIA key');

  // 4. National Identity (SSN)
  const ssnResult = runRegexChecks('Employee SSN is 123-45-6789.');
  assert.strictEqual(ssnResult.some(m => m.category === 'national_id'), true, 'Should detect SSN pattern');

  // 6. Passwords / Passcodes
  const passwordResult = runRegexChecks('this is my laptop password 2901901');
  assert.strictEqual(passwordResult.some(m => m.category === 'pin_passcode'), true, 'Should detect laptop password pattern');

  console.log('  ✓ Regex Category pattern tests passed.');
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
  testAcademicPaperFalsePositiveRegression();
  console.log('--- All Regex Detector Tests Passed Successfully! ---\n');
}

if (require.main === module) {
  runAllRegexTests();
}

module.exports = { runAllRegexTests };
