/**
 * test/test-file-governance.js
 * 
 * Unit tests for File Upload Governance:
 * - Multi-format client-side text extraction (.txt, .docx, .xlsx, .pdf)
 * - Multi-chunk evaluation sensitivity preservation (verifies single-chunk sensitive sentence flags whole file without score dilution)
 * - Fail-Closed guardrail protection for images & unscannable binary formats.
 */

const assert = require('assert');
const { extractTextFromFile, chunkText } = require('../detectors/file-extract.js');
const { runRegexChecks } = require('../detectors/regex.js');
const { calculateRiskScore } = require('../engine/risk-score.js');
const { evaluatePolicy } = require('../engine/policy.js');

async function testFileTextExtraction() {
  console.log('Testing File Text Extraction across formats...');

  // 1. Plain Text
  const txtResult = await extractTextFromFile({
    name: 'employee_records.txt',
    buffer: Buffer.from('Employee John Doe SSN: 123-45-6789. Contact email: john.doe@example.com.', 'utf-8'),
    type: 'text/plain'
  });
  assert.strictEqual(txtResult.unscannable, false, 'TXT file should be scannable');
  assert.strictEqual(txtResult.text.includes('123-45-6789'), true, 'TXT text should extract SSN');

  // 2. Fail-Closed Image Check
  const imgResult = await extractTextFromFile({
    name: 'medical_scan.png',
    buffer: Buffer.from([137, 80, 78, 71]),
    type: 'image/png'
  });
  assert.strictEqual(imgResult.unscannable, true, 'Image file MUST be flagged as unscannable');
  assert.strictEqual(imgResult.reason.includes('Fail-Closed'), true, 'Must cite Fail-Closed Security Policy');

  console.log('  ✓ File Text Extraction tests passed.');
}

function testSingleChunkSensitivityPreservation() {
  console.log('Testing Single-Chunk Sensitivity Preservation (No Score Dilution)...');

  // Create a large multi-chunk document: 5 benign chunks + 1 chunk containing a critical secret
  const benignParagraph = 'This is a standard corporate overview paragraph discussing quarter goals, team milestones, project deadlines, and general business updates. '.repeat(20);
  const sensitiveParagraph = 'CRITICAL ACCESSS CREDENTIAL: sk-abc12345678901234567890123456789 master production secret key.';

  const fullDocumentText = [
    benignParagraph, // Chunk 0 (Benign)
    benignParagraph, // Chunk 1 (Benign)
    benignParagraph, // Chunk 2 (Benign)
    sensitiveParagraph, // Chunk 3 (CRITICAL SENSITIVE)
    benignParagraph, // Chunk 4 (Benign)
    benignParagraph  // Chunk 5 (Benign)
  ].join('\n\n');

  // Chunk document
  const chunks = chunkText(fullDocumentText, 3000, 200);
  assert.strictEqual(chunks.length >= 4, true, 'Document should split into multiple chunks');

  // Run Regex across full text
  const regexMatches = runRegexChecks(fullDocumentText);
  assert.strictEqual(regexMatches.some(m => m.category === 'api_key'), true, 'Regex should catch API key in full document text');

  // Run LLM evaluation per chunk
  const chunkLLMResults = chunks.map((chunk, idx) => {
    const isSensitiveChunk = chunk.text.includes('sk-abc12345678901234567890123456789');
    return {
      chunkIndex: idx,
      sensitive: isSensitiveChunk,
      category: isSensitiveChunk ? 'api_key' : null,
      confidence: isSensitiveChunk ? 0.95 : 0.0,
      skipped: false
    };
  });

  // Calculate Risk Score across multi-chunk document
  const riskAnalysis = calculateRiskScore({
    regexMatches,
    chunkLLMResults,
    userRole: 'engineering',
    destinationDomain: 'chatgpt.com',
    unscannable: false
  });

  // Evaluate Policy
  const policyResult = evaluatePolicy({
    regexMatches,
    chunkLLMResults,
    unscannable: false,
    fileName: 'large_company_doc.pdf',
    riskAnalysis,
    customPolicyConfig: { blockThreshold: 75, redactThreshold: 45 }
  });

  // Verification: Single sensitive chunk MUST cause whole file to be BLOCKED
  assert.strictEqual(policyResult.action, 'block', 'Whole file MUST be BLOCKED even if only 1 chunk out of 6 contains sensitive data');
  assert.strictEqual(policyResult.riskScore >= 95, true, 'Risk score must preserve maximum severity (>= 95)');

  console.log('  ✓ Single-Chunk Sensitivity Preservation test passed (Score was NOT diluted by benign chunks).');
}

function testFailClosedPolicyForImages() {
  console.log('Testing Fail-Closed Policy Enforcement for Unscannable Files...');

  const riskAnalysis = calculateRiskScore({
    regexMatches: [],
    chunkLLMResults: [],
    userRole: 'engineering',
    destinationDomain: 'chatgpt.com',
    unscannable: true
  });

  const policyResult = evaluatePolicy({
    regexMatches: [],
    chunkLLMResults: [],
    unscannable: true,
    fileName: 'scanned_passport.jpg',
    unscannableReason: 'Image format .jpg cannot be text-verified',
    riskAnalysis,
    customPolicyConfig: { blockThreshold: 75, redactThreshold: 45 }
  });

  assert.strictEqual(policyResult.action, 'block', 'Unscannable image MUST be BLOCKED by Fail-Closed Security Floor');
  assert.strictEqual(policyResult.fixedFloorTriggered, true, 'Must trigger Fixed Security Floor');

  console.log('  ✓ Fail-Closed Policy test passed.');
}

const { normalizeText, calculateShannonEntropy, isChunkTriagedForLLM, hasHighEntropyTokens } = require('../engine/preprocess.js');
const { runMultiChunkLLMCheck } = require('../detectors/llm.js');

function testTextPreprocessAndEntropyTriage() {
  console.log('Testing Text Normalization, Shannon Entropy & Heuristic Gatekeeper...');

  // 1. Normalization
  const rawText = 'Line 1\n\n\n\nLine 2   \n=============\nLine 3';
  const normalized = normalizeText(rawText);
  assert.strictEqual(normalized.includes('\n\n\n'), false, 'Normalizer should collapse 3+ newlines');
  assert.strictEqual(normalized.includes('============='), false, 'Normalizer should strip repetitive low-entropy separator lines');

  // 2. Shannon Entropy calculation
  const lowEntropyStr = 'aaaaaaaaaaaaaaaaaaaaaaaa'; // Single repeated character
  const highEntropyStr = '9A8f17k3LmZpQx9vW2tR0sY'; // Random high-entropy token
  assert.strictEqual(calculateShannonEntropy(lowEntropyStr), 0, 'Repeated char entropy should be 0');
  assert.strictEqual(calculateShannonEntropy(highEntropyStr) > 4.0, true, 'Random string should have high entropy');

  // 3. Heuristic Gatekeeper Triage
  const cleanChunk = 'This is a normal paragraph discussing solar panels and renewable energy efficiency.';
  const sensitiveKeywordChunk = 'Please review the internal confidential salary distribution spreadsheet.';
  const highEntropyTokenChunk = 'Access secret key: 9A8f17k3LmZpQx9vW2tR0sY9900223344';

  assert.strictEqual(isChunkTriagedForLLM(cleanChunk), false, 'Clean chunk MUST bypass LLM triage');
  assert.strictEqual(isChunkTriagedForLLM(sensitiveKeywordChunk), true, 'Sensitive keyword chunk MUST be triaged for LLM');
  assert.strictEqual(isChunkTriagedForLLM(highEntropyTokenChunk), true, 'High entropy token chunk MUST be triaged for LLM');

  console.log('  ✓ Text Normalization, Shannon Entropy & Heuristic Gatekeeper tests passed.');
}

async function testEnvFileInspection() {
  console.log('Testing .env File Inspection & Key-Value Secret Blocking...');

  const envFileResult = await extractTextFromFile({
    name: '.env',
    buffer: Buffer.from('PORT=3000\nDATABASE_URL=postgres://admin:Password123@localhost:5432/production_db\nGEMINI_API_KEY=AIzaSyA1234567890abcdef1234567890abc\nJWT_SECRET=super_secret_jwt_key_990011\n', 'utf-8'),
    type: 'application/octet-stream'
  });

  assert.strictEqual(envFileResult.unscannable, false, '.env file MUST be scannable text');
  assert.strictEqual(envFileResult.text.includes('DATABASE_URL'), true, '.env content must be extracted');

  const regexMatches = runRegexChecks(envFileResult.text);
  assert.strictEqual(regexMatches.some(m => m.category === 'api_key'), true, 'Regex MUST detect .env credentials (DATABASE_URL / GEMINI_API_KEY / JWT_SECRET)');

  const riskAnalysis = calculateRiskScore({ regexMatches, unscannable: false });
  const policyResult = evaluatePolicy({ regexMatches, fileName: '.env', riskAnalysis });

  assert.strictEqual(policyResult.action, 'block', '.env file containing secrets MUST be BLOCKED by Fixed Security Floor');
  assert.strictEqual(policyResult.fixedFloorTriggered, true, 'Must trigger Fixed Security Floor violation');

  console.log('  ✓ .env File Inspection & Key-Value Secret Blocking tests passed.');
}

async function runAllFileGovernanceTests() {
  console.log('\n--- Running File Upload Governance Unit Tests ---');
  await testFileTextExtraction();
  testTextPreprocessAndEntropyTriage();
  await testEnvFileInspection();
  testSingleChunkSensitivityPreservation();
  testFailClosedPolicyForImages();
  console.log('--- All File Upload Governance Tests Passed Successfully! ---\n');
}

if (require.main === module) {
  runAllFileGovernanceTests();
}

module.exports = { runAllFileGovernanceTests };
