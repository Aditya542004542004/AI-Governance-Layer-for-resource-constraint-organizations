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
const { buildLAAWWindows } = require('../engine/preprocess.js');

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

  // 3. Microsoft Word (.docx) Extraction Test
  const docxXmlBuffer = Buffer.from(
    'PK\x03\x04<w:document><w:body><w:p><w:t>Confidential Project Valuation EBITDA: 50M. API Key: sk-proj-123456789012345678901234</w:t></w:p></w:body></w:document>',
    'binary'
  );
  const docxResult = await extractTextFromFile({
    name: 'corporate_valuation.docx',
    buffer: docxXmlBuffer,
    type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  });
  assert.strictEqual(docxResult.unscannable, false, 'DOCX with text nodes should be scannable');
  assert.strictEqual(docxResult.text.includes('sk-proj-123456789012345678901234'), true, 'DOCX text must extract sensitive secret key');

  // 4. Adobe PDF (.pdf) Extraction Test
  const pdfStreamBuffer = Buffer.from(
    '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n2 0 obj\n<< /Type /Page >>\nBT\n(Confidential Patient Biopsy Diagnosis: Malignant. SSN: 999-88-7777) Tj\nET\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF',
    'binary'
  );
  const pdfResult = await extractTextFromFile({
    name: 'medical_report.pdf',
    buffer: pdfStreamBuffer,
    type: 'application/pdf'
  });
  assert.strictEqual(pdfResult.unscannable, false, 'PDF with text stream objects should be scannable');
  assert.strictEqual(pdfResult.text.includes('999-88-7777'), true, 'PDF text must extract SSN');

  // 5. DEFLATE-Compressed Microsoft Word (.docx) ZIP Entry Test
  const zlib = require('zlib');
  const xmlPayload = Buffer.from('<w:document><w:body><w:p><w:t>Secret DOCX text sk-proj-998877665544332211223344</w:t></w:p></w:body></w:document>');
  const deflated = zlib.deflateRawSync(xmlPayload);
  
  const entryNameBuf = Buffer.from('word/document.xml');
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0); // PK\x03\x04
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(0, 6);
  header.writeUInt16LE(8, 8); // Compression: 8 (Deflate)
  header.writeUInt32LE(deflated.length, 18); // compressed size
  header.writeUInt32LE(xmlPayload.length, 22); // uncompressed size
  header.writeUInt16LE(entryNameBuf.length, 26);
  header.writeUInt16LE(0, 28);
  
  const zipBuffer = Buffer.concat([header, entryNameBuf, deflated]);
  const compressedDocxResult = await extractTextFromFile({
    name: 'test1doc.docx',
    buffer: zipBuffer,
    type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  });
  assert.strictEqual(compressedDocxResult.unscannable, false, 'DEFLATE compressed DOCX must be scannable');
  assert.strictEqual(compressedDocxResult.text.includes('sk-proj-998877665544332211223344'), true, 'Must extract sensitive key from DEFLATE compressed DOCX');

  // 6. Binary Garbage Stream PDF Test (Verifies binary gibberish is rejected and flagged as unscannable Fail-Closed)
  const binaryGarbagePdfBuffer = Buffer.from(
    '%PDF-1.4\n1 0 obj\nBT (5\xD8f\xB2\xDB\xDB\xDBK\xF5ZcT\xB0\xA4\xC4#\xA9`\xD0) ET\nendobj\n%%EOF',
    'latin1'
  );
  const garbagePdfResult = await extractTextFromFile({
    name: 'intro.pdf',
    buffer: binaryGarbagePdfBuffer,
    type: 'application/pdf'
  });
  assert.strictEqual(garbagePdfResult.unscannable, true, 'Binary stream garbage PDF MUST be flagged as unscannable (Fail-Closed active)');

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

function testHeuristicPrioritySampling() {
  console.log('Testing Heuristic Priority Sampling (Top-K)...');

  const chunks = [
    { chunkIndex: 0, text: 'This is a benign chunk explaining general photosynthesis in plants.' },
    { chunkIndex: 1, text: 'This chunk contains high entropy string 9A8f17k3LmZpQx9vW2tR0sY9900223344 for verification.' },
    { chunkIndex: 2, text: 'This chunk has explicit secret password token salary diagnosis confidential keyword anchors.' },
    { chunkIndex: 3, text: 'Another clean overview chunk with standard documentation text.' }
  ];

  const topPriority = selectPriorityChunks(chunks, 2);

  assert.strictEqual(topPriority.length, 2, 'Should select top 2 priority chunks');
  assert.strictEqual(topPriority[0].chunkIndex, 2, 'Highest priority chunk (+5 score keyword anchor) should be first');
  assert.strictEqual(topPriority[1].chunkIndex, 1, 'Second priority chunk (+3 score entropy token) should be second');

  // Verify clean chunks (score == 0) are excluded
  const cleanChunksOnly = [
    { chunkIndex: 0, text: 'Just a normal sentence.' },
    { chunkIndex: 1, text: 'Another ordinary paragraph.' }
  ];

  const cleanPriority = selectPriorityChunks(cleanChunksOnly, 2);
  assert.strictEqual(cleanPriority.length, 0, 'Clean chunks with score 0 MUST be completely excluded (0 candidates)');

  console.log('  ✓ Heuristic Priority Sampling (Top-K) tests passed.');
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

function testHybridLAAWWindowing() {
  console.log('Testing Hybrid Locality-Aware Anchor Windowing (H-LAAW)...');

  // Test 1: Short text (<= 2500 chars) -> 100% full-text evaluation, 1 window
  const shortText = 'This is a short chat prompt explaining photosynthesis in under 500 characters.';
  const shortWindows = buildLAAWWindows(shortText, 1500, 400);

  assert.strictEqual(shortWindows.length, 1, 'Short text MUST produce 1 window');
  assert.strictEqual(shortWindows[0].isFullText, true, 'Short text window MUST be marked full-text evaluation');
  assert.strictEqual(shortWindows[0].windowType, 'FULL', 'Short text windowType MUST be FULL');

  // Test 2: Large document (> 2500 chars) with anchor at position 5000
  const padding = 'A'.repeat(5000);
  const largeText = `DOCUMENT HEAD TITLE\n${padding}\nCONFIDENTIAL MERGER ACQUISITION EBITDA REVENUE DETAILS AT POSITION 5000\n${padding}`;
  const largeWindows = buildLAAWWindows(largeText, 1500, 400);

  assert.strictEqual(largeWindows.length, 2, 'Large document MUST produce at most 2 LAAW windows');
  assert.strictEqual(largeWindows[0].windowType, 'HEAD', 'Window 1 MUST be document HEAD');
  assert.strictEqual(largeWindows[0].text.length, 1500, 'HEAD window MUST be capped at 1500 chars');

  assert.strictEqual(largeWindows[1].windowType, 'ANCHOR_LOCUS', 'Window 2 MUST be ANCHOR_LOCUS');
  assert.strictEqual(largeWindows[1].text.includes('CONFIDENTIAL MERGER ACQUISITION'), true, 'Snippet 2 MUST capture deep anchor locus');

  console.log('  ✓ Hybrid Locality-Aware Anchor Windowing (H-LAAW) tests passed.');
}

async function runAllFileGovernanceTests() {
  console.log('\n--- Running File Upload Governance Unit Tests ---');
  await testFileTextExtraction();
  testTextPreprocessAndEntropyTriage();
  testHeuristicPrioritySampling();
  testHybridLAAWWindowing();
  await testEnvFileInspection();
  testSingleChunkSensitivityPreservation();
  testFailClosedPolicyForImages();
  console.log('--- All File Upload Governance Tests Passed Successfully! ---\n');
}

if (require.main === module) {
  runAllFileGovernanceTests();
}

module.exports = { runAllFileGovernanceTests };
