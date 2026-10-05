/**
 * test/test-file-governance.js
 * 
 * Unit tests for File Upload Governance:
 * - Multi-format client-side text extraction (.txt, .docx, .xlsx, .pdf)
 * - Multi-chunk evaluation sensitivity preservation (verifies single-chunk sensitive sentence flags whole file without score dilution)
 * - Fail-Closed guardrail protection for images & unscannable binary formats.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { extractTextFromFile, chunkText } = require('../detectors/file-extract.js');
const { extractTextFromImage } = require('../lib/ocr.js');
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

  // 7. DEFLATE-Compressed Microsoft Excel (.xlsx) Extraction Test
  const xlsxXmlPayload = Buffer.from('<sst><si><t>Employee Financial Salaries API Key: sk-proj-112233445566778899001122</t></si></sst>');
  const xlsxDeflated = zlib.deflateRawSync(xlsxXmlPayload);
  const xlsxEntryName = Buffer.from('xl/sharedStrings.xml');
  const xlsxHeader = Buffer.alloc(30);
  xlsxHeader.writeUInt32LE(0x04034b50, 0);
  xlsxHeader.writeUInt16LE(20, 4);
  xlsxHeader.writeUInt16LE(0, 6);
  xlsxHeader.writeUInt16LE(8, 8);
  xlsxHeader.writeUInt32LE(xlsxDeflated.length, 18);
  xlsxHeader.writeUInt32LE(xlsxXmlPayload.length, 22);
  xlsxHeader.writeUInt16LE(xlsxEntryName.length, 26);
  xlsxHeader.writeUInt16LE(0, 28);
  const xlsxZipBuffer = Buffer.concat([xlsxHeader, xlsxEntryName, xlsxDeflated]);
  const xlsxResult = await extractTextFromFile({
    name: 'financial_report.xlsx',
    buffer: xlsxZipBuffer,
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  });
  assert.strictEqual(xlsxResult.unscannable, false, 'DEFLATE compressed XLSX must be scannable');
  assert.strictEqual(xlsxResult.text.includes('sk-proj-112233445566778899001122'), true, 'Must extract sensitive key from XLSX shared strings');

  // 8. DEFLATE-Compressed Microsoft PowerPoint (.pptx) Extraction Test
  const pptxXmlPayload = Buffer.from('<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Executive Q4 Strategy Passcode: 84920 Server Key: sk-proj-556677889900112233445566</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>');
  const pptxDeflated = zlib.deflateRawSync(pptxXmlPayload);
  const pptxEntryName = Buffer.from('ppt/slides/slide1.xml');
  const pptxHeader = Buffer.alloc(30);
  pptxHeader.writeUInt32LE(0x04034b50, 0);
  pptxHeader.writeUInt16LE(20, 4);
  pptxHeader.writeUInt16LE(0, 6);
  pptxHeader.writeUInt16LE(8, 8);
  pptxHeader.writeUInt32LE(pptxDeflated.length, 18);
  pptxHeader.writeUInt32LE(pptxXmlPayload.length, 22);
  pptxHeader.writeUInt16LE(pptxEntryName.length, 26);
  pptxHeader.writeUInt16LE(0, 28);
  const pptxZipBuffer = Buffer.concat([pptxHeader, pptxEntryName, pptxDeflated]);
  const pptxResult = await extractTextFromFile({
    name: 'q4_presentation.pptx',
    buffer: pptxZipBuffer,
    type: 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
  });
  assert.strictEqual(pptxResult.unscannable, false, 'DEFLATE compressed PPTX must be scannable');
  assert.strictEqual(pptxResult.text.includes('sk-proj-556677889900112233445566'), true, 'Must extract sensitive key from PPTX slide text');

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

async function testOnDeviceImageOcrGovernance() {
  console.log('Testing On-Device WebAssembly Image OCR Governance...');

  // 1. Verify local offline asset integrity (Zero external CDN calls)
  const vendorDir = path.resolve(__dirname, '../vendor/tesseract');
  assert.strictEqual(fs.existsSync(path.join(vendorDir, 'tesseract.min.js')), true, 'tesseract.min.js must exist locally');
  assert.strictEqual(fs.existsSync(path.join(vendorDir, 'worker.min.js')), true, 'worker.min.js must exist locally');
  assert.strictEqual(fs.existsSync(path.join(vendorDir, 'tesseract-core.wasm.js')), true, 'tesseract-core.wasm.js must exist locally');
  assert.strictEqual(fs.existsSync(path.join(vendorDir, 'tesseract-core.wasm')), true, 'tesseract-core.wasm must exist locally');
  assert.strictEqual(fs.existsSync(path.join(vendorDir, 'lang-data', 'eng.traineddata.gz')), true, 'eng.traineddata.gz must exist locally in vendor/tesseract/lang-data/');

  // Verify manifest configuration
  const manifest = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../manifest.json'), 'utf8'));
  assert.strictEqual(manifest.content_security_policy.extension_pages.includes('wasm-unsafe-eval'), true, 'CSP must permit wasm-unsafe-eval');
  assert.strictEqual(manifest.content_scripts[0].js.includes('vendor/tesseract/tesseract.min.js'), true, 'content_scripts must include tesseract.min.js');
  assert.strictEqual(manifest.content_scripts[0].js.includes('lib/ocr.js'), true, 'content_scripts must include lib/ocr.js');

  // 2. Purely Visual Image Test: empty text / low confidence -> ALLOW
  const visualImageFile = {
    name: 'architecture_diagram.png',
    type: 'image/png',
    __mockOcrResult: { text: '', confidence: 0 }
  };
  const visualOcr = await extractTextFromImage(visualImageFile);
  assert.strictEqual(visualOcr.text, '', 'Purely visual image must produce empty extracted text');
  assert.strictEqual(visualOcr.confidence, 0, 'Visual image confidence should be 0');

  const visualRegex = runRegexChecks(visualOcr.text);
  assert.strictEqual(visualRegex.length, 0, 'No regex triggers on empty text');
  const visualRisk = calculateRiskScore({ regexMatches: visualRegex, unscannable: false });
  const visualPolicy = evaluatePolicy({ regexMatches: visualRegex, fileName: visualImageFile.name, riskAnalysis: visualRisk });
  assert.strictEqual(visualPolicy.action, 'allow', 'Purely visual image without text MUST be allowed');
  assert.strictEqual(visualPolicy.riskScore, 0, 'Risk score for visual image MUST be 0');

  // 3. Sensitive Image Evasion Test (Closing Visual Evasion):
  // User attempts to bypass DLP by attaching a screenshot containing API keys
  const sensitiveImageFile = {
    name: 'cloud_credentials_screenshot.png',
    type: 'image/png',
    __mockOcrResult: {
      text: 'AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\nSECRET_KEY = sk-proj-123456789012345678901234\n',
      confidence: 92.5
    }
  };
  const sensitiveOcr = await extractTextFromImage(sensitiveImageFile);
  assert.strictEqual(sensitiveOcr.text.includes('sk-proj-'), true, 'OCR must extract credential text from image');
  assert.strictEqual(sensitiveOcr.confidence > 90, true, 'High confidence OCR detection');

  const sensitiveRegex = runRegexChecks(sensitiveOcr.text);
  assert.strictEqual(sensitiveRegex.some(m => m.category === 'api_key'), true, 'Regex MUST detect API credentials extracted from image');

  const sensitiveRisk = calculateRiskScore({ regexMatches: sensitiveRegex, unscannable: false });
  const sensitivePolicy = evaluatePolicy({ regexMatches: sensitiveRegex, fileName: sensitiveImageFile.name, riskAnalysis: sensitiveRisk });

  assert.strictEqual(sensitivePolicy.action, 'block', 'Image containing API key MUST be BLOCKED by Fixed Security Floor');
  assert.strictEqual(sensitivePolicy.fixedFloorTriggered, true, 'Visual evasion attempt MUST trigger Fixed Security Floor violation');
  assert.strictEqual(sensitivePolicy.riskScore >= 95, true, 'Sensitive image must receive maximum risk score');

  // 4. Research Paper Image PII & Multi-Email Test (OCR spacing tolerance & 70% risk score):
  // User uploads an image of a research paper containing researcher names and emails with OCR artifacts
  const paperImageFile = {
    name: 'ieee_research_paper_authors.png',
    type: 'image/png',
    __mockOcrResult: {
      text: 'IEEE Transactions on Artificial Intelligence\nAuthors: Aditya Sharma, Dr. Rajesh Kumar\nAffiliation: Department of Computer Science, VIT University\nContact: aditya.sharma @ vit.ac.in , rkumar @ vit.edu\nAbstract - In this paper we study on-device AI...',
      confidence: 89.0
    }
  };
  const paperOcr = await extractTextFromImage(paperImageFile);
  assert.strictEqual(paperOcr.confidence > 80, true, 'High confidence OCR for paper');

  const paperRegex = runRegexChecks(paperOcr.text);
  const emailHits = paperRegex.filter(m => m.category === 'email');
  assert.strictEqual(emailHits.length >= 2, true, 'Must detect both researcher emails despite OCR whitespace artifacts');

  const paperRisk = calculateRiskScore({ regexMatches: paperRegex, destinationDomain: 'chatgpt.com', unscannable: false });
  assert.strictEqual(paperRisk.score >= 70, true, 'Multi-email / PII disclosure must receive a score of at least 70/100');

  const paperPolicy = evaluatePolicy({ regexMatches: paperRegex, fileName: paperImageFile.name, riskAnalysis: paperRisk });
  assert.strictEqual(paperPolicy.action, 'redact', 'Research paper with researcher PII/emails MUST trigger REDACT warning modal');
  assert.strictEqual(paperPolicy.riskScore >= 70, true, 'Policy evaluated risk score must be >= 70/100');

  // 5. On-Device Image Redaction & Bounding Box Blackout Test:
  // Verifies that redactImageFile and calculateRedactionBoxes properly resolve coordinates
  const { calculateRedactionBoxes, redactImageFile } = require('../lib/ocr.js');
  const mockImageWords = [
    { text: 'Paper', bbox: { x0: 20, y0: 30, x1: 60, y1: 45 } },
    { text: 'aditya.sharma@vit.ac.in', bbox: { x0: 100, y0: 50, x1: 280, y1: 68 } },
    { text: 'rkumar@vit.edu', bbox: { x0: 300, y0: 50, x1: 420, y1: 68 } }
  ];
  const detectedSensitiveMatches = [
    { category: 'email', match: 'aditya.sharma@vit.ac.in' },
    { category: 'email', match: 'rkumar@vit.edu' }
  ];
  const boxes = calculateRedactionBoxes(detectedSensitiveMatches, { words: mockImageWords });
  assert.strictEqual(boxes.length, 2, 'Must calculate bounding boxes for both sensitive emails');
  assert.strictEqual(boxes[0].x0, 100, 'First box coordinates must match first email word');
  assert.strictEqual(boxes[1].x0, 300, 'Second box coordinates must match second email word');

  const redactedResult = await redactImageFile(
    { name: 'paper_authors.png', type: 'image/png', size: 2048 },
    detectedSensitiveMatches,
    { words: mockImageWords }
  );
  assert.strictEqual(redactedResult.name, 'redacted_paper_authors.png', 'Redacted image must receive sanitized filename');
  assert.strictEqual(redactedResult.isRedactedImage, true, 'Image must be flagged as redacted');
  assert.strictEqual(redactedResult.redactedBoxesCount, 2, 'Both sensitive boxes must be covered by blackout');

  console.log('  ✓ On-Device WebAssembly Image OCR Governance tests passed.');
}

const { handleAnalyzeImageFile } = require('../background.js');

async function testImageFileGovernancePipelineWithLLMOff() {
  console.log('Testing Image File Governance Pipeline with LLM OFF & Fail-Closed Protection...');

  const prevChrome = global.chrome;
  global.chrome = {
    runtime: {
      getURL: (path) => `chrome-extension://mock-extension-id/${path}`,
      onInstalled: { addListener: () => {} },
      onMessage: { addListener: () => {} }
    },
    storage: {
      local: {
        get: (defs, cb) => cb({ ...defs, enableLLM: false, enableRegex: true }),
        set: (data, cb) => cb && cb()
      }
    }
  };

  try {
    // 1. Purely visual image -> ALLOW, score 0
    const visualMockImage = {
      name: 'diagram.png',
      type: 'image/png',
      __mockOcrResult: { text: '', confidence: 0, words: [], lines: [] }
    };
    const visualRes = await handleAnalyzeImageFile({
      imageData: visualMockImage,
      fileName: 'diagram.png',
      destinationDomain: 'gemini.google.com'
    });
    assert.strictEqual(visualRes.action, 'allow', 'Purely visual image must be ALLOWED');
    assert.strictEqual(visualRes.riskScore, 0, 'Risk score for visual image must be 0');
    assert.strictEqual(visualRes.isVisualImage, true, 'Image must be flagged as purely visual');

    // 2. Research Paper image containing emails with LLM OFF -> REDACT, score >= 70
    const paperMockImage = {
      name: 'research_paper_vit.png',
      type: 'image/png',
      __mockOcrResult: {
        text: 'IEEE Transactions on Artificial Intelligence\nAuthors: Aditya Sharma, Dr. Rajesh Kumar\nAffiliation: VIT University\nContact: student@vit.edu, prof@vit.edu',
        confidence: 94.0,
        words: [
          { text: 'student@vit.edu', bbox: { x0: 50, y0: 80, x1: 200, y1: 100 } },
          { text: 'prof@vit.edu', bbox: { x0: 220, y0: 80, x1: 350, y1: 100 } }
        ],
        lines: []
      }
    };
    const paperRes = await handleAnalyzeImageFile({
      imageData: paperMockImage,
      fileName: 'research_paper_vit.png',
      destinationDomain: 'gemini.google.com'
    });
    assert.strictEqual(paperRes.action, 'redact', 'Paper image with emails MUST trigger REDACT even with LLM OFF');
    assert.strictEqual(paperRes.riskScore >= 70, true, 'Risk score must be >= 70 with LLM OFF');
    assert.strictEqual(paperRes.redactionBoxes.length, 2, 'Redaction bounding boxes must be calculated for both emails');

    // 3. Sensitive image containing API key with LLM OFF -> BLOCK, score >= 95
    const apiKeyMockImage = {
      name: 'api_key_screenshot.png',
      type: 'image/png',
      __mockOcrResult: {
        text: 'Production API Key: sk-proj-123456789012345678901234',
        confidence: 96.0,
        words: [
          { text: 'sk-proj-123456789012345678901234', bbox: { x0: 10, y0: 20, x1: 300, y1: 40 } }
        ],
        lines: []
      }
    };
    const apiKeyRes = await handleAnalyzeImageFile({
      imageData: apiKeyMockImage,
      fileName: 'api_key_screenshot.png',
      destinationDomain: 'gemini.google.com'
    });
    assert.strictEqual(apiKeyRes.action, 'block', 'API key image MUST trigger BLOCK even with LLM OFF');
    assert.strictEqual(apiKeyRes.fixedFloorTriggered, true, 'Fixed Security Floor must be triggered');
    assert.strictEqual(apiKeyRes.riskScore >= 95, true, 'Risk score must be >= 95');

    // 4. OCR failure / crash -> Fail-Closed BLOCKED (Never fail-open!)
    const errorMockImage = {
      name: 'corrupted_or_csp_blocked.png',
      type: 'image/png',
      get __mockOcrResult() {
        throw new Error('Host CSP blocked Web Worker instantiation');
      }
    };
    const errorRes = await handleAnalyzeImageFile({
      imageData: errorMockImage,
      fileName: 'corrupted_or_csp_blocked.png',
      destinationDomain: 'gemini.google.com'
    });
    assert.strictEqual(errorRes.action, 'block', 'OCR failure MUST trigger Fail-Closed BLOCK');
    assert.strictEqual(errorRes.unscannable, true, 'File must be marked unscannable');
    assert.strictEqual(errorRes.fixedFloorTriggered, true, 'Fail-Closed Fixed Security Floor must be triggered');

    console.log('  ✓ Image File Governance Pipeline with LLM OFF & Fail-Closed Protection tests passed.');
  } finally {
    global.chrome = prevChrome;
  }
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
  await testOnDeviceImageOcrGovernance();
  await testImageFileGovernancePipelineWithLLMOff();
  console.log('--- All File Upload Governance Tests Passed Successfully! ---\n');
}

if (require.main === module) {
  runAllFileGovernanceTests();
}

module.exports = { runAllFileGovernanceTests };
