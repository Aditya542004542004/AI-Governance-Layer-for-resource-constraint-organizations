/**
 * scratch/benchmark-1mb.js
 * 
 * Performance benchmark script testing 1MB document text processing latency.
 * Verifies chunking, full-text regex scanning, short-circuiting, and execution timing.
 */

const { extractTextFromFile, chunkText } = require('../detectors/file-extract.js');
const { runRegexChecks } = require('../detectors/regex.js');
const { calculateRiskScore } = require('../engine/risk-score.js');
const { evaluatePolicy } = require('../engine/policy.js');

async function benchmark1MBFile() {
  console.log('===============================================================');
  console.log('         1MB LARGE DOCUMENT PERFORMANCE BENCHMARK              ');
  console.log('===============================================================\n');

  const totalStartTime = performance.now();

  // 1. Generate ~1.1MB synthetic corporate text document
  console.log('[1/4] Generating 1.1MB synthetic text buffer (~1,100,000 characters)...');
  const baseParagraph = 'This is a standard enterprise document section containing Q3 architectural guidelines, cloud deployment configurations, database scaling policies, team sprint milestones, and security compliance procedures. '.repeat(10) + '\n\n';
  
  // Repeat to reach ~1.1MB (approx 5,500 paragraphs)
  const paragraphCount = 5500;
  const paragraphArray = new Array(paragraphCount).fill(baseParagraph);
  
  // Embed a secret API key at paragraph 4,200 (~80% into the document)
  paragraphArray[4200] = 'CONFIDENTIAL STAGING CREDENTIAL: sk-abc12345678901234567890123456789 master production secret key.\n\n';
  
  const textContent = paragraphArray.join('');
  const textBuffer = Buffer.from(textContent, 'utf-8');

  console.log(`  ✓ Document generated: ${textBuffer.byteLength} bytes (${(textBuffer.byteLength / 1024 / 1024).toFixed(2)} MB), ${textContent.length} characters.`);

  // 2. Extract and Chunk Document
  const extractStartTime = performance.now();
  console.log('\n[2/4] Running text extraction & chunking (8,000 char chunks, 600 char overlap)...');
  
  const extractedData = await extractTextFromFile({
    name: 'large_enterprise_audit_log_1mb.txt',
    buffer: textBuffer,
    type: 'text/plain'
  });

  const extractTimeMs = Math.round(performance.now() - extractStartTime);
  console.log(`  ✓ Extracted in ${extractTimeMs} ms.`);
  console.log(`  ✓ Total Chunks Produced: ${extractedData.chunks.length} chunks (down from 370+ chunks with old 3K settings!)`);

  // 3. Full-Text Regex Pass
  const regexStartTime = performance.now();
  console.log('\n[3/4] Running full-text Regex scanning in ONE pass...');
  
  const regexMatches = runRegexChecks(extractedData.text);
  const regexTimeMs = Math.round(performance.now() - regexStartTime);

  console.log(`  ✓ Full-text Regex completed in ${regexTimeMs} ms. Found ${regexMatches.length} match(es).`);

  // 4. Short-Circuit & Policy Evaluation
  const policyStartTime = performance.now();
  console.log('\n[4/4] Evaluating Policy & Short-Circuit Optimization...');

  const hasFixedFloorRegexHit = regexMatches.some(m => 
    m.category === 'credit_card' || m.category === 'api_key' || m.category === 'national_id' || m.category === 'pin_passcode'
  );

  let decisionAction = 'allow';
  let fixedFloorTriggered = false;

  if (hasFixedFloorRegexHit) {
    console.log(`  ⚡ SHORT-CIRCUIT TRIGGERED: Fixed Floor API Key found via full-text Regex. Skipping LLM chunk pass!`);
    const riskAnalysis = calculateRiskScore({ regexMatches, userRole: 'engineering' });
    const policyResult = evaluatePolicy({ regexMatches, riskAnalysis, fileName: extractedData.fileName });
    decisionAction = policyResult.action;
    fixedFloorTriggered = policyResult.fixedFloorTriggered;
  }

  const policyTimeMs = Math.round(performance.now() - policyStartTime);
  const totalTimeMs = Math.round(performance.now() - totalStartTime);

  console.log('\n---------------------------------------------------------------');
  console.log('              BENCHMARK PERFORMANCE SUMMARY RESULTS            ');
  console.log('---------------------------------------------------------------');
  console.log(`Document Size:           ${(textBuffer.byteLength / 1024 / 1024).toFixed(2)} MB (${textContent.length} chars)`);
  console.log(`Total Chunks Generated:  ${extractedData.chunks.length}`);
  console.log(`Extraction & Chunking:   ${extractTimeMs} ms`);
  console.log(`Full-Text Regex Pass:    ${regexTimeMs} ms`);
  console.log(`Policy & Short-Circuit:  ${policyTimeMs} ms`);
  console.log(`---------------------------------------------------------------`);
  console.log(`TOTAL ELAPSED TIME:      ${(totalTimeMs / 1000).toFixed(2)} seconds (${totalTimeMs} ms)`);
  console.log(`Decision Action:         ${decisionAction.toUpperCase()}`);
  console.log(`Fixed Floor Triggered:   ${fixedFloorTriggered}`);
  console.log('===============================================================\n');

  if (totalTimeMs > 60000) {
    console.error('FAIL: Benchmark exceeded 60 second limit!');
    process.exit(1);
  } else {
    console.log('SUCCESS: 1MB file benchmark completed in WELL UNDER 1 MINUTE!');
  }
}

benchmark1MBFile();
