/**
 * background.js
 * 
 * Manifest V3 Background Service Worker.
 * Acts as the centralized coordinator for prompt scanning requests, storage management,
 * on-device detection execution, and local IndexedDB audit logging.
 */

// Load detection engines, policy layers, and local audit storage
if (typeof importScripts !== 'undefined') {
  try {
    importScripts(
      'lib/pdf-extract.js',
      'lib/docx-extract.js',
      'lib/xlsx-extract.js',
      'lib/pptx-extract.js',
      'lib/ocr.js',
      'detectors/file-extract.js',
      'detectors/regex.js',
      'detectors/llm.js',
      'engine/preprocess.js',
      'engine/risk-score.js',
      'engine/policy.js',
      'engine/explain.js',
      'storage/audit.js'
    );
  } catch (err) {
    console.error('[AI Governance] Background service worker failed to import script dependencies:', err);
  }
} else if (typeof require !== 'undefined') {
  try {
    require('./lib/pdf-extract.js');
    require('./lib/docx-extract.js');
    require('./lib/xlsx-extract.js');
    require('./lib/pptx-extract.js');
    require('./lib/ocr.js');
    require('./detectors/file-extract.js');
    Object.assign(globalThis, require('./detectors/regex.js'));
    Object.assign(globalThis, require('./detectors/llm.js'));
    Object.assign(globalThis, require('./engine/preprocess.js'));
    Object.assign(globalThis, require('./engine/risk-score.js'));
    Object.assign(globalThis, require('./engine/policy.js'));
    Object.assign(globalThis, require('./engine/explain.js'));
    Object.assign(globalThis, require('./storage/audit.js'));
  } catch (err) {}
}

// Default extension configuration settings stored in chrome.storage.local
const DEFAULT_SETTINGS = {
  enableRegex: true,
  enableLLM: true,
  userRole: 'engineering',
  blockThreshold: 75,
  redactThreshold: 45,
  enableMetadataSync: false
};

/**
 * Safely fetches user settings from chrome.storage.local or returns default configuration.
 * @returns {Promise<Object>}
 */
async function getExtensionSettings() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local && typeof chrome.storage.local.get === 'function') {
    return new Promise((resolve) => {
      chrome.storage.local.get(DEFAULT_SETTINGS, (data) => resolve(data || DEFAULT_SETTINGS));
    });
  }
  return { ...DEFAULT_SETTINGS };
}

// Initialize settings on extension install
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.get(DEFAULT_SETTINGS, (stored) => {
      chrome.storage.local.set(stored, () => {
        console.log('[AI Governance] Service worker installed & policy storage initialized.');
        if (typeof clearFileHashCache === 'function') {
          clearFileHashCache().catch(() => {});
        }
      });
    });
  });
}

/**
 * Computes SHA-256 hash using native Web Crypto API.
 * @param {string|Uint8Array|ArrayBuffer} textOrBytes 
 * @returns {Promise<string|null>} Hex string representation of SHA-256 hash
 */
async function computeSHA256Hash(textOrBytes) {
  try {
    let buffer;
    if (typeof textOrBytes === 'string') {
      if (textOrBytes.trim().length === 0) return null;
      buffer = new TextEncoder().encode(textOrBytes);
    } else if (textOrBytes instanceof Uint8Array) {
      if (textOrBytes.byteLength === 0) return null;
      buffer = textOrBytes.buffer.slice(textOrBytes.byteOffset, textOrBytes.byteOffset + textOrBytes.byteLength);
    } else if (textOrBytes instanceof ArrayBuffer) {
      if (textOrBytes.byteLength === 0) return null;
      buffer = textOrBytes;
    } else {
      const str = String(textOrBytes || '').trim();
      if (str.length === 0) return null;
      buffer = new TextEncoder().encode(str);
    }
    if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.digest === 'function') {
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
  } catch (err) {
    console.warn('[AI Governance] Web Crypto SHA-256 calculation failed:', err);
  }
  return null;
}

// Central runtime message listener
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.type) {
      return false;
    }

  if (message.type === 'ANALYZE_PROMPT') {
    handleAnalyzePrompt(message.payload)
      .then(response => sendResponse({ success: true, data: response }))
      .catch(err => {
        console.error('[AI Governance] Error processing prompt analysis:', err);
        sendResponse({ success: false, error: err.message });
      });
    return true; // Keep message channel open for async response
  }

  if (message.type === 'ANALYZE_FILE') {
    handleAnalyzeFile(message.payload)
      .then(response => sendResponse({ success: true, data: response }))
      .catch(err => {
        console.error('[AI Governance] Error processing file analysis:', err);
        sendResponse({ success: false, error: err.message });
      });
    return true;
  }

  if (message.type === 'ANALYZE_BATCH_FILES') {
    handleAnalyzeBatchFiles(message.payload)
      .then(response => sendResponse({ success: true, data: response }))
      .catch(err => {
        console.error('[AI Governance] Error processing batch file analysis:', err);
        sendResponse({ success: false, error: err.message });
      });
    return true;
  }

  if (message.type === 'ANALYZE_IMAGE_TEXT') {
    handleAnalyzeImageText(message.payload)
      .then(response => sendResponse({ success: true, data: response }))
      .catch(err => {
        console.error('[AI Governance] Error processing image OCR text analysis:', err);
        sendResponse({ success: false, error: err.message });
      });
    return true;
  }

  if (message.type === 'PERFORM_IMAGE_OCR') {
    runOffscreenOcr(message.payload?.imageData, message.payload?.options)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(err => {
        console.error('[AI Governance] Error during PERFORM_IMAGE_OCR:', err);
        sendResponse({ success: false, error: err.message });
      });
    return true;
  }

  if (message.type === 'ANALYZE_IMAGE_FILE') {
    handleAnalyzeImageFile(message.payload)
      .then(response => sendResponse({ success: true, data: response }))
      .catch(err => {
        console.error('[AI Governance] Error processing image file analysis:', err);
        sendResponse({ success: false, error: err.message });
      });
    return true;
  }

  if (message.type === 'GET_AUDIT_LOGS') {
    getAuditRecords(message.limit || 100)
      .then(logs => sendResponse({ success: true, data: logs }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'CLEAR_AUDIT_LOGS') {
    clearAuditRecords()
      .then(() => sendResponse({ success: true }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'CLEAR_HASH_CACHE' || message.type === 'CLEAR_FILE_HASH_CACHE') {
    if (typeof clearFileHashCache === 'function') {
      clearFileHashCache()
        .then(() => sendResponse({ success: true }))
        .catch(err => sendResponse({ success: false, error: err.message }));
    } else {
      sendResponse({ success: true });
    }
    return true;
  }
  });
}

/**
 * Handles end-to-end evaluation pipeline for an intercepted prompt text.
 */
async function handleAnalyzePrompt(payload) {
  const { promptText, destinationDomain = 'unknown' } = payload;
  const startTime = performance.now();

  // Retrieve user settings safely
  const settings = await getExtensionSettings();

  // 1. Run Regex Checks
  let regexMatches = [];
  if (settings.enableRegex !== false && typeof runRegexChecks === 'function') {
    regexMatches = runRegexChecks(promptText);
  }

  // 2. Run Local LLM Contextual Check (Gemini Nano)
  let llmResult = { sensitive: false, category: null, confidence: 0, skipped: true };
  if (settings.enableLLM !== false && typeof runLLMCheck === 'function') {
    llmResult = await runLLMCheck(promptText);
  }

  // 3. Compute Risk Score
  const riskAnalysis = calculateRiskScore({
    regexMatches: regexMatches,
    llmResult: llmResult,
    userRole: settings.userRole || 'engineering',
    destinationDomain: destinationDomain,
    customConfig: {
      roleWeights: settings.roleWeights,
      destinationTrust: settings.destinationTrust
    }
  });

  // 4. Evaluate Policy (Fixed Floor + Custom Admin Layer)
  // FIX: promptText passed in so policy.js can compute intelligent redaction
  const policyResult = evaluatePolicy({
    promptText: promptText,
    regexMatches: regexMatches,
    llmResult: llmResult,
    riskAnalysis: riskAnalysis,
    customPolicyConfig: {
      blockThreshold: settings.blockThreshold,
      redactThreshold: settings.redactThreshold
    }
  });

  // 5. Generate Explanation
  const explanation = generateExplanation(policyResult);

  const totalLatencyMs = Math.round(performance.now() - startTime);

  // 6. Save Full Detail Record to Local IndexedDB (No server transmission of raw prompt)
  const categories = [
    ...regexMatches.map(m => m.category),
    ...(llmResult && llmResult.sensitive ? [llmResult.category] : [])
  ].filter(Boolean);

  await logAuditRecord({
    timestamp: new Date().toISOString(),
    promptText: promptText,
    destinationDomain: destinationDomain,
    userRole: settings.userRole || 'engineering',
    riskScore: policyResult.riskScore,
    decision: policyResult.action,
    explanation: explanation,
    reasons: policyResult.reasons,
    categories: Array.from(new Set(categories)),
    fixedFloorTriggered: policyResult.fixedFloorTriggered,
    latencyMs: totalLatencyMs
  });

  // FIX: Return redactedText back to content.js
  return {
    action: policyResult.action,
    riskScore: policyResult.riskScore,
    explanation: explanation,
    reasons: policyResult.reasons,
    regexMatches: regexMatches,
    llmResult: llmResult,
    redactedText: policyResult.redactedText, // <--- Sent to content script
    fixedFloorTriggered: policyResult.fixedFloorTriggered,
    latencyMs: totalLatencyMs
  };
}

/**
 * Handles end-to-end evaluation pipeline for text extracted from an image attachment via on-device OCR.
 * Routes extracted text into the dual-tier inspection pipeline (Regex + LLM) and logs an audit record with sourceType: 'image_ocr'.
 * @param {Object} payload 
 * @param {string} payload.extractedText Text extracted by on-device OCR
 * @param {string} [payload.fileName='image.png'] Name of the image file
 * @param {string} [payload.destinationDomain='unknown'] Destination host
 * @returns {Promise<Object>}
 */
async function handleAnalyzeImageText(payload) {
  const { extractedText = '', fileName = 'image.png', destinationDomain = 'unknown' } = payload || {};
  const startTime = performance.now();

  const settings = await getExtensionSettings();

  // Pre-clean OCR recognition artifacts (spaces in emails, broken symbols)
  const cleanedText = (typeof cleanOcrText === 'function') 
    ? cleanOcrText(extractedText) 
    : (typeof globalThis !== 'undefined' && globalThis.cleanOcrText) 
      ? globalThis.cleanOcrText(extractedText) 
      : extractedText;

  // 1. Run Regex Checks
  let regexMatches = [];
  if (settings.enableRegex !== false && typeof runRegexChecks === 'function' && cleanedText) {
    regexMatches = runRegexChecks(cleanedText);
  }

  // 2. Run Local LLM Contextual Check (Gemini Nano) with short-circuit and focused window
  let llmResult = { sensitive: false, category: null, confidence: 0, skipped: true };
  const hasFixedFloorRegexHit = regexMatches.some(m => 
    m.category === 'credit_card' || m.category === 'api_key' || m.category === 'national_id' || m.category === 'pin_passcode' || m.category === 'database_url'
  );

  if (!hasFixedFloorRegexHit && settings.enableLLM !== false && typeof runLLMCheck === 'function' && cleanedText) {
    // Focus LLM input to the top 1500 characters (author metadata, headers, credential anchors) to prevent token bloat & timeouts
    const llmInput = cleanedText.length > 1500 ? cleanedText.slice(0, 1500) : cleanedText;
    llmResult = await runLLMCheck(llmInput);
  }

  // 3. Compute Risk Score
  const riskAnalysis = calculateRiskScore({
    regexMatches: regexMatches,
    llmResult: llmResult,
    userRole: settings.userRole || 'engineering',
    destinationDomain: destinationDomain,
    customConfig: {
      roleWeights: settings.roleWeights,
      destinationTrust: settings.destinationTrust
    }
  });

  // 4. Evaluate Policy
  const policyResult = evaluatePolicy({
    promptText: extractedText,
    regexMatches: regexMatches,
    llmResult: llmResult,
    riskAnalysis: riskAnalysis,
    fileName: fileName,
    customPolicyConfig: {
      blockThreshold: settings.blockThreshold,
      redactThreshold: settings.redactThreshold
    }
  });

  // 5. Generate Explanation
  const explanation = generateExplanation({ ...policyResult, fileName });
  const totalLatencyMs = Math.round(performance.now() - startTime);

  const categories = [
    ...regexMatches.map(m => m.category),
    ...(llmResult && llmResult.sensitive ? [llmResult.category] : [])
  ].filter(Boolean);

  // 6. Save Full Detail Record to Local IndexedDB with sourceType: 'image_ocr'
  if (typeof logAuditRecord === 'function') {
    await logAuditRecord({
      timestamp: new Date().toISOString(),
      promptText: `[IMAGE OCR: ${fileName}] ${extractedText.substring(0, 300)}`,
      destinationDomain: destinationDomain,
      userRole: settings.userRole || 'engineering',
      riskScore: policyResult.riskScore,
      decision: policyResult.action,
      explanation: explanation,
      reasons: policyResult.reasons,
      categories: Array.from(new Set(categories)),
      fixedFloorTriggered: policyResult.fixedFloorTriggered,
      latencyMs: totalLatencyMs,
      sourceType: 'image_ocr',
      fileName: fileName,
      fileType: fileName.split('.').pop()
    });
  }

  return {
    action: policyResult.action,
    riskScore: policyResult.riskScore,
    explanation: explanation,
    reasons: policyResult.reasons,
    regexMatches: regexMatches,
    llmResult: llmResult,
    fileName: fileName,
    sourceType: 'image_ocr',
    fixedFloorTriggered: policyResult.fixedFloorTriggered,
    latencyMs: totalLatencyMs
  };
}

let creatingOffscreenPromise = null;

/**
 * Ensures an Offscreen Document is active for running Web Workers / WebAssembly OCR
 * in a CSP-isolated environment unaffected by host page restrictions.
 */
async function setupOffscreenDocument(path = 'offscreen.html') {
  if (typeof chrome === 'undefined' || !chrome.offscreen || typeof chrome.offscreen.createDocument !== 'function') {
    return;
  }
  const offscreenUrl = chrome.runtime.getURL(path);

  if (typeof chrome.offscreen.hasDocument === 'function') {
    const hasDoc = await chrome.offscreen.hasDocument();
    if (hasDoc) return;
  } else if (chrome.runtime && typeof chrome.runtime.getContexts === 'function') {
    const contexts = await chrome.runtime.getContexts({
      contextTypes: ['OFFSCREEN_DOCUMENT'],
      documentUrls: [offscreenUrl]
    });
    if (contexts.length > 0) return;
  }

  if (creatingOffscreenPromise) {
    await creatingOffscreenPromise;
    return;
  }

  creatingOffscreenPromise = chrome.offscreen.createDocument({
    url: path,
    reasons: ['DOM_PARSER', 'BLOBS'],
    justification: 'Perform on-device Tesseract OCR in a CSP-isolated extension environment'
  }).catch((err) => {
    if (!err.message?.includes('Only a single offscreen document may be created')) {
      throw err;
    }
  }).finally(() => {
    creatingOffscreenPromise = null;
  });

  await creatingOffscreenPromise;
}

/**
 * Executes OCR on image data via the CSP-isolated Offscreen Document.
 * @param {string|Blob|ArrayBuffer} imageData 
 * @param {Object} options 
 * @returns {Promise<{text: string, confidence: number, words: Array, lines: Array}>}
 */
async function runOffscreenOcr(imageData, options = {}) {
  if (typeof chrome !== 'undefined' && chrome.offscreen && typeof chrome.offscreen.createDocument === 'function') {
    await setupOffscreenDocument('offscreen.html');
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        target: 'offscreen',
        type: 'OFFSCREEN_PERFORM_OCR',
        payload: { imageData, options }
      }, (response) => {
        if (chrome.runtime.lastError) {
          return reject(new Error(chrome.runtime.lastError.message));
        }
        if (!response || !response.success) {
          return reject(new Error(response?.error || 'OCR failed in offscreen document'));
        }
        resolve(response.data);
      });
    });
  }

  if (typeof extractTextFromImage === 'function') {
    return await extractTextFromImage(imageData, options);
  }

  throw new Error('TESSERACT_OCR_UNAVAILABLE: No OCR engine accessible in current context.');
}

/**
 * Handles end-to-end evaluation pipeline for an image attachment file.
 * Performs OCR via CSP-isolated Offscreen Document, evaluates regex & policy,
 * calculates bounding boxes, logs to audit storage, and enforces Fail-Closed policy on errors.
 */
async function handleAnalyzeImageFile(payload) {
  const { imageData, fileName = 'image.png', fileSize = 0, destinationDomain = 'unknown' } = payload || {};
  const startTime = performance.now();

  let ocrResult = null;
  let ocrError = null;

  try {
    ocrResult = await runOffscreenOcr(imageData);
  } catch (err) {
    ocrError = err;
    console.error(`[AI Governance] OCR extraction failed for '${fileName}':`, err);
  }

  // CRITICAL FAIL-CLOSED ENFORCEMENT:
  // If OCR failed or crashed, NEVER treat image as visual! Enforce Fail-Closed policy.
  if (ocrError || !ocrResult) {
    const errorReason = `Image OCR failed (${ocrError ? ocrError.message : 'Unknown OCR failure'})`;
    return handleAnalyzeFile({
      extractedData: {
        fileName,
        fileType: fileName.split('.').pop() || 'png',
        fileSize,
        text: '',
        chunks: [],
        unscannable: true,
        reason: errorReason
      },
      destinationDomain
    });
  }

  const extractedText = (ocrResult.text || '').trim();
  const confidence = typeof ocrResult.confidence === 'number' ? ocrResult.confidence : 0;

  // Purely visual image check: OCR successfully ran and genuinely detected NO text
  if (extractedText.length === 0 || (confidence < 30 && extractedText.length === 0)) {
    return {
      action: 'allow',
      riskScore: 0,
      isVisualImage: true,
      fileName,
      explanation: 'No readable text detected in image (purely visual image).',
      reasons: [],
      ocrResult,
      latencyMs: Math.round(performance.now() - startTime)
    };
  }

  // Text was detected inside the image - analyze with full governance engine
  const analysisResult = await handleAnalyzeImageText({
    extractedText,
    fileName,
    destinationDomain
  });

  // Calculate redaction bounding boxes using Tesseract word/line coordinates
  const redactionBoxes = (typeof calculateRedactionBoxes === 'function')
    ? calculateRedactionBoxes(analysisResult.regexMatches || [], ocrResult)
    : [];

  return {
    ...analysisResult,
    ocrResult,
    redactionBoxes
  };
}

/**
 * Handles end-to-end evaluation pipeline for an attached file document.
 */
async function handleAnalyzeFile(payload) {
  const { extractedData = {}, destinationDomain = 'unknown' } = payload;
  const { fileName = 'unknown_file', text = '', chunks = [], unscannable = false, reason = '', isFolderOrDirectory = false } = extractedData;
  const startTime = performance.now();

  // Directory container or virtual shelf item check (e.g. 'Downloads')
  if (isFolderOrDirectory || (fileName.toLowerCase() === 'downloads' && (!text || text.length === 0))) {
    return {
      action: 'allow',
      riskScore: 0,
      fileName,
      explanation: 'Skipping directory or virtual container.',
      reasons: [],
      isFolderOrDirectory: true,
      latencyMs: 1
    };
  }

  // 1. Cryptographic File Deduplication (SHA-256 Cache Check < 5ms)
  // ONLY hash valid non-empty extracted text content (NEVER fall back to fileName!)
  const fileHash = (text && typeof text === 'string' && text.trim().length > 0 && !unscannable) 
    ? await computeSHA256Hash(text) 
    : null;

  if (fileHash && typeof getFileHashCache === 'function') {
    const cached = await getFileHashCache(fileHash);
    if (cached) {
      console.log(`[AI Governance Perf] SHA-256 Cache Hit (< 5ms) for '${fileName}' (Hash: ${fileHash.substring(0, 8)}...). Returning cached decision.`);
      const totalLatencyMs = Math.round(performance.now() - startTime);
      return {
        action: cached.decision,
        riskScore: cached.riskScore,
        explanation: `[CACHED RESULT] ${cached.explanation || 'File evaluated previously.'}`,
        reasons: cached.reasons || [],
        fileName: fileName,
        unscannable: cached.unscannable,
        fixedFloorTriggered: cached.fixedFloorTriggered,
        cached: true,
        latencyMs: totalLatencyMs
      };
    }
  }

  const settings = await getExtensionSettings();

  let regexMatches = [];
  let chunkLLMResults = [];

  // If unscannable (e.g. image format / encrypted), enforce Fail-Closed policy immediately
  if (unscannable) {
    const riskAnalysis = calculateRiskScore({
      regexMatches: [],
      chunkLLMResults: [],
      userRole: settings.userRole || 'engineering',
      destinationDomain: destinationDomain,
      unscannable: true
    });

    const policyResult = evaluatePolicy({
      regexMatches: [],
      chunkLLMResults: [],
      unscannable: true,
      fileName: fileName,
      unscannableReason: reason,
      riskAnalysis: riskAnalysis,
      customPolicyConfig: { blockThreshold: settings.blockThreshold, redactThreshold: settings.redactThreshold }
    });

    const explanation = generateExplanation({ ...policyResult, fileName });
    const totalLatencyMs = Math.round(performance.now() - startTime);

    const result = {
      action: policyResult.action,
      riskScore: policyResult.riskScore,
      explanation: explanation,
      reasons: policyResult.reasons,
      fileName: fileName,
      unscannable: true,
      fixedFloorTriggered: policyResult.fixedFloorTriggered,
      latencyMs: totalLatencyMs
    };

    if (fileHash && typeof saveFileHashCache === 'function') {
      await saveFileHashCache({ hash: fileHash, ...result });
    }

    await logAuditRecord({
      timestamp: new Date().toISOString(),
      promptText: `[FILE ATTACHMENT: ${fileName}] (Unscannable: ${reason})`,
      destinationDomain: destinationDomain,
      userRole: settings.userRole || 'engineering',
      riskScore: policyResult.riskScore,
      decision: policyResult.action,
      explanation: explanation,
      reasons: policyResult.reasons,
      categories: ['unscannable_file'],
      fixedFloorTriggered: policyResult.fixedFloorTriggered,
      latencyMs: totalLatencyMs
    });

    return result;
  }

  // 1. Run Regex across full document text in ONE pass
  if (settings.enableRegex !== false && typeof runRegexChecks === 'function' && text) {
    regexMatches = runRegexChecks(text);
  }

  // SHORT-CIRCUIT OPTIMIZATION: If full-text regex triggered a Fixed Floor category (Credit Card, API key, SSN, PIN),
  // stop processing immediately and return block decision without creating an LLM session!
  const hasFixedFloorRegexHit = regexMatches.some(m => 
    m.category === 'credit_card' || m.category === 'api_key' || m.category === 'national_id' || m.category === 'pin_passcode'
  );

  if (hasFixedFloorRegexHit) {
    console.log(`[AI Governance Perf] Short-circuit: Fixed Floor Regex match found in full document. Skipping LLM chunk processing.`);
    
    const riskAnalysis = calculateRiskScore({
      regexMatches: regexMatches,
      chunkLLMResults: [],
      userRole: settings.userRole || 'engineering',
      destinationDomain: destinationDomain,
      unscannable: false
    });

    const policyResult = evaluatePolicy({
      regexMatches: regexMatches,
      chunkLLMResults: [],
      unscannable: false,
      fileName: fileName,
      riskAnalysis: riskAnalysis,
      customPolicyConfig: { blockThreshold: settings.blockThreshold, redactThreshold: settings.redactThreshold }
    });

    const explanation = generateExplanation({ ...policyResult, fileName });
    const totalLatencyMs = Math.round(performance.now() - startTime);

    const result = {
      action: policyResult.action,
      riskScore: policyResult.riskScore,
      explanation: explanation,
      reasons: policyResult.reasons,
      fileName: fileName,
      regexMatches: regexMatches,
      chunkLLMResults: [],
      fixedFloorTriggered: policyResult.fixedFloorTriggered,
      latencyMs: totalLatencyMs
    };

    if (fileHash && typeof saveFileHashCache === 'function') {
      await saveFileHashCache({ hash: fileHash, ...result });
    }

    await logAuditRecord({
      timestamp: new Date().toISOString(),
      promptText: `[FILE ATTACHMENT: ${fileName}] Extracted Text Snippet: "${text.substring(0, 150)}..."`,
      destinationDomain: destinationDomain,
      userRole: settings.userRole || 'engineering',
      riskScore: policyResult.riskScore,
      decision: policyResult.action,
      explanation: explanation,
      reasons: policyResult.reasons,
      categories: Array.from(new Set(regexMatches.map(m => m.category))),
      fixedFloorTriggered: policyResult.fixedFloorTriggered,
      latencyMs: totalLatencyMs
    });

    return result;
  }

  // 2. Run Local LLM across document chunks sequentially REUSING ONE SESSION
  if (settings.enableLLM !== false && Array.isArray(chunks) && chunks.length > 0) {
    if (typeof runMultiChunkLLMCheck === 'function') {
      chunkLLMResults = await runMultiChunkLLMCheck(chunks);
    } else if (typeof runLLMCheck === 'function') {
      for (const chunk of chunks) {
        if (chunk.text && chunk.text.trim()) {
          const chunkRes = await runLLMCheck(chunk.text);
          chunkLLMResults.push({ ...chunkRes, chunkIndex: chunk.chunkIndex });
          if (chunkRes.sensitive && chunkRes.confidence >= 0.85) break;
        }
      }
    }
  }

  // 3. Compute Combined Risk Score (MAX strategy)
  const riskAnalysis = calculateRiskScore({
    regexMatches: regexMatches,
    chunkLLMResults: chunkLLMResults,
    userRole: settings.userRole || 'engineering',
    destinationDomain: destinationDomain,
    unscannable: false
  });

  // 4. Evaluate Policy
  const policyResult = evaluatePolicy({
    regexMatches: regexMatches,
    chunkLLMResults: chunkLLMResults,
    unscannable: false,
    fileName: fileName,
    riskAnalysis: riskAnalysis,
    customPolicyConfig: { blockThreshold: settings.blockThreshold, redactThreshold: settings.redactThreshold }
  });

  // 5. Generate Explanation
  const explanation = generateExplanation({ ...policyResult, fileName });
  const totalLatencyMs = Math.round(performance.now() - startTime);

  const categories = [
    ...regexMatches.map(m => m.category),
    ...chunkLLMResults.filter(c => c.sensitive).map(c => c.category)
  ].filter(Boolean);

  const result = {
    action: policyResult.action,
    riskScore: policyResult.riskScore,
    explanation: explanation,
    reasons: policyResult.reasons,
    fileName: fileName,
    regexMatches: regexMatches,
    chunkLLMResults: chunkLLMResults,
    fixedFloorTriggered: policyResult.fixedFloorTriggered,
    latencyMs: totalLatencyMs
  };

  if (fileHash && text && text.trim().length > 0 && !unscannable && typeof saveFileHashCache === 'function') {
    await saveFileHashCache({ hash: fileHash, ...result });
  }

  await logAuditRecord({
    timestamp: new Date().toISOString(),
    promptText: `[FILE ATTACHMENT: ${fileName}] Extracted Text Snippet: "${text.substring(0, 150)}..."`,
    destinationDomain: destinationDomain,
    userRole: settings.userRole || 'engineering',
    riskScore: policyResult.riskScore,
    decision: policyResult.action,
    explanation: explanation,
    reasons: policyResult.reasons,
    categories: Array.from(new Set(categories)),
    fixedFloorTriggered: policyResult.fixedFloorTriggered,
    latencyMs: totalLatencyMs
  });

  return result;
}

/**
 * Handles asymmetric parallel ingestion and fast-fail evaluation for multiple uploaded files.
 */
async function handleAnalyzeBatchFiles(payload) {
  const { files = [], destinationDomain = 'unknown' } = payload;
  const startTime = performance.now();

  // Filter out any directory markers or virtual folder containers from the batch
  const filesToAnalyze = (files || []).filter(f => {
    const d = f.extractedData || f;
    return !d.isFolderOrDirectory && !(d.fileName?.toLowerCase() === 'downloads' && (d.fileSize === 0 || !d.text));
  });

  if (!Array.isArray(filesToAnalyze) || filesToAnalyze.length === 0) {
    return { action: 'allow', riskScore: 0, fileResults: [], totalLatencyMs: 0 };
  }

  // Phase 1: Parallel Ingestion & SHA-256 Deduplication + Fast-Path Regex Check across ALL files
  const phase1Results = await Promise.all(filesToAnalyze.map(async (fileData) => {
    return handleAnalyzeFile({ extractedData: fileData.extractedData || fileData, destinationDomain });
  }));

  // SHORT-CIRCUIT FAST-FAIL: If ANY file in the batch returns a BLOCK decision,
  // return the forced block decision immediately!
  const blockedFile = phase1Results.find(r => r.action === 'block');
  if (blockedFile) {
    console.log(`[AI Governance Perf] Multi-File Batch Fast-Fail: File '${blockedFile.fileName}' triggered BLOCK. Halting remaining batch processing.`);
    return {
      action: 'block',
      riskScore: Math.max(...phase1Results.map(r => r.riskScore || 0)),
      explanation: blockedFile.explanation,
      reasons: blockedFile.reasons,
      fileResults: phase1Results,
      totalLatencyMs: Math.round(performance.now() - startTime)
    };
  }

  const maxRiskScore = Math.max(...phase1Results.map(r => r.riskScore || 0), 0);
  const requiresRedact = phase1Results.some(r => r.action === 'redact');

  return {
    action: requiresRedact ? 'redact' : 'allow',
    riskScore: maxRiskScore,
    explanation: phase1Results.map(r => `${r.fileName}: ${r.explanation}`).join(' | '),
    reasons: Array.from(new Set(phase1Results.flatMap(r => r.reasons || []))),
    fileResults: phase1Results,
    totalLatencyMs: Math.round(performance.now() - startTime)
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    handleAnalyzePrompt,
    handleAnalyzeFile,
    handleAnalyzeBatchFiles,
    handleAnalyzeImageText,
    handleAnalyzeImageFile,
    runOffscreenOcr,
    setupOffscreenDocument
  };
}