/**
 * background.js
 * 
 * Manifest V3 Background Service Worker.
 * Acts as the centralized coordinator for prompt scanning requests, storage management,
 * on-device detection execution, and local IndexedDB audit logging.
 */

// Load detection engines, policy layers, and local audit storage
try {
  importScripts(
    'detectors/regex.js',
    'detectors/llm.js',
    'engine/risk-score.js',
    'engine/policy.js',
    'engine/explain.js',
    'storage/audit.js'
  );
} catch (err) {
  console.error('[AI Governance] Background service worker failed to import script dependencies:', err);
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

// Initialize settings on extension install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(DEFAULT_SETTINGS, (stored) => {
    chrome.storage.local.set(stored, () => {
      console.log('[AI Governance] Service worker installed & policy storage initialized.');
    });
  });
});

// Central runtime message listener
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
});

/**
 * Handles end-to-end evaluation pipeline for an intercepted prompt text.
 */
async function handleAnalyzePrompt(payload) {
  const { promptText, destinationDomain = 'unknown' } = payload;
  const startTime = performance.now();

  // Retrieve user settings from chrome.storage.local
  const settings = await new Promise((resolve) => {
    chrome.storage.local.get(DEFAULT_SETTINGS, (data) => resolve(data));
  });

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
 * Handles end-to-end evaluation pipeline for an attached file document.
 */
async function handleAnalyzeFile(payload) {
  const { extractedData = {}, destinationDomain = 'unknown' } = payload;
  const { fileName = 'unknown_file', text = '', chunks = [], unscannable = false, reason = '' } = extractedData;
  const startTime = performance.now();

  const settings = await new Promise((resolve) => {
    chrome.storage.local.get(DEFAULT_SETTINGS, (data) => resolve(data));
  });

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

    return {
      action: policyResult.action,
      riskScore: policyResult.riskScore,
      explanation: explanation,
      reasons: policyResult.reasons,
      fileName: fileName,
      unscannable: true,
      fixedFloorTriggered: policyResult.fixedFloorTriggered,
      latencyMs: totalLatencyMs
    };
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

    return {
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
          if (chunkRes.sensitive && chunkRes.confidence >= 0.8) break;
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

  return {
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
}