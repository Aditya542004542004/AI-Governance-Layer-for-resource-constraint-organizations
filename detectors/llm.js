/**
 * detectors/llm.js
 * 
 * Intercepts prompt text and performs contextual semantic sensitivity checks
 * using Chrome's built-in on-device Gemini Nano (LanguageModel Prompt API).
 * Runs completely locally on the user's browser device with zero API keys or network calls.
 * Gracefully falls back if Chrome Prompt API is unsupported or disabled.
 */

/**
 * Checks availability of Chrome's built-in Prompt API.
 * @returns {Promise<string>} 'readily' | 'after-download' | 'no' | 'unavailable'
 */
async function checkPromptAPIAvailability() {
  try {
    if (typeof LanguageModel !== 'undefined' && typeof LanguageModel.availability === 'function') {
      const avail = await LanguageModel.availability();
      return typeof avail === 'string' ? avail : (avail.available ? 'readily' : 'no');
    }
    if (typeof ai !== 'undefined' && ai.languageModel && typeof ai.languageModel.capabilities === 'function') {
      const caps = await ai.languageModel.capabilities();
      return caps.available || 'no';
    }
    return 'unavailable';
  } catch (err) {
    console.warn('[AI Governance] Error checking Prompt API availability:', err);
    return 'unavailable';
  }
}

/**
 * Robust JSON parser that handles markdown backticks, conversational preamble,
 * and fixes negative false-positives.
 */
function extractAndParseJSON(responseText) {
  if (!responseText || typeof responseText !== 'string') return null;

  // 1. Try direct parse on cleaned string
  const cleaned = responseText.replace(/```json/gi, '').replace(/```/g, '').trim();
  try {
    return JSON.parse(cleaned);
  } catch (_) {}

  // 2. Extract first outer JSON object { ... }
  const jsonMatch = responseText.match(/\{[\s\S]*?\}/);
  if (jsonMatch) {
    try {
      return JSON.parse(jsonMatch[0]);
    } catch (_) {}
  }

  // 3. Resilient Heuristic Fallback (Avoid false positives on "not sensitive")
  const lower = responseText.toLowerCase();
  
  // Detect explicit negative statements from Gemini Nano
  const isExplicitlySafe = 
    lower.includes('does not contain any sensitive') ||
    lower.includes('not considered to contain') ||
    lower.includes('not sensitive') ||
    lower.includes('no sensitive data') ||
    lower.includes('low-risk');

  if (isExplicitlySafe) {
    return {
      sensitive: false,
      category: null,
      confidence: 0.0
    };
  }

  // Check for explicit positive assertions
  const isExplicitlySensitive = 
    lower.includes('contains sensitive information') ||
    lower.includes('contains an api key') ||
    lower.includes('security risk') ||
    lower.includes('confidential');

  return {
    sensitive: isExplicitlySensitive,
    category: isExplicitlySensitive ? 'confidential_context' : null,
    confidence: isExplicitlySensitive ? 0.85 : 0.0
  };
}

/**
 * Analyzes prompt text contextually using Chrome's on-device Gemini Nano.
 * @param {string} text - Prompt text to analyze
 * @returns {Promise<{sensitive: boolean, category: string|null, confidence: number, skipped: boolean, reason?: string, latencyMs?: number}>}
 */
async function runLLMCheck(text) {
  const startTime = performance.now();

  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return {
      sensitive: false,
      category: null,
      confidence: 0,
      skipped: true,
      reason: 'Empty prompt text',
      latencyMs: 0
    };
  }

  const availability = await checkPromptAPIAvailability();

  // If Prompt API is not available or disabled in Chrome flags, fall back safely
  if (availability === 'no' || availability === 'unavailable') {
    console.warn(`[AI Governance] Local LLM check skipped (Prompt API status: ${availability}). Falling back to Regex-only.`);
    return {
      sensitive: false,
      category: null,
      confidence: 0,
      skipped: true,
      reason: `Prompt API unavailable (${availability})`,
      latencyMs: performance.now() - startTime
    };
  }

  let session = null;
  try {
    const systemPrompt = `You are a strict data security auditor running locally on-device.
Analyze the input text for confidential, medical (PHI), personal identity (PII), corporate proprietary secrets, credentials, or private financial data.
Respond ONLY with a valid JSON object. No explanation, no markdown backticks, no commentary.`;

    // Using few-shot initialPrompts forces Gemini Nano to reply with raw JSON
    const sessionOptions = {
      systemPrompt: systemPrompt,
      initialPrompts: [
        { 
          role: 'user', 
          content: 'Analyze prompt: "Hi, can you explain what photosyntheses is?"' 
        },
        { 
          role: 'assistant', 
          content: '{"sensitive": false, "category": null, "confidence": 0.0}' 
        },
        { 
          role: 'user', 
          content: 'Analyze prompt: "this is API Key - 62755573sffsjd"' 
        },
        { 
          role: 'assistant', 
          content: '{"sensitive": true, "category": "proprietary", "confidence": 0.95}' 
        }
      ]
    };

    if (typeof LanguageModel !== 'undefined' && typeof LanguageModel.create === 'function') {
      session = await LanguageModel.create(sessionOptions);
    } else if (typeof ai !== 'undefined' && ai.languageModel && typeof ai.languageModel.create === 'function') {
      session = await ai.languageModel.create(sessionOptions);
    }

    if (!session) {
      throw new Error('Failed to instantiate LanguageModel session');
    }

    const userPrompt = `Analyze prompt: "${text}"`;
    const responseText = await session.prompt(userPrompt);
    const latencyMs = performance.now() - startTime;

    // Parse with resilient extractor
    const parsedResult = extractAndParseJSON(responseText);

    return {
      sensitive: Boolean(parsedResult.sensitive),
      category: parsedResult.category || (parsedResult.sensitive ? 'confidential_context' : null),
      confidence: typeof parsedResult.confidence === 'number' ? parsedResult.confidence : (parsedResult.sensitive ? 0.8 : 0.0),
      skipped: false,
      latencyMs: Math.round(latencyMs)
    };

  } catch (err) {
    console.error('[AI Governance] Error during local LLM execution:', err);
    return {
      sensitive: false,
      category: null,
      confidence: 0,
      skipped: true,
      reason: err.message || 'LLM execution exception',
      latencyMs: Math.round(performance.now() - startTime)
    };
  } finally {
    // Destroy session after use to immediately reclaim GPU/RAM memory
    if (session && typeof session.destroy === 'function') {
      try {
        session.destroy();
      } catch (destroyErr) {
        // Ignore session teardown warnings
      }
    }
  }
}

/**
 * Helper to wrap session.prompt with a strict timeout (default 3000ms).
 */
function promptWithTimeout(session, promptText, timeoutMs = 3000) {
  return Promise.race([
    session.prompt(promptText),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`LLM prompt execution timed out (${timeoutMs}ms)`)), timeoutMs))
  ]);
}

/**
 * Creates ONE LanguageModel session and reuses it across multiple document chunks.
 * Integrates Heuristic Gatekeeper triage, 3-second per-chunk timeout, 2-chunk cap,
 * and early exit on high-confidence detection.
 * @param {Array<{chunkIndex: number, text: string}>} chunks 
 * @returns {Promise<Array<Object>>}
 */
async function runMultiChunkLLMCheck(chunks = []) {
  if (!Array.isArray(chunks) || chunks.length === 0) {
    return [];
  }

  const results = [];
  const candidateChunks = [];

  // 1. Phase 1 Heuristic Gatekeeper Triage (Shannon Entropy & Keyword Anchors)
  const triageCheckFn = typeof isChunkTriagedForLLM === 'function' 
    ? isChunkTriagedForLLM 
    : (typeof globalThis !== 'undefined' && globalThis.isChunkTriagedForLLM) 
      ? globalThis.isChunkTriagedForLLM 
      : null;

  for (const chunk of chunks) {
    const isTriaged = triageCheckFn ? triageCheckFn(chunk.text) : true;
    if (!isTriaged) {
      // Chunk is clean: bypass LLM inference completely
      results.push({
        chunkIndex: chunk.chunkIndex,
        sensitive: false,
        category: null,
        confidence: 0,
        skipped: true,
        reason: 'Passed heuristic gatekeeper (clean)'
      });
    } else {
      candidateChunks.push(chunk);
    }
  }

  // If no chunks require LLM inference, return early
  if (candidateChunks.length === 0) {
    console.log(`[AI Governance Perf] Heuristic Gatekeeper cleared all ${chunks.length} chunks. Bypassing Prompt API LLM completely.`);
    return results;
  }

  const availability = await checkPromptAPIAvailability();
  if (availability === 'no' || availability === 'unavailable') {
    console.warn(`[AI Governance Perf] Prompt API unavailable (${availability}). Multi-chunk check skipped for candidate chunks.`);
    candidateChunks.forEach(c => {
      results.push({
        chunkIndex: c.chunkIndex,
        sensitive: false,
        category: null,
        confidence: 0,
        skipped: true,
        reason: `Prompt API unavailable (${availability})`
      });
    });
    return results;
  }

  // Performance cap: Evaluate at most 2 candidate chunks via LLM to prevent long stalls
  const chunksToProcess = candidateChunks.slice(0, 2);

  const sessionStart = performance.now();
  let session = null;

  try {
    const systemPrompt = `You are a strict data security auditor running locally on-device.
Analyze the input text for confidential, medical (PHI), personal identity (PII), corporate proprietary secrets, credentials, or private financial data.
Respond ONLY with a valid JSON object. No explanation, no markdown backticks, no commentary.`;

    const sessionOptions = {
      systemPrompt: systemPrompt,
      initialPrompts: [
        { role: 'user', content: 'Analyze prompt: "Hi, can you explain what photosyntheses is?"' },
        { role: 'assistant', content: '{"sensitive": false, "category": null, "confidence": 0.0}' },
        { role: 'user', content: 'Analyze prompt: "this is API Key - 62755573sffsjd"' },
        { role: 'assistant', content: '{"sensitive": true, "category": "proprietary", "confidence": 0.95}' }
      ]
    };

    if (typeof LanguageModel !== 'undefined' && typeof LanguageModel.create === 'function') {
      session = await LanguageModel.create(sessionOptions);
    } else if (typeof ai !== 'undefined' && ai.languageModel && typeof ai.languageModel.create === 'function') {
      session = await ai.languageModel.create(sessionOptions);
    }

    const sessionTimeMs = Math.round(performance.now() - sessionStart);
    console.log(`[AI Governance Perf] LanguageModel Session Creation: ${sessionTimeMs} ms (Session reused across ${chunksToProcess.length} candidate chunks out of ${chunks.length} total)`);

    if (!session) {
      throw new Error('Failed to instantiate LanguageModel session');
    }

    for (let i = 0; i < chunksToProcess.length; i++) {
      const chunk = chunksToProcess[i];
      const chunkStart = performance.now();

      let responseText = null;
      try {
        responseText = await promptWithTimeout(session, `Analyze prompt: "${chunk.text}"`, 3000);
      } catch (timeoutErr) {
        console.warn(`[AI Governance Perf] Chunk ${i + 1}/${chunksToProcess.length} timed out after 3000ms. Skipping remaining LLM inference.`);
        results.push({
          chunkIndex: chunk.chunkIndex,
          sensitive: false,
          category: null,
          confidence: 0,
          skipped: true,
          reason: 'LLM prompt inference timed out (3000ms limit)'
        });
        break; // Exit candidate loop on timeout
      }

      const chunkInferenceMs = Math.round(performance.now() - chunkStart);
      const parsedResult = extractAndParseJSON(responseText);

      const chunkResult = {
        chunkIndex: chunk.chunkIndex,
        sensitive: Boolean(parsedResult ? parsedResult.sensitive : false),
        category: parsedResult ? (parsedResult.category || (parsedResult.sensitive ? 'confidential_context' : null)) : null,
        confidence: parsedResult ? (typeof parsedResult.confidence === 'number' ? parsedResult.confidence : (parsedResult.sensitive ? 0.85 : 0.0)) : 0,
        skipped: false,
        latencyMs: chunkInferenceMs
      };

      console.log(`[AI Governance Perf] Chunk ${i + 1}/${chunksToProcess.length} Inference: ${chunkInferenceMs} ms | Sensitive: ${chunkResult.sensitive} | Confidence: ${chunkResult.confidence}`);

      results.push(chunkResult);

      // EARLY EXIT Optimization: If candidate chunk returns sensitive with confidence >= 0.85, abort remaining chunk evaluations immediately!
      if (chunkResult.sensitive && chunkResult.confidence >= 0.85) {
        console.log(`[AI Governance Perf] Early Exit triggered on chunk ${i + 1}/${chunksToProcess.length} (Confidence: ${chunkResult.confidence}). Halting remaining chunk evaluations.`);
        break;
      }
    }

  } catch (err) {
    console.error('[AI Governance Perf] Error in runMultiChunkLLMCheck (graceful fallback active):', err);
    // Graceful fallback for remaining candidate chunks
    candidateChunks.forEach(c => {
      if (!results.some(r => r.chunkIndex === c.chunkIndex)) {
        results.push({
          chunkIndex: c.chunkIndex,
          sensitive: false,
          category: null,
          confidence: 0,
          skipped: true,
          reason: err.message || 'LLM execution exception'
        });
      }
    });
  } finally {
    if (session && typeof session.destroy === 'function') {
      try { session.destroy(); } catch (_) {}
    }
  }

  return results;
}

// Universal Export Wrapper for Node.js, Web Worker, and Browser Contexts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { runLLMCheck, runMultiChunkLLMCheck, checkPromptAPIAvailability };
}
if (typeof globalThis !== 'undefined') {
  globalThis.runLLMCheck = runLLMCheck;
  globalThis.runMultiChunkLLMCheck = runMultiChunkLLMCheck;
  globalThis.checkPromptAPIAvailability = checkPromptAPIAvailability;
}
if (typeof self !== 'undefined') {
  self.runLLMCheck = runLLMCheck;
  self.runMultiChunkLLMCheck = runMultiChunkLLMCheck;
  self.checkPromptAPIAvailability = checkPromptAPIAvailability;
}