/**
 * eval/eval-runner.js
 * 
 * In-browser evaluation script that executes benchmark runs over test-set.json.
 * Supports ablation mode (Pass 1: Regex Only vs Pass 2: Hybrid Regex + On-Device Gemini Nano),
 * records timing latency, and produces downloadable result JSON payloads.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const promptStatusEl = document.getElementById('prompt-api-status');
  const btnRunRegexOnly = document.getElementById('btn-run-regex-only');
  const btnRunHybrid = document.getElementById('btn-run-hybrid');
  const btnDownloadRegex = document.getElementById('btn-download-regex');
  const btnDownloadHybrid = document.getElementById('btn-download-hybrid');

  const progressBar = document.getElementById('progress-bar');
  const progressStatus = document.getElementById('progress-status');
  const evalConsole = document.getElementById('eval-console');

  let testSet = [];
  let resultsRegexOnly = null;
  let resultsHybrid = null;

  // Check Prompt API Status
  if (typeof checkPromptAPIAvailability === 'function') {
    const avail = await checkPromptAPIAvailability();
    promptStatusEl.textContent = `Prompt API: ${avail}`;
    logConsole(`Prompt API Availability Status: ${avail}`);
  }

  // Load Test Set JSON
  try {
    const response = await fetch('test-set.json');
    testSet = await response.json();
    logConsole(`Loaded ${testSet.length} synthetic test prompts from test-set.json.`);
  } catch (err) {
    logConsole(`Error loading test-set.json: ${err.message}`);
  }

  // Button Listeners
  btnRunRegexOnly.addEventListener('click', () => runEvaluationPass(false));
  btnRunHybrid.addEventListener('click', () => runEvaluationPass(true));

  btnDownloadRegex.addEventListener('click', () => downloadJSON(resultsRegexOnly, 'results-regex-only.json'));
  btnDownloadHybrid.addEventListener('click', () => downloadJSON(resultsHybrid, 'results-regex-llm.json'));

  /**
   * Executes evaluation pipeline across the test set.
   * @param {boolean} enableLLM 
   */
  async function runEvaluationPass(enableLLM) {
    if (!testSet || testSet.length === 0) {
      logConsole('Error: Test set is empty.');
      return;
    }

    const passName = enableLLM ? 'Hybrid (Regex + Gemini Nano)' : 'Regex Only';
    logConsole(`\n=== Starting Benchmark Pass: ${passName} ===`);

    btnRunRegexOnly.disabled = true;
    btnRunHybrid.disabled = true;

    const results = [];
    const total = testSet.length;

    for (let i = 0; i < total; i++) {
      const item = testSet[i];
      const percent = Math.round(((i + 1) / total) * 100);
      progressBar.style.width = `${percent}%`;
      progressStatus.textContent = `Processing item ${i + 1} of ${total} (${percent}%) - ID: ${item.id}`;

      const itemStartTime = performance.now();

      // 1. Run Regex
      const regexMatches = runRegexChecks(item.text);

      // 2. Run LLM (if enabled)
      let llmResult = { sensitive: false, category: null, confidence: 0, skipped: true, latencyMs: 0 };
      if (enableLLM && typeof runLLMCheck === 'function') {
        llmResult = await runLLMCheck(item.text);
      }

      // 3. Compute Risk Score & Policy Decision
      const riskAnalysis = calculateRiskScore({
        regexMatches: regexMatches,
        llmResult: llmResult,
        userRole: 'engineering',
        destinationDomain: 'chatgpt.com'
      });

      const policyResult = evaluatePolicy({
        regexMatches: regexMatches,
        llmResult: llmResult,
        riskAnalysis: riskAnalysis,
        customPolicyConfig: { blockThreshold: 75, redactThreshold: 45 }
      });

      const totalItemTime = Math.round(performance.now() - itemStartTime);

      results.push({
        id: item.id,
        text: item.text,
        ground_truth_sensitive: item.is_sensitive,
        ground_truth_category: item.category,
        predicted_action: policyResult.action,
        riskScore: policyResult.riskScore,
        regex_hits_count: regexMatches.length,
        llm_sensitive: llmResult.sensitive,
        llm_confidence: llmResult.confidence,
        llm_category: llmResult.category,
        llm_skipped: llmResult.skipped,
        llm_latency_ms: llmResult.latencyMs || 0,
        total_latency_ms: totalItemTime
      });

      logConsole(`[${item.id}] Truth: ${item.is_sensitive ? 'SENSITIVE' : 'BENIGN'} | Action: ${policyResult.action.toUpperCase()} | Score: ${policyResult.riskScore} | Time: ${totalItemTime}ms`);
    }

    logConsole(`=== Completed Pass: ${passName} (${total} items processed) ===\n`);

    if (enableLLM) {
      resultsHybrid = results;
      btnDownloadHybrid.disabled = false;
    } else {
      resultsRegexOnly = results;
      btnDownloadRegex.disabled = false;
    }

    btnRunRegexOnly.disabled = false;
    btnRunHybrid.disabled = false;
    progressStatus.textContent = `Completed ${passName} pass! Download result JSON above.`;
  }

  function downloadJSON(data, filename) {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function logConsole(msg) {
    evalConsole.textContent += `${msg}\n`;
    evalConsole.scrollTop = evalConsole.scrollHeight;
  }
});
