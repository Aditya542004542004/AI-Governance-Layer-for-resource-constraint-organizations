/**
 * content.js
 * 
 * Injected content script targeting ChatGPT, Gemini, and Claude web interfaces.
 * Intercepts prompt submission AND file attachments (<input type="file"> & drag-and-drop),
 * extracts text client-side, evaluates governance policy pre-flight, and enforces guardrails inline.
 * Includes direct in-page execution fallback if background service worker is idle or reloaded.
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__AI_GOVERNANCE_INJECTED__) {
    return;
  }
  window.__AI_GOVERNANCE_INJECTED__ = true;

  let isBypassingInterception = false;
  let lastProcessedPrompt = '';
  let lastProcessedTime = 0;

  console.log('[AI Governance] Content script active with File Upload Governance on:', window.location.hostname);

  /**
   * Locates the active AI prompt input box based on domain-specific selectors.
   * @returns {HTMLElement|null}
   */
  function findPromptInput() {
    const hostname = window.location.hostname;

    if (hostname.includes('chatgpt.com') || hostname.includes('openai.com')) {
      return document.querySelector('#prompt-textarea') ||
             document.querySelector('textarea[tabindex="0"]') ||
             document.querySelector('div[contenteditable="true"]');
    }

    if (hostname.includes('gemini.google.com')) {
      return document.querySelector('div[contenteditable="true"]') ||
             document.querySelector('.input-area textarea') ||
             document.querySelector('textarea');
    }

    if (hostname.includes('claude.ai')) {
      return document.querySelector('div[contenteditable="true"]') ||
             document.querySelector('fieldset div[contenteditable="true"]');
    }

    // Fallback search
    return document.querySelector('textarea') || document.querySelector('div[contenteditable="true"]');
  }

  function findSendButton() {
    const hostname = window.location.hostname;
    if (hostname.includes('chatgpt.com') || hostname.includes('openai.com')) {
      return document.querySelector('button[data-testid="send-button"]') ||
             document.querySelector('button[data-testid="submit-button"]');
    }
    if (hostname.includes('gemini.google.com')) {
      return document.querySelector('button.send-button') ||
             document.querySelector('button[aria-label*="Send"]');
    }
    if (hostname.includes('claude.ai')) {
      return document.querySelector('button[aria-label*="Send"]') ||
             document.querySelector('button[aria-label*="send"]');
    }
    return document.querySelector('button[type="submit"]');
  }

  function getInputValue(element) {
    if (!element) return '';
    if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
      return element.value || '';
    }
    return element.innerText || element.textContent || '';
  }

  function setInputValue(element, newValue) {
    if (!element) return;
    if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
      element.value = newValue;
      element.dispatchEvent(new Event('input', { bubbles: true }));
      element.dispatchEvent(new Event('change', { bubbles: true }));
    } else if (element.isContentEditable) {
      element.innerText = newValue;
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  /**
   * Safely sends runtime messages to background worker with fail-safe local fallback.
   */
  function safeSendMessage(message, callback) {
    let hasResponded = false;

    function doFallback() {
      if (!hasResponded) {
        hasResponded = true;
        fallbackLocalAnalyze(message, callback);
      }
    }

    try {
      if (typeof chrome !== 'undefined' && chrome && chrome.runtime && typeof chrome.runtime.sendMessage === 'function') {
        chrome.runtime.sendMessage(message, (response) => {
          try {
            const lastErr = (typeof chrome !== 'undefined' && chrome && chrome.runtime) ? chrome.runtime.lastError : null;
            if (lastErr || !response) {
              doFallback();
            } else if (!hasResponded) {
              hasResponded = true;
              callback(response);
            }
          } catch (e) {
            doFallback();
          }
        });
      } else {
        doFallback();
      }
    } catch (err) {
      doFallback();
    }
  }

  /**
   * Direct in-content-script governance evaluation fallback if background worker is unavailable.
   */
  async function fallbackLocalAnalyze(message, callback) {
    if (message.type === 'ANALYZE_PROMPT') {
      const { promptText, destinationDomain = 'unknown' } = message.payload;
      
      const regexMatches = typeof runRegexChecks === 'function' ? runRegexChecks(promptText) : [];
      let llmResult = { sensitive: false, category: null, confidence: 0, skipped: true };
      if (typeof runLLMCheck === 'function') {
        llmResult = await runLLMCheck(promptText);
      }

      const riskAnalysis = typeof calculateRiskScore === 'function' ? calculateRiskScore({
        regexMatches, llmResult, userRole: 'engineering', destinationDomain
      }) : { score: regexMatches.length > 0 ? 85 : 0 };

      const policyResult = typeof evaluatePolicy === 'function' ? evaluatePolicy({
        regexMatches, llmResult, riskAnalysis, customPolicyConfig: { blockThreshold: 75, redactThreshold: 45 }
      }) : { action: regexMatches.length > 0 ? 'block' : 'allow', riskScore: riskAnalysis.score, reasons: [] };

      const explanation = typeof generateExplanation === 'function' ? generateExplanation(policyResult) : 'Governance decision applied.';

      if (typeof logAuditRecord === 'function') {
        await logAuditRecord({
          timestamp: new Date().toISOString(),
          promptText, destinationDomain, riskScore: policyResult.riskScore, decision: policyResult.action, explanation
        });
      }

      callback({
        success: true,
        data: {
          action: policyResult.action,
          riskScore: policyResult.riskScore,
          explanation: explanation,
          reasons: policyResult.reasons || [],
          regexMatches: regexMatches,
          llmResult: llmResult
        }
      });
    } else if (message.type === 'ANALYZE_FILE') {
      const { extractedData = {}, destinationDomain = 'unknown' } = message.payload;
      const { fileName = 'file', text = '', unscannable = false, reason = '' } = extractedData;

      const regexMatches = typeof runRegexChecks === 'function' ? runRegexChecks(text) : [];
      
      const riskAnalysis = typeof calculateRiskScore === 'function' ? calculateRiskScore({
        regexMatches, unscannable, destinationDomain
      }) : { score: unscannable ? 85 : 0 };

      const policyResult = typeof evaluatePolicy === 'function' ? evaluatePolicy({
        regexMatches, unscannable, fileName, unscannableReason: reason, riskAnalysis
      }) : { action: unscannable ? 'block' : 'allow', riskScore: riskAnalysis.score, reasons: [] };

      const explanation = typeof generateExplanation === 'function' ? generateExplanation({ ...policyResult, fileName }) : 'File governance decision applied.';

      callback({
        success: true,
        data: {
          action: policyResult.action,
          riskScore: policyResult.riskScore,
          explanation: explanation,
          reasons: policyResult.reasons || [],
          fileName: fileName
        }
      });
    }
  }

  /**
   * Attaches submission and file upload event interceptors.
   */
  function attachInterceptors() {
    document.addEventListener('keydown', handleKeyDown, true);
    document.addEventListener('click', handleClick, true);
    document.addEventListener('change', handleFileInputChange, true);
    document.addEventListener('dragover', handleDragOver, true);
    document.addEventListener('drop', handleFileDrop, true);
  }

  function handleKeyDown(event) {
    if (event.key === 'Enter' && !event.shiftKey && !isBypassingInterception) {
      const inputEl = findPromptInput();
      if (inputEl && (event.target === inputEl || inputEl.contains(event.target))) {
        const text = getInputValue(inputEl);
        if (text.trim().length > 0) {
          event.preventDefault();
          event.stopPropagation();
          event.stopImmediatePropagation();
          processPromptSubmission(text, inputEl);
        }
      }
    }
  }

  function handleClick(event) {
    if (isBypassingInterception) return;

    const target = event.target;
    const button = target.closest('button, [role="button"]');
    if (!button) return;

    const dataTestId = (button.getAttribute('data-testid') || '').toLowerCase();
    const ariaLabel = (button.getAttribute('aria-label') || '').toLowerCase();
    
    const isSendButton = dataTestId.includes('send') ||
                         dataTestId.includes('submit') ||
                         ariaLabel.includes('send') ||
                         ariaLabel.includes('submit');

    if (isSendButton) {
      const inputEl = findPromptInput();
      if (inputEl) {
        const text = getInputValue(inputEl);
        if (text.trim().length > 0) {
          event.preventDefault();
          event.stopPropagation();
          event.stopImmediatePropagation();
          processPromptSubmission(text, inputEl);
        }
      }
    }
  }

  // ==========================================
  // FILE UPLOAD INTERCEPTION HANDLERS
  // ==========================================

  function handleFileInputChange(event) {
    if (isBypassingInterception) return;

    const target = event.target;
    if (target && target.tagName === 'INPUT' && target.type === 'file' && target.files && target.files.length > 0) {
      const files = Array.from(target.files);
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      processFileGovernance(files, target);
    }
  }

  function handleDragOver(event) {
    if (isBypassingInterception) return;
    if (event.dataTransfer && event.dataTransfer.types && event.dataTransfer.types.includes('Files')) {
      // Allow drag visually
    }
  }

  function handleFileDrop(event) {
    if (isBypassingInterception) return;

    if (event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files.length > 0) {
      const files = Array.from(event.dataTransfer.files);
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      processFileGovernance(files, event.target);
    }
  }

  /**
   * Processes file attachments through on-device text extraction & governance evaluation.
   */
  async function processFileGovernance(files, targetElement) {
    for (const file of files) {
      showFileCheckingOverlay(file.name);

      let extractedData = null;
      if (typeof extractTextFromFile === 'function') {
        extractedData = await extractTextFromFile(file);
      } else {
        extractedData = {
          fileName: file.name,
          fileType: file.name.split('.').pop(),
          fileSize: file.size,
          text: '',
          pages: [],
          chunks: [],
          unscannable: true,
          reason: 'Extraction module unavailable.'
        };
      }

      safeSendMessage(
        {
          type: 'ANALYZE_FILE',
          payload: {
            extractedData: extractedData,
            destinationDomain: window.location.hostname
          }
        },
        (response) => {
          removeFileCheckingOverlay();

          if (!response || !response.success) {
            console.error('[AI Governance] Error analyzing file:', response?.error);
            dispatchOriginalFileAttach(files, targetElement);
            return;
          }

          const data = response.data;

          if (data.action === 'block') {
            showGovernanceModal({
              action: 'block',
              fileName: file.name,
              riskScore: data.riskScore,
              explanation: data.explanation,
              reasons: data.reasons,
              onDismiss: () => {}
            });
          } else if (data.action === 'redact') {
            showGovernanceModal({
              action: 'redact',
              fileName: file.name,
              riskScore: data.riskScore,
              explanation: data.explanation,
              reasons: data.reasons,
              onRedactAndResend: () => {
                dispatchOriginalFileAttach(files, targetElement);
              },
              onDismiss: () => {}
            });
          } else {
            dispatchOriginalFileAttach(files, targetElement);
          }
        }
      );
    }
  }

  function dispatchOriginalFileAttach(files, targetElement) {
    isBypassingInterception = true;

    if (targetElement && targetElement.tagName === 'INPUT' && targetElement.type === 'file') {
      targetElement.dispatchEvent(new Event('change', { bubbles: true }));
    }

    setTimeout(() => {
      isBypassingInterception = false;
    }, 1000);
  }

  /**
   * Prompts user for text pre-flight processing with deduplication check.
   */
  function processPromptSubmission(promptText, inputEl) {
    const now = Date.now();
    // Deduplication check: ignore duplicate evaluation within 1500ms for exact same text
    if (promptText === lastProcessedPrompt && (now - lastProcessedTime) < 1500) {
      console.log('[AI Governance] Skipping duplicate evaluation request within 1500ms window.');
      return;
    }
    lastProcessedPrompt = promptText;
    lastProcessedTime = now;

    safeSendMessage(
      {
        type: 'ANALYZE_PROMPT',
        payload: {
          promptText: promptText,
          destinationDomain: window.location.hostname
        }
      },
      (response) => {
        if (!response || !response.success) {
          console.error('[AI Governance] Error processing prompt:', response?.error);
          dispatchOriginalSubmission(inputEl);
          return;
        }

        const data = response.data;

        if (data.action === 'block') {
          showGovernanceModal({
            action: 'block',
            riskScore: data.riskScore,
            explanation: data.explanation,
            reasons: data.reasons,
            onDismiss: () => {
              // Simply focus input area for user to edit. Do NOT submit.
              if (inputEl && typeof inputEl.focus === 'function') inputEl.focus();
            }
          });
        } else if (data.action === 'redact') {
          showGovernanceModal({
            action: 'redact',
            riskScore: data.riskScore,
            explanation: data.explanation,
            reasons: data.reasons,
            regexMatches: data.regexMatches,
            onRedactAndResend: () => {
              const redactedText = redactSensitiveText(promptText, data.regexMatches);
              setInputValue(inputEl, redactedText);
              dispatchOriginalSubmission(inputEl);
            },
            onDismiss: () => {
              // Simply focus input area for user to edit manually. Do NOT submit.
              if (inputEl && typeof inputEl.focus === 'function') inputEl.focus();
            }
          });
        } else {
          // Action = 'allow'
          dispatchOriginalSubmission(inputEl);
        }
      }
    );
  }

  function redactSensitiveText(text, regexMatches = []) {
    let result = text;
    for (const match of regexMatches) {
      if (match.match) {
        const placeholder = `[REDACTED_${(match.category || 'DATA').toUpperCase()}]`;
        result = result.split(match.match).join(placeholder);
      }
    }
    return result;
  }

  function dispatchOriginalSubmission(inputEl) {
    isBypassingInterception = true;

    const sendBtn = findSendButton();
    if (sendBtn) {
      sendBtn.click();
    } else {
      const enterEvent = new KeyboardEvent('keydown', {
        key: 'Enter', code: 'Enter', keyCode: 13, which: 13,
        bubbles: true, cancelable: true
      });
      inputEl.dispatchEvent(enterEvent);
    }

    setTimeout(() => {
      isBypassingInterception = false;
    }, 1000);
  }

  // ==========================================
  // MODALS & OVERLAYS UI
  // ==========================================

  function showFileCheckingOverlay(fileName) {
    removeFileCheckingOverlay();

    const overlay = document.createElement('div');
    overlay.id = 'ai-gov-checking-root';
    overlay.className = 'ai-gov-modal-overlay';
    overlay.innerHTML = `
      <div class="ai-gov-modal-card ai-gov-checking-card">
        <div class="ai-gov-spinner"></div>
        <div class="ai-gov-checking-title">Checking File Security...</div>
        <div class="ai-gov-checking-desc">Extracting text & running on-device AI inspection on <strong>${escapeHtml(fileName)}</strong></div>
      </div>
    `;
    document.body.appendChild(overlay);
  }

  function removeFileCheckingOverlay() {
    const existing = document.getElementById('ai-gov-checking-root');
    if (existing) existing.remove();
  }

  function showGovernanceModal({ action, fileName, riskScore, explanation, reasons, regexMatches, onRedactAndResend, onDismiss }) {
    const existing = document.getElementById('ai-gov-modal-root');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'ai-gov-modal-root';
    overlay.className = 'ai-gov-modal-overlay';

    const isBlock = action === 'block';
    const reasonsHtml = (reasons || []).map(r => `<li>${escapeHtml(r.description)}</li>`).join('');

    // Dynamic button labels based on action type
    let primaryButtonText = 'Remove Flagged Data & Send';
    let secondaryButtonText = 'Understand & Edit Prompt';

    if (fileName) {
      primaryButtonText = 'Proceed with Upload';
      secondaryButtonText = isBlock ? 'Understand & Cancel Attachment' : 'Cancel & Edit Manually';
    } else if (!isBlock) {
      secondaryButtonText = 'Keep & Edit Manually';
    }

    overlay.innerHTML = `
      <div class="ai-gov-modal-card">
        <div class="ai-gov-modal-header ${action}">
          <div class="ai-gov-title-wrapper">
            <span class="ai-gov-badge ${action}">${action}</span>
            <h3 class="ai-gov-modal-title">AI Governance Guardrail</h3>
          </div>
        </div>
        <div class="ai-gov-modal-body">
          ${fileName ? `<div style="font-size: 13px; font-weight: 600; color: #38bdf8; margin-bottom: 12px;">File Attachment: ${escapeHtml(fileName)}</div>` : ''}
          <div class="ai-gov-risk-meter">
            <span>Evaluated Risk Score</span>
            <span class="ai-gov-risk-score ${riskScore >= 75 ? 'high' : 'medium'}">${riskScore} / 100</span>
          </div>
          <p>${escapeHtml(explanation)}</p>
          ${reasons && reasons.length > 0 ? `
            <strong style="color: #f8fafc; font-size: 13px;">Detected Policy Triggers:</strong>
            <ul class="ai-gov-reasons-list">
              ${reasonsHtml}
            </ul>
          ` : ''}
        </div>
        <div class="ai-gov-modal-footer">
          ${!isBlock && onRedactAndResend ? `
            <button id="ai-gov-btn-redact" class="ai-gov-btn ai-gov-btn-primary">${primaryButtonText}</button>
          ` : ''}
          <button id="ai-gov-btn-close" class="ai-gov-btn ai-gov-btn-secondary">${secondaryButtonText}</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById('ai-gov-btn-close').addEventListener('click', () => {
      overlay.remove();
      if (onDismiss) onDismiss();
    });

    const redactBtn = document.getElementById('ai-gov-btn-redact');
    if (redactBtn && onRedactAndResend) {
      redactBtn.addEventListener('click', () => {
        overlay.remove();
        onRedactAndResend();
      });
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Attach all submission and file upload listeners
  attachInterceptors();

})();