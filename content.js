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
  let isScanningActive = false;
  let lastProcessedPrompt = '';
  let lastProcessedTime = 0;

  console.log('[AI Governance] Content script active with File Upload Governance on:', window.location.hostname);

  /**
   * Locates the active AI prompt input box based on domain-specific selectors.
   * @returns {HTMLElement|null}
   */
  function findPromptInput() {
    // Check if active element is already the prompt input/composer
    if (document.activeElement && 
        (document.activeElement.tagName === 'TEXTAREA' || 
         document.activeElement.isContentEditable || 
         document.activeElement.getAttribute('contenteditable') === 'true')) {
      const parentEditable = document.activeElement.closest('#prompt-textarea') || document.activeElement;
      return parentEditable;
    }

    const hostname = window.location.hostname;

    if (hostname.includes('chatgpt.com') || hostname.includes('openai.com')) {
      return document.querySelector('#prompt-textarea') ||
             document.querySelector('textarea[tabindex="0"]') ||
             document.querySelector('div[contenteditable="true"]');
    }

    if (hostname.includes('gemini.google.com')) {
      return document.querySelector('rich-textarea div[contenteditable="true"]') ||
             document.querySelector('div.ql-editor[contenteditable="true"]') ||
             document.querySelector('rich-textarea p') ||
             document.querySelector('div[contenteditable="true"]') ||
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

  function isSendButtonElement(target) {
    if (!target) return false;
    const button = target.closest('button, [role="button"]');
    if (!button) return false;

    const dataTestId = (button.getAttribute('data-testid') || '').toLowerCase();
    const ariaLabel = (button.getAttribute('aria-label') || '').toLowerCase();
    const btnType = (button.getAttribute('type') || '').toLowerCase();

    return dataTestId.includes('send') ||
           dataTestId.includes('submit') ||
           ariaLabel.includes('send') ||
           ariaLabel.includes('submit') ||
           btnType === 'submit';
  }

  function findSendButton() {
    const hostname = window.location.hostname;
    if (hostname.includes('chatgpt.com') || hostname.includes('openai.com')) {
      return document.querySelector('button[data-testid="send-button"]') ||
             document.querySelector('button[data-testid="submit-button"]') ||
             document.querySelector('button[data-testid*="send"]') ||
             document.querySelector('button[aria-label*="Send"]') ||
             document.querySelector('form button[type="submit"]') ||
             document.querySelector('form button:not([disabled])');
    }
    if (hostname.includes('gemini.google.com')) {
      return document.querySelector('button.send-button') ||
             document.querySelector('button[aria-label*="Send"]') ||
             document.querySelector('button[aria-label*="Submit"]') ||
             document.querySelector('.send-button-container button') ||
             document.querySelector('rich-textarea ~ button') ||
             document.querySelector('button.send-button-container');
    }
    if (hostname.includes('claude.ai')) {
      return document.querySelector('button[aria-label*="Send"]') ||
             document.querySelector('button[aria-label*="send"]');
    }
    return document.querySelector('button[type="submit"]') || document.querySelector('button[aria-label*="Send"]');
  }

  function getInputValue(element) {
    if (!element) return '';
    if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
      return element.value || '';
    }
    return element.innerText || element.textContent || '';
  }

  /**
   * Updates host input value while properly notifying React 16-19 and Lexical/ProseMirror state handlers.
   */
  function setInputValue(element, newValue) {
    if (!element) return false;

    // 1. Textarea or Input (React controlled component synchronization)
    if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
      const proto = element.tagName === 'TEXTAREA'
        ? window.HTMLTextAreaElement.prototype
        : window.HTMLInputElement.prototype;
      const valueSetter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;

      // Reset React's internal value tracker so React's onChange does not reject the update
      if (element._valueTracker) {
        try {
          element._valueTracker.setValue('');
        } catch (_) {}
      }

      if (valueSetter) {
        valueSetter.call(element, newValue);
      } else {
        element.value = newValue;
      }

      element.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
      element.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
      return true;
    }

    // 2. Contenteditable (ChatGPT Lexical / ProseMirror, Claude, Gemini)
    if (element.isContentEditable || element.getAttribute('contenteditable') === 'true') {
      element.focus();

      let replaced = false;
      try {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(element);
        selection.removeAllRanges();
        selection.addRange(range);

        replaced = document.execCommand('insertText', false, newValue);
      } catch (_) {}

      if (!replaced) {
        try {
          element.innerHTML = `<p>${escapeHtml(newValue)}</p>`;
        } catch (_) {
          element.textContent = newValue;
        }
      }

      try {
        element.dispatchEvent(new InputEvent('input', {
          bubbles: true,
          composed: true,
          inputType: 'insertText',
          data: newValue
        }));
      } catch (_) {}

      element.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
      element.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
      return true;
    }

    return false;
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
    } else if (message.type === 'ANALYZE_FILE' || message.type === 'ANALYZE_BATCH_FILES') {
      const payload = message.payload || {};
      const files = payload.files || [payload];
      const firstData = (files[0] && files[0].extractedData) ? files[0].extractedData : (files[0] || {});
      const { fileName = 'file', text = '', unscannable = false, reason = '' } = firstData;

      const regexMatches = typeof runRegexChecks === 'function' ? runRegexChecks(text) : [];
      
      const riskAnalysis = typeof calculateRiskScore === 'function' ? calculateRiskScore({
        regexMatches, unscannable, destinationDomain: payload.destinationDomain || 'unknown'
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
          fileName: fileName,
          fileResults: [{ action: policyResult.action, riskScore: policyResult.riskScore, fileName }]
        }
      });
    } else if (message.type === 'ANALYZE_IMAGE_TEXT') {
      const { extractedText = '', fileName = 'image.png', destinationDomain = 'unknown' } = message.payload || {};
      const regexMatches = typeof runRegexChecks === 'function' ? runRegexChecks(extractedText) : [];
      let llmResult = { sensitive: false, category: null, confidence: 0, skipped: true };
      if (typeof runLLMCheck === 'function' && extractedText) {
        llmResult = await runLLMCheck(extractedText);
      }
      const riskAnalysis = typeof calculateRiskScore === 'function' ? calculateRiskScore({
        regexMatches, llmResult, userRole: 'engineering', destinationDomain
      }) : { score: regexMatches.length > 0 ? 85 : 0 };
      const policyResult = typeof evaluatePolicy === 'function' ? evaluatePolicy({
        promptText: extractedText, regexMatches, llmResult, riskAnalysis, fileName, customPolicyConfig: { blockThreshold: 75, redactThreshold: 45 }
      }) : { action: regexMatches.length > 0 ? 'block' : 'allow', riskScore: riskAnalysis.score, reasons: [] };
      const explanation = typeof generateExplanation === 'function' ? generateExplanation({ ...policyResult, fileName }) : 'Image OCR governance decision applied.';

      if (typeof logAuditRecord === 'function') {
        await logAuditRecord({
          timestamp: new Date().toISOString(),
          promptText: `[IMAGE OCR: ${fileName}] ${extractedText.substring(0, 300)}`,
          destinationDomain, riskScore: policyResult.riskScore, decision: policyResult.action, explanation,
          sourceType: 'image_ocr', fileName
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
          llmResult: llmResult,
          fileName: fileName,
          sourceType: 'image_ocr'
        }
      });
    }
  }

  /**
   * Attaches submission and file upload event interceptors.
   */
  function attachInterceptors() {
    document.addEventListener('keydown', handleKeyDown, true);
    document.addEventListener('pointerdown', handleSendButtonPrePointer, true);
    document.addEventListener('mousedown', handleSendButtonPrePointer, true);
    document.addEventListener('click', handleClick, true);
    document.addEventListener('submit', handleFormSubmit, true);
    document.addEventListener('change', handleFileInputChange, true);
    document.addEventListener('dragover', handleDragOver, true);
    document.addEventListener('drop', handleFileDrop, true);
    document.addEventListener('paste', handleFilePaste, true);
  }

  function handleKeyDown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
      if (isScanningActive) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
        showStatusChip('Please wait: File security inspection in progress...');
        return;
      }

      if (!isBypassingInterception) {
        let inputEl = findPromptInput();
        const isTargetEditable = event.target === inputEl || 
                                 (inputEl && inputEl.contains(event.target)) ||
                                 event.target.tagName === 'TEXTAREA' || 
                                 event.target.isContentEditable ||
                                 Boolean(event.target.closest('#prompt-textarea'));

        if (isTargetEditable) {
          if (!inputEl || !inputEl.contains(event.target)) {
            inputEl = event.target.closest('#prompt-textarea') || event.target;
          }
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
  }

  /**
   * Pre-emptively halts pointerdown/mousedown on the send button so host apps (ChatGPT, Claude)
   * cannot start or dispatch prompt requests before click interception evaluates governance.
   */
  function handleSendButtonPrePointer(event) {
    if (isBypassingInterception) return;

    if (isSendButtonElement(event.target)) {
      if (isScanningActive) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
        showStatusChip('Please wait: File security inspection in progress...');
        return;
      }

      // Stop pointerdown/mousedown from triggering early network dispatch in React/Tailwind/Radix
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
    }
  }

  function handleClick(event) {
    if (isBypassingInterception) return;

    if (isSendButtonElement(event.target)) {
      if (isScanningActive) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
        showStatusChip('Please wait: File security inspection in progress...');
        return;
      }

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

  function handleFormSubmit(event) {
    if (isBypassingInterception) return;

    if (isScanningActive) {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      showStatusChip('Please wait: File security inspection in progress...');
      return;
    }

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

  // ==========================================
  // FILE UPLOAD INTERCEPTION HANDLERS
  // ==========================================

  async function readDirectoryEntries(dirEntry) {
    const reader = dirEntry.createReader();
    const entries = await new Promise((resolve) => {
      reader.readEntries((ents) => resolve(ents), () => resolve([]));
    });

    const files = [];
    for (const ent of entries) {
      if (ent.isFile) {
        const file = await new Promise((resolve) => {
          ent.file((f) => resolve(f), () => resolve(null));
        });
        if (file) files.push(file);
      } else if (ent.isDirectory) {
        const subFiles = await readDirectoryEntries(ent);
        files.push(...subFiles);
      }
    }
    return files;
  }

  async function resolveTransferFiles(dataTransfer) {
    if (!dataTransfer) return [];

    // 1. If webkitGetAsEntry is available, recursively expand directories or filter out directory markers
    if (dataTransfer.items && dataTransfer.items.length > 0) {
      const results = [];
      for (const item of Array.from(dataTransfer.items)) {
        if (item.kind !== 'file') continue;
        const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
        if (entry) {
          if (entry.isDirectory) {
            try {
              const subFiles = await readDirectoryEntries(entry);
              results.push(...subFiles);
            } catch (_) {}
          } else if (entry.isFile) {
            const f = item.getAsFile();
            if (f) results.push(f);
          }
        } else {
          const f = item.getAsFile();
          if (f) results.push(f);
        }
      }
      if (results.length > 0) {
        return results;
      }
    }

    // 2. Fallback to dataTransfer.files, filtering out virtual directory markers (e.g. 'Downloads')
    if (dataTransfer.files && dataTransfer.files.length > 0) {
      return Array.from(dataTransfer.files).filter(f => {
        const isDirMarker = (!f.name || !f.name.includes('.')) && (f.size === 0 || f.name.toLowerCase() === 'downloads');
        return !isDirMarker;
      });
    }

    return [];
  }

  function handleFileInputChange(event) {
    if (isBypassingInterception) return;

    const target = event.target;
    if (target && target.tagName === 'INPUT' && target.type === 'file' && target.files && target.files.length > 0) {
      const files = Array.from(target.files).filter(f => {
        const isDirMarker = (!f.name || !f.name.includes('.')) && (f.size === 0 || f.name.toLowerCase() === 'downloads');
        return !isDirMarker;
      });
      if (files.length > 0) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        processFileGovernance(files, target, 'change');
      }
    }
  }

  function handleDragOver(event) {
    if (isBypassingInterception) return;
    if (event.dataTransfer && event.dataTransfer.types && event.dataTransfer.types.includes('Files')) {
      // Allow drag visually
    }
  }

  async function handleFileDrop(event) {
    if (isBypassingInterception) return;

    if (event.dataTransfer) {
      const files = await resolveTransferFiles(event.dataTransfer);
      if (files.length > 0) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        processFileGovernance(files, event.target, 'drop');
      }
    }
  }

  function handleFilePaste(event) {
    if (isBypassingInterception) return;

    if (event.clipboardData && event.clipboardData.files && event.clipboardData.files.length > 0) {
      const files = Array.from(event.clipboardData.files).filter(f => {
        const isDirMarker = (!f.name || !f.name.includes('.')) && (f.size === 0 || f.name.toLowerCase() === 'downloads');
        return !isDirMarker;
      });
      if (files.length > 0) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        processFileGovernance(files, event.target, 'paste');
      }
    }
  }

  /**
   * Inline Status Chip UI helpers for multi-file progressive status feedback.
   */
  function showStatusChip(text) {
    removeStatusChip();
    try {
      const chip = document.createElement('div');
      chip.id = 'ai-gov-status-chip-root';
      chip.className = 'ai-gov-status-chip';
      chip.innerHTML = `<div class="ai-gov-chip-spinner"></div><span>${escapeHtml(text)}</span>`;
      if (document.body) {
        document.body.appendChild(chip);
      }
    } catch (_) {}
  }

  function removeStatusChip() {
    try {
      const existing = document.getElementById('ai-gov-status-chip-root');
      if (existing && existing.parentNode) {
        existing.parentNode.removeChild(existing);
      }
    } catch (_) {}
  }

  function isImageFile(file) {
    if (!file) return false;
    const name = (file.name || file.fileName || '').toLowerCase();
    const type = (file.type || '').toLowerCase();
    return type.startsWith('image/') || /\.(png|jpe?g|webp)$/i.test(name);
  }

  /**
   * Processes file attachments through on-device text extraction & governance evaluation.
   * Supports multi-file parallel ingestion, on-device WebAssembly OCR for images, and progressive status feedback.
   */
  async function processFileGovernance(files, targetElement, eventType = 'change') {
    if (!files || files.length === 0) return;

    isScanningActive = true;
    const sendBtn = findSendButton();
    if (sendBtn) {
      sendBtn.disabled = true;
      sendBtn.setAttribute('data-ai-gov-disabled', 'true');
    }

    const unlockScanningState = () => {
      isScanningActive = false;
      removeStatusChip();
      removeFileCheckingOverlay();
      if (sendBtn && sendBtn.getAttribute('data-ai-gov-disabled')) {
        sendBtn.disabled = false;
        sendBtn.removeAttribute('data-ai-gov-disabled');
      }
    };

    const readFileAsDataUrl = (file) => {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error('Failed to read image data'));
        reader.readAsDataURL(file);
      });
    };

    // Single image attachment fast path using CSP-isolated Offscreen OCR
    if (files.length === 1 && isImageFile(files[0])) {
      const file = files[0];
      showStatusChip(`[Scanning Image for text: ${file.name}...]`);

      let dataUrl = null;
      try {
        dataUrl = await readFileAsDataUrl(file);
      } catch (readErr) {
        console.error('[AI Governance] Error reading image file:', readErr);
        unlockScanningState();
        showGovernanceModal({
          action: 'block',
          fileName: file.name,
          riskScore: 90,
          explanation: 'Image file could not be read for security screening.',
          reasons: ['File read error during pre-submission screening.'],
          onDismiss: () => {}
        });
        return;
      }

      safeSendMessage(
        {
          type: 'ANALYZE_IMAGE_FILE',
          payload: {
            imageData: dataUrl,
            fileName: file.name,
            fileSize: file.size,
            destinationDomain: window.location.hostname
          }
        },
        (response) => {
          unlockScanningState();

          if (!response || !response.success) {
            console.error('[AI Governance] Error analyzing image file:', response?.error);
            showGovernanceModal({
              action: 'block',
              fileName: file.name,
              riskScore: 90,
              explanation: 'Security inspection for image file encountered an error. Enforcing Fail-Closed security.',
              reasons: [response?.error || 'Security inspection service communication error.'],
              onDismiss: () => {}
            });
            return;
          }

          const data = response.data || {};

          // Purely visual image (genuinely no text detected by OCR)
          if (data.isVisualImage || (data.action === 'allow' && (!data.reasons || data.reasons.length === 0))) {
            console.log(`[AI Governance] Image '${file.name}' is purely visual (no sensitive text). Permitting attachment.`);
            dispatchOriginalFileAttach(files, targetElement, eventType);
            return;
          }

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
              onRedactAndResend: async () => {
                showStatusChip(`[Blacking out sensitive text in ${file.name}...]`);
                let fileToAttach = file;
                if (typeof redactImageFile === 'function') {
                  try {
                    fileToAttach = await redactImageFile(file, data.regexMatches || [], data.ocrResult || {});
                  } catch (redactErr) {
                    console.warn('[AI Governance] Error performing on-device canvas image redaction:', redactErr);
                  }
                }
                removeStatusChip();
                dispatchOriginalFileAttach([fileToAttach], targetElement, eventType);
              },
              onDismiss: () => {}
            });
          } else {
            // Action = 'allow'
            dispatchOriginalFileAttach(files, targetElement, eventType);
          }
        }
      );
      return;
    }

    const extractedFilesData = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];

      if (isImageFile(file)) {
        showStatusChip(`Scanning Image ${i + 1} of ${files.length}: ${file.name}...`);
        let ocrResult = null;
        let ocrFailed = false;
        try {
          const dataUrl = await readFileAsDataUrl(file);
          ocrResult = await new Promise((resolve, reject) => {
            safeSendMessage(
              {
                type: 'PERFORM_IMAGE_OCR',
                payload: { imageData: dataUrl, fileName: file.name }
              },
              (res) => {
                if (res && res.success && res.data) {
                  resolve(res.data);
                } else {
                  reject(new Error(res?.error || 'OCR failed'));
                }
              }
            );
          });
        } catch (err) {
          console.warn('[AI Governance] Error performing offscreen OCR for file in batch:', err);
          ocrFailed = true;
        }

        if (ocrFailed || !ocrResult) {
          extractedFilesData.push({
            file,
            extractedData: {
              fileName: file.name,
              fileType: file.name.split('.').pop().toLowerCase(),
              fileSize: file.size,
              text: '',
              chunks: [],
              unscannable: true,
              reason: 'Image OCR processing failed.',
              sourceType: 'image_ocr'
            }
          });
        } else {
          const extractedText = (ocrResult.text || '').trim();
          const confidence = typeof ocrResult.confidence === 'number' ? ocrResult.confidence : 0;
          const isPurelyVisual = extractedText.length === 0 || (confidence < 30 && extractedText.length === 0);

          extractedFilesData.push({
            file,
            extractedData: {
              fileName: file.name,
              fileType: file.name.split('.').pop().toLowerCase(),
              fileSize: file.size,
              text: extractedText,
              pages: extractedText ? [{ page: 1, text: extractedText }] : [],
              chunks: extractedText ? [{ chunkIndex: 0, text: extractedText, startChar: 0, endChar: extractedText.length }] : [],
              unscannable: false,
              isVisualImage: isPurelyVisual,
              ocrResult: ocrResult,
              sourceType: 'image_ocr'
            }
          });
        }
      } else {
        showStatusChip(`Scanning File ${i + 1} of ${files.length}: ${file.name}...`);
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
        extractedFilesData.push({ file, extractedData });
      }
    }

    safeSendMessage(
      {
        type: 'ANALYZE_BATCH_FILES',
        payload: {
          files: extractedFilesData,
          destinationDomain: window.location.hostname
        }
      },
      (response) => {
        unlockScanningState();

        if (!response || !response.success) {
          console.error('[AI Governance] Error analyzing batch files:', response?.error);
          dispatchOriginalFileAttach(files, targetElement, eventType);
          return;
        }

        const data = response.data;
        const fileResults = data.fileResults || [];
        const blockedFile = fileResults.find(r => r.action === 'block');

        if (data.action === 'block' || blockedFile) {
          const targetResult = blockedFile || fileResults[0] || {};
          showGovernanceModal({
            action: 'block',
            fileName: targetResult.fileName || files[0].name,
            riskScore: data.riskScore || targetResult.riskScore,
            explanation: data.explanation || targetResult.explanation,
            reasons: data.reasons || targetResult.reasons,
            onDismiss: () => {}
          });
        } else if (data.action === 'redact') {
          const redactFile = fileResults.find(r => r.action === 'redact') || fileResults[0] || {};
          showGovernanceModal({
            action: 'redact',
            fileName: redactFile.fileName || files[0].name,
            riskScore: data.riskScore || redactFile.riskScore,
            explanation: data.explanation || redactFile.explanation,
            reasons: data.reasons || redactFile.reasons,
            onRedactAndResend: async () => {
              const processedFiles = [];
              for (const fItem of extractedFilesData) {
                const f = fItem.file;
                const extData = fItem.extractedData || {};
                if (isImageFile(f) && extData.sourceType === 'image_ocr' && typeof redactImageFile === 'function') {
                  showStatusChip(`[Blacking out sensitive text in ${f.name}...]`);
                  try {
                    const sanitized = await redactImageFile(f, data.regexMatches || [], extData.ocrResult || {});
                    processedFiles.push(sanitized);
                  } catch (_) {
                    processedFiles.push(f);
                  }
                } else {
                  processedFiles.push(f);
                }
              }
              removeStatusChip();
              dispatchOriginalFileAttach(processedFiles, targetElement, eventType);
            },
            onDismiss: () => {}
          });
        } else {
          dispatchOriginalFileAttach(files, targetElement, eventType);
        }
      }
    );
  }

  /**
   * Re-dispatches allowed file attachments to the host page (ChatGPT, Claude, Gemini).
   * Constructs synthetic DragEvent ('drop'), ClipboardEvent ('paste'), and synchronizes native <input type="file">.
   */
  function dispatchOriginalFileAttach(files, targetElement, eventType = 'change') {
    isBypassingInterception = true;

    try {
      // 1. Build a native DataTransfer populated with the allowed files
      let dataTransfer = null;
      if (typeof DataTransfer !== 'undefined') {
        try {
          dataTransfer = new DataTransfer();
          for (const f of files) {
            dataTransfer.items.add(f);
          }
        } catch (_) {}
      }

      // 2. Dispatch according to the original ingestion event type
      if (eventType === 'drop' && dataTransfer) {
        try {
          const dropEvt = new DragEvent('drop', {
            bubbles: true,
            cancelable: true,
            composed: true,
            dataTransfer: dataTransfer
          });
          const target = (targetElement && document.contains(targetElement)) 
            ? targetElement 
            : (findPromptInput() || document.querySelector('[contenteditable="true"]') || document.body);
          target.dispatchEvent(dropEvt);
        } catch (dropErr) {
          console.warn('[AI Governance] DragEvent dispatch error:', dropErr);
        }
      } else if (eventType === 'paste' && dataTransfer) {
        try {
          const pasteEvt = new ClipboardEvent('paste', {
            bubbles: true,
            cancelable: true,
            composed: true,
            clipboardData: dataTransfer
          });
          const target = (targetElement && document.contains(targetElement)) 
            ? targetElement 
            : (findPromptInput() || document.querySelector('[contenteditable="true"]') || document.body);
          target.dispatchEvent(pasteEvt);
        } catch (pasteErr) {
          console.warn('[AI Governance] ClipboardEvent dispatch error:', pasteErr);
        }
      } else {
        // 3. Update hidden or active file input element (supports ChatGPT, Claude, and Gemini native React state)
        const fileInput = (targetElement && targetElement.tagName === 'INPUT' && targetElement.type === 'file')
          ? targetElement
          : document.querySelector('input[type="file"]');

        if (fileInput) {
          if (dataTransfer && dataTransfer.files) {
            try {
              fileInput.files = dataTransfer.files;
            } catch (_) {}
          }
          // Reset React's internal value tracker if present so React accepts synthetic change
          if (fileInput._valueTracker) {
            try {
              fileInput._valueTracker.setValue('');
            } catch (_) {}
          }
          fileInput.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
          fileInput.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
        } else if (targetElement && document.contains(targetElement)) {
          targetElement.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
          targetElement.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
        }
      }
    } catch (err) {
      console.warn('[AI Governance] Non-critical warning during file attach re-dispatch:', err);
    }

    setTimeout(() => {
      isBypassingInterception = false;
    }, 1200);
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
              const textToSubmit = data.redactedText || redactSensitiveText(promptText, data.regexMatches);
              setInputValue(inputEl, textToSubmit);
              // Allow React 18 / Lexical 120ms to process state reconciliation and update composer state
              setTimeout(() => {
                dispatchOriginalSubmission(inputEl);
              }, 120);
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
    } else if (inputEl) {
      const enterEvent = new KeyboardEvent('keydown', {
        key: 'Enter', code: 'Enter', keyCode: 13, which: 13,
        bubbles: true, cancelable: true
      });
      inputEl.dispatchEvent(enterEvent);
    }

    setTimeout(() => {
      isBypassingInterception = false;
    }, 1200);
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

    // Deduplicate and aggregate policy reason descriptions (e.g. 10x Email Address -> "Email Address (×10)")
    const reasonCounts = {};
    (reasons || []).forEach(r => {
      const desc = typeof r === 'object' && r ? (r.description || r.type || JSON.stringify(r)) : String(r);
      reasonCounts[desc] = (reasonCounts[desc] || 0) + 1;
    });

    const reasonsHtml = Object.entries(reasonCounts).map(([desc, count]) => {
      const countBadge = count > 1 ? ` <span style="background: #334155; color: #f8fafc; padding: 2px 6px; border-radius: 10px; font-size: 11px; font-weight: 700;">×${count}</span>` : '';
      return `<li>${escapeHtml(desc)}${countBadge}</li>`;
    }).join('');

    // Dynamic button labels based on action type
    let primaryButtonText = 'Remove Flagged Data & Send';
    let secondaryButtonText = 'Understand & Edit Prompt';
    const isImageAttachment = fileName && /\.(png|jpe?g|webp)$/i.test(fileName);

    if (fileName) {
      primaryButtonText = isImageAttachment ? 'Blackout Sensitive Data & Upload' : 'Proceed with Upload';
      secondaryButtonText = isBlock ? 'Understand & Cancel Attachment' : 'Cancel Attachment';
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
          ${isImageAttachment && !isBlock ? `
            <div style="background: rgba(56, 189, 248, 0.1); border-left: 3px solid #38bdf8; padding: 8px 12px; border-radius: 4px; font-size: 12px; color: #bae6fd; margin-bottom: 12px;">
              🔒 <strong>On-Device Canvas Redaction:</strong> Sensitive text will be physically blacked out on the image pixels before uploading. Surrounding diagrams, charts, and layout remain intact.
            </div>
          ` : ''}
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