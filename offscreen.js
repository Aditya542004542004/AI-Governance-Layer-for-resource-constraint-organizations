/**
 * offscreen.js
 * 
 * Chrome Extension Offscreen Document script.
 * Hosts Tesseract.js WebAssembly & Web Worker execution within the extension's own origin
 * (chrome-extension://), completely bypassing restrictive host webpage CSPs (Gemini, ChatGPT, Claude).
 */

if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || message.target !== 'offscreen') {
      return false;
    }

    if (message.type === 'OFFSCREEN_PERFORM_OCR') {
      const payload = message.payload || {};
      const { imageData, options = {} } = payload;

      if (!imageData) {
        sendResponse({ success: false, error: 'No image data provided for OCR analysis.' });
        return false;
      }

      if (typeof extractTextFromImage !== 'function') {
        sendResponse({ success: false, error: 'OCR engine function extractTextFromImage unavailable.' });
        return false;
      }

      extractTextFromImage(imageData, options)
        .then((result) => {
          sendResponse({ success: true, data: result });
        })
        .catch((err) => {
          console.error('[AI Governance Offscreen] OCR recognition failed:', err);
          sendResponse({ success: false, error: err.message || String(err) });
        });

      return true; // Keep channel open for async response
    }

    return false;
  });
}
