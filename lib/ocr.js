/**
 * lib/ocr.js
 * 
 * On-device WebAssembly Optical Character Recognition (OCR) Engine powered by Tesseract.js.
 * Inspects image attachments (.png, .jpg, .jpeg, .webp) 100% locally inside the browser.
 * Zero external network requests to unpkg, jsdelivr, or remote tessdata repositories.
 */

/**
 * Extracts visible text and recognition confidence from an image File, Blob, or Buffer.
 * @param {File|Blob|ArrayBuffer|Uint8Array|string} imageFileOrBlob 
 * @param {Object} [options={}]
 * @returns {Promise<{text: string, confidence: number}>}
 */
async function extractTextFromImage(imageFileOrBlob, options = {}) {
  // Support testing mock hooks
  if (options && options.mockResult) {
    return options.mockResult;
  }
  if (imageFileOrBlob && imageFileOrBlob.__mockOcrResult) {
    return imageFileOrBlob.__mockOcrResult;
  }
  if (typeof globalThis !== 'undefined' && globalThis.__mockOcrResult) {
    return globalThis.__mockOcrResult;
  }

  // Obtain Tesseract instance
  let TesseractInstance = null;
  if (typeof Tesseract !== 'undefined') {
    TesseractInstance = Tesseract;
  } else if (typeof globalThis !== 'undefined' && globalThis.Tesseract) {
    TesseractInstance = globalThis.Tesseract;
  } else if (typeof self !== 'undefined' && self.Tesseract) {
    TesseractInstance = self.Tesseract;
  } else if (typeof require !== 'undefined') {
    try {
      if (typeof self === 'undefined') {
        globalThis.self = globalThis;
      }
      TesseractInstance = require('../vendor/tesseract/tesseract.min.js');
    } catch (_) {}
  }

  if (!TesseractInstance || typeof TesseractInstance.createWorker !== 'function') {
    throw new Error('TESSERACT_OCR_UNAVAILABLE: Tesseract.js library not loaded');
  }

  // Configure local extension assets via chrome.runtime.getURL to prevent CDN network requests
  const hasChromeRuntime = typeof chrome !== 'undefined' && chrome && chrome.runtime && typeof chrome.runtime.getURL === 'function';

  const workerPath = hasChromeRuntime 
    ? chrome.runtime.getURL('vendor/tesseract/worker.min.js') 
    : (options.workerPath || './vendor/tesseract/worker.min.js');

  const corePath = hasChromeRuntime 
    ? chrome.runtime.getURL('vendor/tesseract/tesseract-core.wasm.js') 
    : (options.corePath || './vendor/tesseract/tesseract-core.wasm.js');

  const langPath = hasChromeRuntime 
    ? chrome.runtime.getURL('vendor/tesseract/lang-data') 
    : (options.langPath || './vendor/tesseract/lang-data');

  let worker = null;
  try {
    worker = await TesseractInstance.createWorker('eng', 1, {
      workerPath: workerPath,
      corePath: corePath,
      langPath: langPath,
      logger: options.logger || (() => {}) // Suppress verbose logging
    });

    const ret = await worker.recognize(imageFileOrBlob);
    const text = (ret && ret.data && ret.data.text) ? ret.data.text.trim() : '';
    const confidence = (ret && ret.data && typeof ret.data.confidence === 'number') ? ret.data.confidence : 0;

    return {
      text: text,
      confidence: confidence
    };
  } finally {
    if (worker && typeof worker.terminate === 'function') {
      try {
        await worker.terminate();
      } catch (_) {}
    }
  }
}

// Universal Export Wrapper for Node.js, Web Worker, and Browser Contexts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractTextFromImage };
}
if (typeof globalThis !== 'undefined') {
  globalThis.extractTextFromImage = extractTextFromImage;
}
if (typeof self !== 'undefined') {
  self.extractTextFromImage = extractTextFromImage;
}
