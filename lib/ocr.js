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
      workerBlobURL: false,
      logger: options.logger || (() => {}) // Suppress verbose logging
    });

    const ret = await worker.recognize(imageFileOrBlob);
    const text = (ret && ret.data && ret.data.text) ? ret.data.text.trim() : '';
    const confidence = (ret && ret.data && typeof ret.data.confidence === 'number') ? ret.data.confidence : 0;

    const words = (ret && ret.data && Array.isArray(ret.data.words))
      ? ret.data.words.map(w => ({
          text: w.text || '',
          bbox: w.bbox || null,
          confidence: w.confidence || 0
        }))
      : [];
    const lines = (ret && ret.data && Array.isArray(ret.data.lines))
      ? ret.data.lines.map(l => ({
          text: l.text || '',
          bbox: l.bbox || null
        }))
      : [];

    return {
      text: text,
      confidence: confidence,
      words: words,
      lines: lines
    };
  } finally {
    if (worker && typeof worker.terminate === 'function') {
      try {
        await worker.terminate();
      } catch (_) {}
    }
  }
}

/**
 * Calculates bounding boxes to blackout on an image canvas corresponding to sensitive regex matches.
 * @param {Array<Object>} sensitiveMatches 
 * @param {Object} ocrResult 
 * @returns {Array<{x0: number, y0: number, x1: number, y1: number}>}
 */
function calculateRedactionBoxes(sensitiveMatches = [], ocrResult = {}) {
  const words = (ocrResult && Array.isArray(ocrResult.words)) ? ocrResult.words : [];
  const lines = (ocrResult && Array.isArray(ocrResult.lines)) ? ocrResult.lines : [];

  const targetStrings = sensitiveMatches
    .map(m => (m && (m.match || m.value)) ? String(m.match || m.value).trim().toLowerCase() : '')
    .filter(Boolean);

  if (targetStrings.length === 0) return [];

  const boxes = [];

  for (const target of targetStrings) {
    let matchedInWords = false;

    // 1. Word-level matching
    if (words.length > 0) {
      for (const w of words) {
        const wText = (w.text || '').trim().toLowerCase();
        if (!wText) continue;

        // Check if word is substring of target (e.g. split email parts) or vice versa
        if (target.includes(wText) || wText.includes(target)) {
          if (w.bbox && typeof w.bbox.x0 === 'number') {
            boxes.push(w.bbox);
            matchedInWords = true;
          }
        }
      }
    }

    // 2. Line fallback matching if word-level didn't match
    if (!matchedInWords && lines.length > 0) {
      for (const l of lines) {
        const lText = (l.text || '').trim().toLowerCase();
        if (lText && lText.includes(target) && l.bbox && typeof l.bbox.x0 === 'number') {
          boxes.push(l.bbox);
        }
      }
    }
  }

  return boxes;
}

/**
 * Redacts sensitive text from an image by painting opaque black blackout rectangles
 * over the coordinates corresponding to detected regex matches.
 * 
 * @param {File|Blob} imageFileOrBlob - Original image file
 * @param {Array<Object>} sensitiveMatches - Array of regex matches ({ match, category, ... })
 * @param {Object} ocrResult - Result from extractTextFromImage ({ text, words, lines })
 * @returns {Promise<File>} A newly synthesized, sanitized File object
 */
async function redactImageFile(imageFileOrBlob, sensitiveMatches = [], ocrResult = {}) {
  if (!imageFileOrBlob || !Array.isArray(sensitiveMatches) || sensitiveMatches.length === 0) {
    return imageFileOrBlob;
  }

  // Handle mock environment (e.g. Node.js unit tests without DOM Canvas)
  if (typeof document === 'undefined' || typeof Image === 'undefined') {
    const origName = imageFileOrBlob.name || 'image.png';
    const sanitizedName = origName.startsWith('redacted_') ? origName : `redacted_${origName}`;
    return {
      name: sanitizedName,
      type: imageFileOrBlob.type || 'image/png',
      size: imageFileOrBlob.size || 1024,
      isRedactedImage: true,
      redactedBoxesCount: calculateRedactionBoxes(sensitiveMatches, ocrResult).length
    };
  }

  const boxes = calculateRedactionBoxes(sensitiveMatches, ocrResult);
  if (boxes.length === 0) {
    console.warn('[AI Governance] No bounding boxes could be located for sensitive matches.');
    return imageFileOrBlob;
  }

  const url = URL.createObjectURL(imageFileOrBlob);
  try {
    const img = new Image();
    await new Promise((resolve, reject) => {
      img.onload = resolve;
      img.onerror = () => reject(new Error('Failed to load image for canvas redaction'));
      img.src = url;
    });

    const width = img.naturalWidth || img.width;
    const height = img.naturalHeight || img.height;

    // Create offscreen canvas and draw original image
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);

    // Paint solid black blackout bars over boxes with padding
    for (const b of boxes) {
      const padX = 4;
      const padY = 2;
      const x = Math.max(0, Math.floor(b.x0 - padX));
      const y = Math.max(0, Math.floor(b.y0 - padY));
      const w = Math.min(width - x, Math.ceil((b.x1 - b.x0) + (padX * 2)));
      const h = Math.min(height - y, Math.ceil((b.y1 - b.y0) + (padY * 2)));

      if (w <= 0 || h <= 0) continue;

      // Solid black redaction box
      ctx.fillStyle = '#000000';
      ctx.fillRect(x, y, w, h);

      // Security overlay text if box is large enough to display it
      if (h >= 12 && w >= 55) {
        ctx.fillStyle = '#ffffff';
        const fontSize = Math.max(9, Math.min(13, Math.floor(h * 0.65)));
        ctx.font = `bold ${fontSize}px sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('[REDACTED]', x + (w / 2), y + (h / 2));
      }
    }

    // Convert canvas back to Blob
    const mimeType = imageFileOrBlob.type || 'image/png';
    const blob = await new Promise((resolve) => {
      canvas.toBlob((b) => resolve(b), mimeType, 0.95);
    });

    // Free canvas backing store memory immediately
    canvas.width = 0;
    canvas.height = 0;

    if (!blob) {
      throw new Error('canvas.toBlob returned null');
    }

    // Wrap into a new File object with sanitized name and unique suffix to avoid host app deduplication collisions (e.g. Gemini)
    const origName = imageFileOrBlob.name || 'image.png';
    const dotIdx = origName.lastIndexOf('.');
    const baseName = dotIdx !== -1 ? origName.slice(0, dotIdx) : origName;
    const ext = dotIdx !== -1 ? origName.slice(dotIdx) : '.png';
    const cleanBase = baseName.replace(/^redacted_([a-z0-9]+_)?/i, '');
    const uniqueTag = Date.now().toString(36).slice(-4) + Math.random().toString(36).slice(2, 5);
    const sanitizedName = `redacted_${cleanBase}_${uniqueTag}${ext}`;
    return new File([blob], sanitizedName, { type: mimeType, lastModified: Date.now() });
  } finally {
    URL.revokeObjectURL(url);
  }
}

// Universal Export Wrapper for Node.js, Web Worker, and Browser Contexts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractTextFromImage, redactImageFile, calculateRedactionBoxes };
}
if (typeof globalThis !== 'undefined') {
  globalThis.extractTextFromImage = extractTextFromImage;
  globalThis.redactImageFile = redactImageFile;
  globalThis.calculateRedactionBoxes = calculateRedactionBoxes;
}
if (typeof self !== 'undefined') {
  self.extractTextFromImage = extractTextFromImage;
  self.redactImageFile = redactImageFile;
  self.calculateRedactionBoxes = calculateRedactionBoxes;
}

