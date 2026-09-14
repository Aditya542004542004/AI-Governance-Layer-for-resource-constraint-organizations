/**
 * detectors/file-extract.js
 * 
 * Multi-format text extraction router and document chunking engine.
 * Routes files by extension and MIME type to local client-side parsers (PDF, DOCX, XLSX, TXT).
 * Applies fail-closed security classification for unscannable or image file formats.
 * 
 * Runs 100% offline inside the browser. Zero network calls or external APIs.
 */

// Load extractor helpers if in Node environment
if (typeof require !== 'undefined') {
  try {
    const pdfLib = require('../lib/pdf-extract.js');
    const docxLib = require('../lib/docx-extract.js');
    const xlsxLib = require('../lib/xlsx-extract.js');
    globalThis.extractPdfText = pdfLib.extractPdfText;
    globalThis.extractDocxText = docxLib.extractDocxText;
    globalThis.extractXlsxText = xlsxLib.extractXlsxText;
  } catch (e) {
    // Ignore require warnings in browser
  }
}

/**
 * Splits extracted text into sequential chunks for safe LLM context window evaluation.
 * @param {string} text 
 * @param {number} [maxChunkSize=8000] Default 8000 chars for optimal performance
 * @param {number} [overlap=600] 600 char overlap to safely cover long secrets across boundaries
 * @returns {Array<{chunkIndex: number, text: string, startChar: number, endChar: number}>}
 */
function chunkText(text, maxChunkSize = 8000, overlap = 600) {
  if (!text || typeof text !== 'string') return [];
  if (text.length <= maxChunkSize) {
    return [{ chunkIndex: 0, text: text, startChar: 0, endChar: text.length }];
  }

  const chunks = [];
  let start = 0;
  let index = 0;

  while (start < text.length) {
    let end = start + maxChunkSize;
    if (end < text.length) {
      // Try to break at a paragraph or sentence boundary
      const lastBreak = Math.max(text.lastIndexOf('\n', end), text.lastIndexOf('. ', end));
      if (lastBreak > start + 1000) {
        end = lastBreak + 1;
      }
    } else {
      end = text.length;
    }

    const chunkStr = text.slice(start, end).trim();
    if (chunkStr.length > 0) {
      chunks.push({
        chunkIndex: index,
        text: chunkStr,
        startChar: start,
        endChar: end
      });
      index++;
    }

    start = end - overlap;
    if (start >= text.length - overlap) break;
  }

  return chunks;
}

/**
 * Converts File or Blob to Uint8Array.
 * @param {File|Blob|ArrayBuffer|Uint8Array} fileInput 
 * @returns {Promise<Uint8Array>}
 */
async function fileToUint8Array(fileInput) {
  if (fileInput instanceof Uint8Array) return fileInput;
  if (fileInput instanceof ArrayBuffer) return new Uint8Array(fileInput);
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(fileInput)) return new Uint8Array(fileInput);
  
  if (fileInput.buffer) {
    if (fileInput.buffer instanceof ArrayBuffer) return new Uint8Array(fileInput.buffer);
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(fileInput.buffer)) {
      return new Uint8Array(fileInput.buffer.buffer, fileInput.buffer.byteOffset, fileInput.buffer.byteLength);
    }
  }

  if (typeof FileReader !== 'undefined' && (fileInput instanceof Blob || fileInput instanceof File)) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(new Uint8Array(reader.result));
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(fileInput);
    });
  }

  throw new Error('Unsupported file input structure');
}

/**
 * Unified text extraction entry point.
 * @param {Object|File} fileInput 
 * @returns {Promise<{fileName: string, fileType: string, fileSize: number, text: string, pages: Array, chunks: Array, unscannable: boolean, reason?: string}>}
 */
async function extractTextFromFile(fileInput) {
  const fileName = fileInput.name || fileInput.fileName || 'unknown_file';
  const fileSize = fileInput.size || (fileInput.buffer ? fileInput.buffer.byteLength : 0) || 0;
  const ext = fileName.split('.').pop().toLowerCase();
  const mimeType = (fileInput.type || '').toLowerCase();

  // 1. Unscannable Guardrail Check (Images, Audio, Binary, Compressed archives)
  const unscannableExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'zip', 'tar', 'gz', '7z', 'exe', 'bin', 'mp3', 'mp4'];
  if (unscannableExts.includes(ext) || mimeType.startsWith('image/') || mimeType.startsWith('audio/') || mimeType.startsWith('video/')) {
    return {
      fileName,
      fileType: ext || 'unscannable',
      fileSize,
      text: '',
      pages: [],
      chunks: [],
      unscannable: true,
      reason: `File format '.${ext}' is an image or unsupported binary format. Fail-Closed Security Policy active.`
    };
  }

  try {
    const bytes = await fileToUint8Array(fileInput);
    let result = { fullText: '', pages: [], unscannable: false };

    // 2. Plain Text Formats (.txt, .csv, .json, .md, .log, .xml)
    const textExts = ['txt', 'csv', 'json', 'md', 'log', 'xml', 'js', 'html', 'py'];
    if (textExts.includes(ext) || mimeType.startsWith('text/')) {
      const plainText = new TextDecoder('utf-8').decode(bytes);
      result = {
        fullText: plainText,
        pages: [{ page: 1, text: plainText }],
        unscannable: plainText.trim().length === 0
      };
    }
    // 3. PDF Documents (.pdf)
    else if (ext === 'pdf' || mimeType.includes('pdf')) {
      if (typeof extractPdfText === 'function') {
        result = extractPdfText(bytes);
      } else {
        result.unscannable = true;
        result.reason = 'PDF extraction module unavailable.';
      }
    }
    // 4. Word Documents (.docx)
    else if (ext === 'docx' || mimeType.includes('wordprocessingml')) {
      if (typeof extractDocxText === 'function') {
        result = extractDocxText(bytes);
      } else {
        result.unscannable = true;
        result.reason = 'DOCX extraction module unavailable.';
      }
    }
    // 5. Excel Spreadsheets (.xlsx, .xls)
    else if (ext === 'xlsx' || ext === 'xls' || mimeType.includes('spreadsheetml')) {
      if (typeof extractXlsxText === 'function') {
        result = extractXlsxText(bytes);
      } else {
        result.unscannable = true;
        result.reason = 'XLSX extraction module unavailable.';
      }
    }
    // 6. Unknown / Unrecognized Format
    else {
      result.unscannable = true;
      result.reason = `Unrecognized document extension '.${ext}'. Fail-Closed Security Policy active.`;
    }

    let text = result.fullText || '';

    // Apply text normalization to strip multi-line whitespace and boilerplate filler
    const normalizeFn = typeof normalizeText === 'function' 
      ? normalizeText 
      : (typeof globalThis !== 'undefined' && globalThis.normalizeText) 
        ? globalThis.normalizeText 
        : null;

    if (normalizeFn) {
      text = normalizeFn(text);
    }

    const chunks = chunkText(text, 8000, 600);

    return {
      fileName,
      fileType: ext,
      fileSize,
      text: text,
      pages: result.pages || [],
      chunks: chunks,
      unscannable: result.unscannable || text.trim().length === 0,
      reason: result.reason || (text.trim().length === 0 ? 'Empty text content extracted.' : undefined)
    };

  } catch (err) {
    console.error(`[AI Governance] Error extracting text from ${fileName}:`, err);
    return {
      fileName,
      fileType: ext,
      fileSize,
      text: '',
      pages: [],
      chunks: [],
      unscannable: true,
      reason: `Extraction exception: ${err.message}. Fail-Closed Policy active.`
    };
  }
}

// Universal Export Wrapper for Node.js, Web Worker, and Browser Contexts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractTextFromFile, chunkText };
}
if (typeof globalThis !== 'undefined') {
  globalThis.extractTextFromFile = extractTextFromFile;
  globalThis.chunkText = chunkText;
}
if (typeof self !== 'undefined') {
  self.extractTextFromFile = extractTextFromFile;
  self.chunkText = chunkText;
}
