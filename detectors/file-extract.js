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
    const pptxLib = require('../lib/pptx-extract.js');
    const preprocess = require('../engine/preprocess.js');
    globalThis.extractPdfText = pdfLib.extractPdfText;
    globalThis.extractDocxText = docxLib.extractDocxText;
    globalThis.extractXlsxText = xlsxLib.extractXlsxText;
    globalThis.extractPptxText = pptxLib.extractPptxText;
    if (preprocess.buildLAAWWindows) {
      globalThis.buildLAAWWindows = preprocess.buildLAAWWindows;
    }
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
    if (fileInput.buffer instanceof Uint8Array) return fileInput.buffer;
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
 * Checks whether raw bytes represent valid UTF-8 plain text rather than compiled binary.
 * Inspects a sample for null bytes (\0) and validates UTF-8 decoding.
 * @param {Uint8Array} uint8Array 
 * @returns {boolean}
 */
function isLikelyTextContent(uint8Array) {
  if (!uint8Array || uint8Array.length === 0) return true;
  const sampleSize = Math.min(uint8Array.length, 2048);
  let nullByteCount = 0;
  for (let i = 0; i < sampleSize; i++) {
    if (uint8Array[i] === 0) nullByteCount++;
  }
  if (nullByteCount > 0) return false;

  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    decoder.decode(uint8Array.subarray(0, sampleSize));
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * Extracts source code, markdown narrative, and cell outputs from a Jupyter Notebook (.ipynb) JSON.
 * @param {string} rawJson 
 * @returns {string} Concatenated code and markdown text
 */
function extractIpynbText(rawJson) {
  try {
    const nb = typeof rawJson === 'string' ? JSON.parse(rawJson) : rawJson;
    if (nb && Array.isArray(nb.cells)) {
      const parts = [];
      for (const cell of nb.cells) {
        const type = cell.cell_type || 'code';
        const src = Array.isArray(cell.source) ? cell.source.join('') : (cell.source || '');
        if (src.trim()) {
          parts.push(`[NOTEBOOK_${type.toUpperCase()}_CELL]\n${src}`);
        }
        // Inspect cell execution outputs for leaked tokens or data
        if (Array.isArray(cell.outputs)) {
          for (const out of cell.outputs) {
            if (out.text) {
              const outTxt = Array.isArray(out.text) ? out.text.join('') : (out.text || '');
              if (outTxt && outTxt.trim()) parts.push(`[CELL_OUTPUT]\n${outTxt}`);
            } else if (out.data && out.data['text/plain']) {
              const dataTxt = Array.isArray(out.data['text/plain']) ? out.data['text/plain'].join('') : out.data['text/plain'];
              if (dataTxt && dataTxt.trim()) parts.push(`[CELL_OUTPUT]\n${dataTxt}`);
            }
          }
        }
      }
      return parts.join('\n\n');
    }
  } catch (_) {}
  return typeof rawJson === 'string' ? rawJson : '';
}

/**
 * Unified text extraction entry point.
 * @param {Object|File} fileInput 
 * @returns {Promise<{fileName: string, fileType: string, fileSize: number, text: string, pages: Array, chunks: Array, unscannable: boolean, reason?: string, isFolderOrDirectory?: boolean}>}
 */
async function extractTextFromFile(fileInput) {
  const fileName = fileInput.name || fileInput.fileName || 'unknown_file';
  const fileSize = fileInput.size || (fileInput.buffer ? fileInput.buffer.byteLength : 0) || 0;
  const ext = fileName.split('.').pop().toLowerCase();
  const mimeType = (fileInput.type || '').toLowerCase();

  // 0. Directory Container or Virtual Shelf Item Check (e.g. 'Downloads')
  if ((!fileName.includes('.') && fileSize === 0) || fileName.toLowerCase() === 'downloads') {
    return {
      fileName,
      fileType: 'directory',
      fileSize: 0,
      text: '',
      pages: [],
      chunks: [],
      unscannable: false,
      isFolderOrDirectory: true
    };
  }

  // 1. Unscannable Guardrail Check (Images, Audio, Binary, Compressed archives)
  const unscannableExts = [
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'zip', 'tar', 'gz', '7z', 'rar', 'bz2',
    'exe', 'bin', 'dll', 'so', 'dylib', 'iso', 'mp3', 'mp4', 'wav', 'ogg', 'mov', 'avi',
    'woff', 'woff2', 'ttf', 'eot'
  ];
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

    // 2. Comprehensive Plain Text & Code Formats
    const textExts = [
      'txt', 'text', 'env', 'csv', 'tsv', 'json', 'json5', 'jsonc', 'ipynb',
      'md', 'markdown', 'log', 'out', 'xml', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx',
      'html', 'htm', 'xhtml', 'svg', 'css', 'scss', 'sass', 'less',
      'py', 'pyw', 'yaml', 'yml', 'toml', 'ini', 'conf', 'cfg', 'config', 'properties',
      'sh', 'bash', 'zsh', 'fish', 'bat', 'cmd', 'ps1', 'psm1',
      'c', 'h', 'cpp', 'hpp', 'cc', 'cxx', 'cs', 'java', 'kt', 'kts', 'scala', 'go', 'rs', 'swift', 'rb', 'php', 'lua', 'r', 'dart', 'pl', 'pm',
      'sql', 'prisma', 'graphql', 'gql', 'proto',
      'dockerfile', 'makefile', 'cmake', 'vagrantfile', 'gemfile', 'pipfile', 'lock',
      'pem', 'key', 'cer', 'crt', 'pub'
    ];

    const isEnvFile = fileName.startsWith('.env') || ext === 'env' || ext.startsWith('env') || fileName.endsWith('.env');
    const isIpynb = ext === 'ipynb' || fileName.endsWith('.ipynb');
    const isXmlMime = mimeType === 'text/xml' || mimeType === 'application/xml' || mimeType.endsWith('/xml');
    const isTextMime = mimeType.startsWith('text/') || mimeType.includes('json') || mimeType.includes('javascript') || isXmlMime;
    const isKnownTextExt = isEnvFile || isIpynb || textExts.includes(ext);

    // Dynamic heuristic text sniffing for extensionless or uncommon text formats
    const isSniffedText = !isKnownTextExt && isLikelyTextContent(bytes);

    if (isKnownTextExt || isTextMime || isSniffedText) {
      let plainText = new TextDecoder('utf-8').decode(bytes);
      if (isIpynb) {
        plainText = extractIpynbText(plainText);
      }
      result = {
        fullText: plainText,
        pages: [{ page: 1, text: plainText }],
        unscannable: false
      };
    }
    // 3. PDF Documents (.pdf)
    else if (ext === 'pdf' || mimeType.includes('pdf')) {
      if (typeof extractPdfText === 'function') {
        result = await extractPdfText(bytes);
      } else {
        result.unscannable = true;
        result.reason = 'PDF extraction module unavailable.';
      }
    }
    // 4. Word Documents (.docx)
    else if (ext === 'docx' || mimeType.includes('wordprocessingml')) {
      if (typeof extractDocxText === 'function') {
        result = await extractDocxText(bytes);
      } else {
        result.unscannable = true;
        result.fullText = '';
        result.reason = 'DOCX extraction module unavailable (UNSCANNABLE_BINARY). Fail-Closed active.';
      }
    }
    // 5. Excel Spreadsheets (.xlsx, .xls)
    else if (ext === 'xlsx' || ext === 'xls' || mimeType.includes('spreadsheetml')) {
      if (typeof extractXlsxText === 'function') {
        result = await extractXlsxText(bytes);
      } else {
        result.unscannable = true;
        result.fullText = '';
        result.reason = 'XLSX extraction module unavailable (UNSCANNABLE_BINARY). Fail-Closed active.';
      }
    }
    // 6. PowerPoint Presentations (.pptx, .ppt)
    else if (ext === 'pptx' || ext === 'ppt' || mimeType.includes('presentationml')) {
      if (typeof extractPptxText === 'function') {
        result = await extractPptxText(bytes);
      } else {
        result.unscannable = true;
        result.fullText = '';
        result.reason = 'PPTX extraction module unavailable (UNSCANNABLE_BINARY). Fail-Closed active.';
      }
    }
    // 7. Unknown / Unrecognized Binary Format
    else {
      result.unscannable = true;
      result.fullText = '';
      result.reason = `Unrecognized document extension '.${ext}' (UNSCANNABLE_BINARY). Fail-Closed Security Policy active.`;
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

    const laawFn = typeof buildLAAWWindows === 'function' 
      ? buildLAAWWindows 
      : (typeof globalThis !== 'undefined' && globalThis.buildLAAWWindows) 
        ? globalThis.buildLAAWWindows 
        : null;

    const chunks = laawFn ? laawFn(text, 1500, 400) : chunkText(text, 8000, 600);

    const isTextDoc = isKnownTextExt || isTextMime || isSniffedText;
    const isUnscannable = result.unscannable || (!isTextDoc && text.trim().length === 0);

    return {
      fileName,
      fileType: ext,
      fileSize,
      text: text,
      pages: result.pages || [],
      chunks: chunks,
      unscannable: isUnscannable,
      reason: result.reason || (isUnscannable ? 'Unscannable or empty binary format.' : undefined)
    };

  } catch (err) {
    const isNotFoundOrDir = err.name === 'NotFoundError' || err.message?.includes('could not be found');
    if (isNotFoundOrDir) {
      console.warn(`[AI Governance] Skipped directory or unreadable virtual container: ${fileName}`);
      return {
        fileName,
        fileType: ext || 'directory',
        fileSize: 0,
        text: '',
        pages: [],
        chunks: [],
        unscannable: false,
        isFolderOrDirectory: true
      };
    }
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

const laawExport = typeof buildLAAWWindows !== 'undefined' ? buildLAAWWindows : (typeof globalThis !== 'undefined' ? globalThis.buildLAAWWindows : null);

// Universal Export Wrapper for Node.js, Web Worker, and Browser Contexts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractTextFromFile, chunkText, buildLAAWWindows: laawExport };
}
if (typeof globalThis !== 'undefined') {
  globalThis.extractTextFromFile = extractTextFromFile;
  globalThis.chunkText = chunkText;
  globalThis.buildLAAWWindows = laawExport;
}
if (typeof self !== 'undefined') {
  self.extractTextFromFile = extractTextFromFile;
  self.chunkText = chunkText;
  self.buildLAAWWindows = laawExport;
}
