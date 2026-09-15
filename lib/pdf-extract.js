/**
 * lib/pdf-extract.js
 * 
 * Local client-side PDF text extractor.
 * Parses PDF binary structures, text objects (BT...ET), FlateDecode compressed streams,
 * string literals, and page object streams 100% offline.
 * Filters binary garbage streams and enforces Fail-Closed policy on unreadable PDF streams.
 * 
 * Zero external dependencies or network calls.
 * License: Apache 2.0 / MIT Compliant for bundling within Chrome Extensions.
 */

/**
 * Decompresses a DEFLATE / FlateDecode byte stream using zlib or DecompressionStream.
 * @param {Uint8Array} bytes 
 * @returns {Promise<Uint8Array|null>}
 */
async function decompressFlateStream(bytes) {
  if (!bytes || bytes.length === 0) return null;
  // 1. Node.js zlib
  if (typeof require !== 'undefined') {
    try {
      const zlib = require('zlib');
      const buf = (typeof Buffer !== 'undefined' && Buffer.isBuffer(bytes)) 
        ? bytes 
        : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      try {
        const decompressed = zlib.inflateSync(buf);
        return new Uint8Array(decompressed.buffer, decompressed.byteOffset, decompressed.byteLength);
      } catch (_) {
        const decompressed = zlib.inflateRawSync(buf);
        return new Uint8Array(decompressed.buffer, decompressed.byteOffset, decompressed.byteLength);
      }
    } catch (_) {}
  }
  // 2. Browser DecompressionStream API
  if (typeof DecompressionStream !== 'undefined') {
    try {
      const ds = new DecompressionStream('deflate');
      const writer = ds.writable.getWriter();
      writer.write(bytes);
      writer.close();
      const res = new Response(ds.readable);
      const buf = await res.arrayBuffer();
      return new Uint8Array(buf);
    } catch (_) {
      try {
        const ds = new DecompressionStream('deflate-raw');
        const writer = ds.writable.getWriter();
        writer.write(bytes);
        writer.close();
        const res = new Response(ds.readable);
        const buf = await res.arrayBuffer();
        return new Uint8Array(buf);
      } catch (_) {}
    }
  }
  return null;
}

/**
 * Validates extracted text string. Filters binary garbage or non-printable character bloat.
 * @param {string} text 
 * @returns {string} Sanitized string or empty if binary garbage.
 */
function sanitizeExtractedText(text) {
  if (!text || typeof text !== 'string') return '';
  // Strip control chars except newline, carriage return, and tab
  const cleaned = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, ' ').replace(/\s+/g, ' ').trim();
  if (cleaned.length === 0) return '';
  
  // Count ratio of printable ASCII / Latin-1 characters
  const printableMatches = cleaned.match(/[\x20-\x7E\s]/g) || [];
  const printableRatio = printableMatches.length / cleaned.length;

  // If over 30% of characters are non-printable extended binary gibberish, return empty
  if (printableRatio < 0.70) {
    return '';
  }
  return cleaned;
}

/**
 * Extracts text operators (Tj, TJ, ', ") and text blocks from a PDF text string or decompressed stream.
 * @param {string} pdfContent 
 * @returns {string}
 */
function parsePdfStreamText(pdfContent) {
  if (!pdfContent || typeof pdfContent !== 'string') return '';
  const textBlocks = [];

  // Match all text objects (BT ... ET)
  const btEtRegex = /BT[\s\S]*?ET/g;
  let match;

  while ((match = btEtRegex.exec(pdfContent)) !== null) {
    const block = match[0];
    
    // 1. Match string literals in parentheses ( ... ) Tj or ( ... ) TJ
    const strMatches = block.match(/\((?:[^()\\]|\\.)*\)/g) || [];
    for (const str of strMatches) {
      const cleanStr = str.slice(1, -1)
        .replace(/\\([()])/g, '$1')
        .replace(/\\n/g, '\n')
        .replace(/\\r/g, '\r')
        .replace(/\\t/g, '\t');

      const sanitized = sanitizeExtractedText(cleanStr);
      if (sanitized.length > 0) {
        textBlocks.push(sanitized);
      }
    }

    // 2. Match hex string literals in angle brackets < ... >
    const hexMatches = block.match(/<[0-9a-fA-F]+>/g) || [];
    for (const hexStr of hexMatches) {
      const hex = hexStr.slice(1, -1);
      if (hex.length % 2 === 0) {
        let decoded = '';
        for (let k = 0; k < hex.length; k += 2) {
          decoded += String.fromCharCode(parseInt(hex.substr(k, 2), 16));
        }
        const sanitized = sanitizeExtractedText(decoded);
        if (sanitized.length > 0) {
          textBlocks.push(sanitized);
        }
      }
    }
  }

  return sanitizeExtractedText(textBlocks.join(' '));
}

/**
 * Decompresses FlateDecode streams inside PDF binary buffer and extracts readable text.
 * @param {Uint8Array} uint8Array 
 * @returns {Promise<{fullText: string, pages: Array, unscannable: boolean, reason?: string}>}
 */
async function extractPdfText(uint8Array) {
  if (!uint8Array || uint8Array.length === 0) {
    return {
      fullText: '',
      pages: [],
      unscannable: true,
      reason: 'PDF_EMPTY_OR_UNREADABLE'
    };
  }

  let fullTextPages = [];
  const textDecoder = new TextDecoder('latin1');
  const pdfString = textDecoder.decode(uint8Array);

  // Phase 1: Decompress FlateDecode streams (stream ... endstream)
  try {
    const streamRegex = / stream[\r\n]+([\s\S]*?)[\r\n]+endstream/g;
    let streamMatch;

    while ((streamMatch = streamRegex.exec(pdfString)) !== null) {
      const streamStartPos = streamMatch.index + streamMatch[0].indexOf('stream') + 6;
      let dataStart = streamStartPos;
      if (uint8Array[dataStart] === 13) dataStart++; // \r
      if (uint8Array[dataStart] === 10) dataStart++; // \n

      const endStreamPos = streamMatch.index + streamMatch[0].lastIndexOf('endstream');
      let dataEnd = endStreamPos;
      if (dataEnd > dataStart && uint8Array[dataEnd - 1] === 10) dataEnd--;
      if (dataEnd > dataStart && uint8Array[dataEnd - 1] === 13) dataEnd--;

      if (dataEnd > dataStart) {
        const compressedStreamBytes = uint8Array.subarray(dataStart, dataEnd);
        const decompressedBytes = await decompressFlateStream(compressedStreamBytes);

        if (decompressedBytes && decompressedBytes.length > 0) {
          const decompressedText = new TextDecoder('utf-8').decode(decompressedBytes);
          const extractedStreamText = parsePdfStreamText(decompressedText);
          if (extractedStreamText.length > 0) {
            fullTextPages.push({ page: fullTextPages.length + 1, text: extractedStreamText });
          }
        }
      }
    }
  } catch (err) {
    console.warn('[AI Governance] Error decompressing FlateDecode PDF streams:', err);
  }

  // Phase 2: Uncompressed PDF Page Object Parsing (/Type /Page)
  if (fullTextPages.length === 0) {
    const pageParts = pdfString.split(/\/Type\s*\/Page\b/i);
    for (let i = 1; i < pageParts.length; i++) {
      const pageText = parsePdfStreamText(pageParts[i]);
      if (pageText.length > 0) {
        fullTextPages.push({ page: i, text: pageText });
      }
    }
  }

  // Phase 3: Global Uncompressed Stream Fallback
  if (fullTextPages.length === 0) {
    const fallbackText = parsePdfStreamText(pdfString);
    if (fallbackText.length > 0) {
      fullTextPages.push({ page: 1, text: fallbackText });
    }
  }

  const combinedText = sanitizeExtractedText(fullTextPages.map(p => p.text).join('\n\n'));
  const isUnscannable = combinedText.length === 0;

  return {
    fullText: combinedText,
    pages: fullTextPages,
    unscannable: isUnscannable,
    reason: isUnscannable ? 'PDF_EMPTY_OR_UNREADABLE (Unscannable image, encrypted, or compressed stream). Fail-Closed active.' : undefined
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractPdfText, parsePdfStreamText, sanitizeExtractedText };
}
if (typeof globalThis !== 'undefined') {
  globalThis.extractPdfText = extractPdfText;
  globalThis.parsePdfStreamText = parsePdfStreamText;
  globalThis.sanitizeExtractedText = sanitizeExtractedText;
}
if (typeof self !== 'undefined') {
  self.extractPdfText = extractPdfText;
  self.parsePdfStreamText = parsePdfStreamText;
  self.sanitizeExtractedText = sanitizeExtractedText;
}
