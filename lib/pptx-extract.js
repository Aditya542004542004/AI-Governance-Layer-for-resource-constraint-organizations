/**
 * lib/pptx-extract.js
 * 
 * Local client-side PPTX presentation text extractor.
 * Parses OpenXML slide structures (<a:t> tags) 100% offline.
 * Supports DEFLATE compressed zip streams via native DecompressionStream API.
 * Zero external network calls or remote dependencies.
 * 
 * License: Apache 2.0 / MIT Compliant for bundling within Chrome Extensions.
 */

/**
 * Decompresses a DEFLATE raw byte stream using native browser API or Node zlib.
 * @param {Uint8Array} bytes 
 * @returns {Promise<Uint8Array|null>}
 */
async function decompressDeflateRaw(bytes) {
  if (typeof require !== 'undefined') {
    try {
      const zlib = require('zlib');
      const buf = (typeof Buffer !== 'undefined' && Buffer.isBuffer(bytes)) 
        ? bytes 
        : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      try {
        const decompressed = zlib.inflateRawSync(buf);
        return new Uint8Array(decompressed.buffer, decompressed.byteOffset, decompressed.byteLength);
      } catch (_) {
        const decompressed = zlib.inflateSync(buf);
        return new Uint8Array(decompressed.buffer, decompressed.byteOffset, decompressed.byteLength);
      }
    } catch (_) {}
  }
  if (typeof DecompressionStream !== 'undefined') {
    try {
      const ds = new DecompressionStream('deflate-raw');
      const writer = ds.writable.getWriter();
      writer.write(bytes);
      writer.close();
      const res = new Response(ds.readable);
      const buf = await res.arrayBuffer();
      return new Uint8Array(buf);
    } catch (_) {
      try {
        const ds = new DecompressionStream('deflate');
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
 * Parses XML text nodes (<a:t>...</a:t>) from an OpenXML slide string.
 * @param {string} xmlString 
 * @returns {Array<string>}
 */
function extractAtNodes(xmlString) {
  if (!xmlString || typeof xmlString !== 'string') return [];
  const atRegex = /<a:t[^>]*>([\s\S]*?)<\/a:t>/g;
  const segments = [];
  let match;

  while ((match = atRegex.exec(xmlString)) !== null) {
    const val = match[1]
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .trim();
    if (val) {
      segments.push(val);
    }
  }
  return segments;
}

/**
 * Extracts text content from a PPTX binary buffer.
 * @param {Uint8Array} uint8Array 
 * @returns {Promise<{fullText: string, pages: Array, unscannable: boolean, reason?: string}>}
 */
async function extractPptxText(uint8Array) {
  if (!uint8Array || uint8Array.length === 0) {
    return {
      fullText: '',
      pages: [],
      unscannable: true,
      reason: 'PPTX_EMPTY_OR_UNREADABLE'
    };
  }

  const slideSegments = [];

  // Phase 1: ZIP Archive Local File Header Traversal (PK\x03\x04)
  try {
    const len = uint8Array.length;
    let i = 0;

    while (i < len - 30) {
      if (uint8Array[i] === 0x50 && uint8Array[i + 1] === 0x4b && uint8Array[i + 2] === 0x03 && uint8Array[i + 3] === 0x04) {
        const compressionMethod = uint8Array[i + 8] | (uint8Array[i + 9] << 8);
        const compressedSize = uint8Array[i + 18] | (uint8Array[i + 19] << 8) | (uint8Array[i + 20] << 16) | (uint8Array[i + 21] * 16777216);
        const nameLen = uint8Array[i + 26] | (uint8Array[i + 27] << 8);
        const extraLen = uint8Array[i + 28] | (uint8Array[i + 29] << 8);

        const fileNameBytes = uint8Array.subarray(i + 30, i + 30 + nameLen);
        const entryName = new TextDecoder('utf-8').decode(fileNameBytes);

        if (entryName.includes('ppt/slides/') || entryName.includes('ppt/notesSlides/') || entryName.includes('ppt/presentation.xml')) {
          const dataStart = i + 30 + nameLen + extraLen;
          let dataEnd = dataStart + compressedSize;

          if (compressedSize === 0 || dataEnd > len) {
            let nextSig = len;
            for (let j = dataStart + 1; j < len - 4; j++) {
              if (uint8Array[j] === 0x50 && uint8Array[j + 1] === 0x4b) {
                nextSig = j;
                break;
              }
            }
            dataEnd = nextSig;
          }

          const entryBytes = uint8Array.subarray(dataStart, dataEnd);
          let xmlString = '';

          if (compressionMethod === 0) {
            xmlString = new TextDecoder('utf-8').decode(entryBytes);
          } else if (compressionMethod === 8) {
            const decompressed = await decompressDeflateRaw(entryBytes);
            if (decompressed) {
              xmlString = new TextDecoder('utf-8').decode(decompressed);
            }
          }

          if (xmlString) {
            const nodes = extractAtNodes(xmlString);
            slideSegments.push(...nodes);
          }
        }

        i = Math.max(i + 30 + nameLen + extraLen + Math.max(compressedSize, 0), i + 4);
      } else {
        i++;
      }
    }
  } catch (err) {
    console.warn('[AI Governance] ZIP traversal for PPTX exception:', err);
  }

  // Phase 2: Fallback Uncompressed String Match
  if (slideSegments.length === 0) {
    const rawString = new TextDecoder('latin1').decode(uint8Array);
    const fallbackNodes = extractAtNodes(rawString);
    slideSegments.push(...fallbackNodes);
  }

  const combinedText = slideSegments.join(' ').replace(/\s+/g, ' ').trim();
  const isUnscannable = combinedText.length === 0;

  return {
    fullText: combinedText,
    pages: [{ page: 1, text: combinedText }],
    unscannable: isUnscannable,
    reason: isUnscannable ? 'PPTX_EMPTY_OR_UNREADABLE' : undefined
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractPptxText };
}
if (typeof globalThis !== 'undefined') {
  globalThis.extractPptxText = extractPptxText;
}
if (typeof self !== 'undefined') {
  self.extractPptxText = extractPptxText;
}
