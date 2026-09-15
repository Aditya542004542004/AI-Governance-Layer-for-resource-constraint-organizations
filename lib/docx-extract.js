/**
 * lib/docx-extract.js
 * 
 * Local client-side DOCX text extractor.
 * Parses OpenXML document zip structures (<w:t> tags) 100% offline.
 * Supports DEFLATE compressed zip streams via native DecompressionStream API.
 * Zero external network calls or remote dependencies.
 * 
 * License: BSD 2-Clause / MIT Compliant for bundling within Chrome Extensions.
 */

/**
 * Decompresses a DEFLATE raw byte stream using native browser API or Node zlib.
 * @param {Uint8Array} bytes 
 * @returns {Promise<Uint8Array|null>}
 */
async function decompressDeflateRaw(bytes) {
  // 1. Try Node.js zlib module if available (Node environment)
  if (typeof require !== 'undefined') {
    try {
      const zlib = require('zlib');
      const buf = (typeof Buffer !== 'undefined' && Buffer.isBuffer(bytes)) 
        ? bytes 
        : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      try {
        const decompressedBuf = zlib.inflateRawSync(buf);
        return new Uint8Array(decompressedBuf.buffer, decompressedBuf.byteOffset, decompressedBuf.byteLength);
      } catch (rawErr) {
        const decompressedBuf = zlib.inflateSync(buf);
        return new Uint8Array(decompressedBuf.buffer, decompressedBuf.byteOffset, decompressedBuf.byteLength);
      }
    } catch (_) {}
  }

  // 2. Try native browser DecompressionStream API
  if (typeof DecompressionStream !== 'undefined') {
    try {
      const ds = new DecompressionStream('deflate-raw');
      const writer = ds.writable.getWriter();
      writer.write(bytes);
      writer.close();
      const res = new Response(ds.readable);
      const buf = await res.arrayBuffer();
      return new Uint8Array(buf);
    } catch (err1) {
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
 * Parses XML text nodes (<w:t>...</w:t>) from an OpenXML string.
 * @param {string} xmlString 
 * @returns {Array<string>}
 */
function extractWtNodes(xmlString) {
  if (!xmlString || typeof xmlString !== 'string') return [];
  const wtRegex = /<w:t[^>]*>([\s\S]*?)<\/w:t>/g;
  const segments = [];
  let match;

  while ((match = wtRegex.exec(xmlString)) !== null) {
    const textContent = match[1]
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'");
    
    if (textContent.trim()) {
      segments.push(textContent.trim());
    }
  }
  return segments;
}

/**
 * Extracts text content from a DOCX binary buffer.
 * @param {Uint8Array} uint8Array 
 * @returns {Promise<{fullText: string, pages: Array, unscannable: boolean, reason?: string}>}
 */
async function extractDocxText(uint8Array) {
  if (!uint8Array || uint8Array.length === 0) {
    return {
      fullText: '',
      pages: [],
      unscannable: true,
      reason: 'DOCX_EMPTY_OR_UNREADABLE'
    };
  }

  const allSegments = [];

  // Phase 1: ZIP Archive Local File Header Traversal (PK\x03\x04)
  try {
    const len = uint8Array.length;
    let i = 0;

    while (i < len - 30) {
      // Local File Header Signature: 0x50 0x4B 0x03 0x04 ('PK\x03\x04')
      if (uint8Array[i] === 0x50 && uint8Array[i + 1] === 0x4b && uint8Array[i + 2] === 0x03 && uint8Array[i + 3] === 0x04) {
        const compressionMethod = uint8Array[i + 8] | (uint8Array[i + 9] << 8);
        const compressedSize = uint8Array[i + 18] | (uint8Array[i + 19] << 8) | (uint8Array[i + 20] << 16) | (uint8Array[i + 21] * 16777216);
        const nameLen = uint8Array[i + 26] | (uint8Array[i + 27] << 8);
        const extraLen = uint8Array[i + 28] | (uint8Array[i + 29] << 8);

        const fileNameBytes = uint8Array.subarray(i + 30, i + 30 + nameLen);
        const entryName = new TextDecoder('utf-8').decode(fileNameBytes);

        // Check if entry is a main text payload (word/document.xml, word/header*.xml, word/footer*.xml)
        if (entryName.includes('word/document.xml') || entryName.includes('word/header') || entryName.includes('word/footer')) {
          const dataStart = i + 30 + nameLen + extraLen;
          let dataEnd = dataStart + compressedSize;

          if (compressedSize === 0 || dataEnd > len) {
            // Find next PK signature if size is unstated or bit 3 descriptor active
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
            // Uncompressed (Stored)
            xmlString = new TextDecoder('utf-8').decode(entryBytes);
          } else if (compressionMethod === 8) {
            // DEFLATE compressed
            const decompressed = await decompressDeflateRaw(entryBytes);
            if (decompressed) {
              xmlString = new TextDecoder('utf-8').decode(decompressed);
            }
          }

          if (xmlString) {
            const extracted = extractWtNodes(xmlString);
            allSegments.push(...extracted);
          }
        }

        i = Math.max(i + 30 + nameLen + extraLen + Math.max(compressedSize, 0), i + 4);
      } else {
        i++;
      }
    }
  } catch (err) {
    console.warn('[AI Governance] ZIP traversal for DOCX encountered exception:', err);
  }

  // Phase 2: Fallback Uncompressed String Match (If ZIP traversal yielded zero segments)
  if (allSegments.length === 0) {
    const rawString = new TextDecoder('latin1').decode(uint8Array);
    const fallbackSegments = extractWtNodes(rawString);
    allSegments.push(...fallbackSegments);
  }

  const combinedText = allSegments.join(' ').replace(/\s+/g, ' ').trim();
  const isUnscannable = combinedText.length === 0;

  return {
    fullText: combinedText,
    pages: [{ page: 1, text: combinedText }],
    unscannable: isUnscannable,
    reason: isUnscannable ? 'DOCX_EMPTY_OR_UNREADABLE' : undefined
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractDocxText };
}
if (typeof globalThis !== 'undefined') {
  globalThis.extractDocxText = extractDocxText;
}
if (typeof self !== 'undefined') {
  self.extractDocxText = extractDocxText;
}
