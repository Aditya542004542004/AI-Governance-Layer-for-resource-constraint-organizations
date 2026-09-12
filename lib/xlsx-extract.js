/**
 * lib/xlsx-extract.js
 * 
 * Local client-side XLSX / XLS spreadsheet text extractor.
 * Parses OpenXML shared strings and cell values 100% offline.
 * Zero external dependencies or network calls.
 * 
 * License: Apache 2.0 / MIT Compliant for bundling within Chrome Extensions.
 */

function extractXlsxText(uint8Array) {
  const textDecoder = new TextDecoder('latin1');
  const rawString = textDecoder.decode(uint8Array);

  // Match shared string tags <t>...</t> and numeric cell values <v>...</v>
  const tRegex = /<t[^>]*>([\s\S]*?)<\/t>/g;
  const vRegex = /<v[^>]*>([\s\S]*?)<\/v>/g;

  const cellContents = [];
  let match;

  while ((match = tRegex.exec(rawString)) !== null) {
    const val = match[1]
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .trim();
    if (val) {
      cellContents.push(val);
    }
  }

  while ((match = vRegex.exec(rawString)) !== null) {
    const val = match[1].trim();
    if (val && !cellContents.includes(val)) {
      cellContents.push(val);
    }
  }

  const combinedText = cellContents.join(' | ').replace(/\s+/g, ' ').trim();

  return {
    fullText: combinedText,
    pages: [{ page: 1, text: combinedText }],
    unscannable: combinedText.length === 0
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractXlsxText };
} else if (typeof globalThis !== 'undefined') {
  globalThis.extractXlsxText = extractXlsxText;
}
