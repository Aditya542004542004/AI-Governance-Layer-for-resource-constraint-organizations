/**
 * lib/pdf-extract.js
 * 
 * Local client-side PDF text extractor.
 * Parses PDF binary structures, text objects (BT...ET), string literals, and page streams 100% offline.
 * Zero external dependencies or network calls.
 * 
 * License: Apache 2.0 / MIT Compliant for bundling within Chrome Extensions.
 */

function parsePdfStreamText(pdfContent) {
  const textBlocks = [];
  const btEtRegex = /BT[\s\S]*?ET/g;
  let match;

  while ((match = btEtRegex.exec(pdfContent)) !== null) {
    const block = match[0];
    
    // Match string literals in parentheses ( ... )
    const strMatches = block.match(/\((?:[^()\\]|\\.)*\)/g) || [];
    for (const str of strMatches) {
      const cleanStr = str.slice(1, -1)
        .replace(/\\([()])/g, '$1')
        .replace(/\\n/g, '\n')
        .replace(/\\r/g, '\r')
        .replace(/\\t/g, '\t');
      if (cleanStr.trim()) {
        textBlocks.push(cleanStr);
      }
    }

    // Match hex string literals in angle brackets < ... >
    const hexMatches = block.match(/<[0-9a-fA-F]+>/g) || [];
    for (const hexStr of hexMatches) {
      const hex = hexStr.slice(1, -1);
      let decoded = '';
      for (let k = 0; k < hex.length; k += 2) {
        decoded += String.fromCharCode(parseInt(hex.substr(k, 2), 16));
      }
      if (decoded.trim()) {
        textBlocks.push(decoded.trim());
      }
    }
  }

  return textBlocks.join(' ').replace(/\s+/g, ' ').trim();
}

function extractPdfText(uint8Array) {
  const textDecoder = new TextDecoder('latin1');
  const pdfString = textDecoder.decode(uint8Array);

  const pageParts = pdfString.split(/\/Type\s*\/Page\b/i);
  const fullTextPages = [];

  for (let i = 1; i < pageParts.length; i++) {
    const pageText = parsePdfStreamText(pageParts[i]);
    if (pageText.length > 0) {
      fullTextPages.push({ page: i, text: pageText });
    }
  }

  if (fullTextPages.length === 0) {
    const fallbackText = parsePdfStreamText(pdfString);
    if (fallbackText.length > 0) {
      fullTextPages.push({ page: 1, text: fallbackText });
    }
  }

  const combinedText = fullTextPages.map(p => p.text).join('\n\n');

  return {
    fullText: combinedText,
    pages: fullTextPages,
    unscannable: combinedText.length === 0
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractPdfText, parsePdfStreamText };
} else if (typeof globalThis !== 'undefined') {
  globalThis.extractPdfText = extractPdfText;
}
