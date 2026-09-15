/**
 * lib/docx-extract.js
 * 
 * Local client-side DOCX text extractor.
 * Parses OpenXML document structures (<w:t> tags) 100% offline.
 * Zero external dependencies or network calls.
 * 
 * License: BSD 2-Clause / MIT Compliant for bundling within Chrome Extensions.
 */

function extractDocxText(uint8Array) {
  const textDecoder = new TextDecoder('latin1');
  const rawString = textDecoder.decode(uint8Array);

  // Match all OpenXML text node tags <w:t>...</w:t>
  const wtRegex = /<w:t[^>]*>([\s\S]*?)<\/w:t>/g;
  const textSegments = [];
  let match;

  while ((match = wtRegex.exec(rawString)) !== null) {
    const textContent = match[1]
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'");
    
    if (textContent.trim()) {
      textSegments.push(textContent.trim());
    }
  }

  const combinedText = textSegments.join(' ').replace(/\s+/g, ' ').trim();
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
} else if (typeof globalThis !== 'undefined') {
  globalThis.extractDocxText = extractDocxText;
}
