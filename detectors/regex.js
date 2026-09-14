/**
 * detectors/regex.js
 * 
 * Intercepts and scans prompt text for structured sensitive patterns
 * using native JavaScript RegExp engine. No external libraries used.
 * Includes Luhn algorithm validation for credit card detection.
 */

// Configurable regex patterns and detection definitions
const REGEX_CONFIG = [
  {
    category: 'credit_card',
    label: 'Credit Card Number',
    // Matches 13-19 digit card patterns with optional dashes or spaces
    pattern: /\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{1,4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|\d{13,19})\b/g,
    validate: (matchStr) => luhnCheck(matchStr),
    severity: 'critical'
  },
  {
    category: 'email',
    label: 'Email Address',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    severity: 'medium'
  },
  {
    category: 'api_key',
    label: 'API Secret / Key',
    // OpenAI keys (sk-...), AWS Access Keys (AKIA...), Bearer tokens, and explicit key assignments
    pattern: /\b(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|[a-zA-Z0-9_-]{32,}|(?:(?:this\s+is\s+)?(?:my\s+)?(?:api|secret|access|auth|bearer)[\s_-]*(?:key|token|code)?)\s*(?:is|:|=)?\s*[a-zA-Z0-9_-]{8,})\b/gi,
    severity: 'critical'
  },
  {
    category: 'national_id',
    label: 'National Identity / Social Security Number',
    // US SSN (XXX-XX-XXXX) or Indian Aadhaar (XXXX XXXX XXXX / 12 digits)
    pattern: /\b(?:\d{3}-\d{2}-\d{4}|\d{4}\s?\d{4}\s?\d{4})\b/g,
    severity: 'high'
  },
  {
    category: 'phone',
    label: 'Phone Number',
    // US and international standard phone formats
    pattern: /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    severity: 'low'
  },
  {
    category: 'pin_passcode',
    label: 'ATM PIN / Secret Passcode',
    // Matches explicit mentions of PIN / Passcode followed by 4 to 8 digits
    pattern: /\b(?:pin|passcode|p\.i\.n\.|atm\s*pin|secret\s*code)\s*(?:is|:|=)?\s*(\d{4,8})\b/gi,
    severity: 'high'
  }
];

/**
 * Validates a numerical card string using the Luhn Algorithm.
 * @param {string} val 
 * @returns {boolean}
 */
function luhnCheck(val) {
  const digits = val.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  
  let sum = 0;
  let shouldDouble = false;
  
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  
  return sum % 10 === 0;
}

/**
 * Scans input text against configured regex rules.
 * @param {string} text - Prompt text to inspect
 * @returns {Array<{category: string, label: string, match: string, index: number, severity: string}>}
 */
function runRegexChecks(text) {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const results = [];

  for (const config of REGEX_CONFIG) {
    // Reset regex lastIndex state
    config.pattern.lastIndex = 0;
    let match;

    while ((match = config.pattern.exec(text)) !== null) {
      const matchedString = match[0];

      // Execute custom validation function if present (e.g. Luhn algorithm for credit cards)
      if (config.validate && !config.validate(matchedString)) {
        continue;
      }

      results.push({
        category: config.category,
        label: config.label,
        match: matchedString,
        index: match.index,
        severity: config.severity
      });
    }
  }

  return results;
}

// Support both ES Modules and script environment exports
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { runRegexChecks, luhnCheck, REGEX_CONFIG };
} else if (typeof globalThis !== 'undefined') {
  globalThis.runRegexChecks = runRegexChecks;
}
