/**
 * detectors/regex.js
 * 
 * Intercepts and scans prompt text for structured sensitive patterns
 * using native JavaScript RegExp engine. No external libraries used.
 * Includes Luhn algorithm validation for credit card detection.
 */

// Common English technical/academic dictionary words that should never be flagged as secret API tokens
const COMMON_ENGLISH_WORDS = new Set([
  'imported', 'attached', 'generated', 'implementation', 'protocol', 'management',
  'variable', 'framework', 'function', 'server', 'endpoint', 'system', 'process',
  'services', 'security', 'database', 'overview', 'architecture', 'application',
  'component', 'interface', 'configuration', 'parameter', 'response', 'request',
  'payload', 'research', 'encrypted', 'encryption', 'algorithm', 'operation',
  'operations', 'generation', 'authentication', 'verification', 'mechanism',
  'pipeline', 'definition', 'execution', 'interception', 'middleware'
]);

/**
 * Validates API Key matches to discard false positives on standard English prose.
 */
function validateApiKeyMatch(matchStr) {
  if (!matchStr || typeof matchStr !== 'string') return false;
  
  const parts = matchStr.split(/[:=]|\bis\b/i);
  if (parts.length > 1) {
    const candidate = parts[parts.length - 1].trim().replace(/^['"]|['"]$/g, '').toLowerCase();
    if (COMMON_ENGLISH_WORDS.has(candidate)) {
      return false; // Discard false positive English prose matches
    }
  }
  return true;
}

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
    // Known Vendor API tokens with strict prefixes (sk-..., AKIA..., AIza..., ghp_..., xox..., ya29..., AQ...) & strict assignment operators with optional quotes for secret keys
    pattern: /\b(?:sk-(?:proj-|ant-)?[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{20,}|gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[a-zA-Z0-9]{10,}|ya29\.[a-zA-Z0-9_-]{50,}|AQ[a-zA-Z0-9_-]{40,})\b|(?:[A-Za-z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN|AUTH|PASS|CREDENTIAL|PRIVATE|DATABASE_URL|DB_URL)[A-Za-z0-9_]*)\s*[:=]\s*['"]?[a-zA-Z0-9_.:/@\-]{8,}['"]?/gi,
    validate: (matchStr) => validateApiKeyMatch(matchStr),
    severity: 'critical'
  },
  {
    category: 'database_url',
    label: 'Database Connection String',
    // Matches Database URIs: mysql://, postgres://, mongodb://, redis://, etc.
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|oracle|sqlite):\/\/[^\s'"]{8,}\b/gi,
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
    label: 'ATM PIN / Password / Secret Passcode',
    // Requires explicit assignment syntax or strict pin assignment keywords
    pattern: /\b(?:atm\s*pin|my\s*pin|pin\s*code|passcode)\s*[:=is\s]+\b(\d{4,8})\b|\b(?:pin|passcode|password)\s*[:=]\s*['"]?([a-zA-Z0-9!@#$%^&*_-]{4,32})['"]?\b/gi,
    severity: 'critical'
  },
  {
    category: 'potential_credential',
    label: 'Unverified Credential Pattern',
    // Matches "api key", "token", "secret", "password" followed by non-delimited strings (8+ chars)
    pattern: /\b(?:(?:this\s+is\s+)?(?:my\s+)?(?:api|secret|access|auth)[\s_-]*(?:key|token|code)|password|passcode)\s*[:=is\s]+([a-zA-Z0-9_\-]{8,})\b/gi,
    validate: (matchStr) => {
      // Extract the trailing candidate token
      const parts = matchStr.split(/[:=is\s]+/i).filter(Boolean);
      if (parts.length === 0) return false;
      const candidate = parts[parts.length - 1].trim().replace(/^['"]|['"]$/g, '').toLowerCase();

      // 1. If the token is a standard English/technical dictionary word, DISCARD (False Positive on prose)
      if (COMMON_ENGLISH_WORDS.has(candidate)) {
        return false;
      }

      // 2. Discard purely numeric years or small integers (e.g. 2022, 2023)
      if (/^\d{1,4}$/.test(candidate)) {
        return false;
      }

      return true;
    },
    severity: 'low' // Explicitly LOW severity so it does NOT trigger Fixed Security Floor
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
