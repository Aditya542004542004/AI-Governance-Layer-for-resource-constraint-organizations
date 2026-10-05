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

/**
 * Validates an Indian Permanent Account Number (PAN Card).
 * Format: 5 uppercase letters, 4 digits, 1 uppercase letter (e.g. ABCPE1234F).
 * 4th character must be one of the registered entity types:
 * P (Person), C (Company), H (HUF), F (Firm), A (AOP), T (Trust), B (BOI), L (Local), J (Artificial Juridical), G (Government).
 */
function validatePan(pan) {
  if (!pan || typeof pan !== 'string' || pan.length !== 10) return false;
  const entityType = pan.charAt(3).toUpperCase();
  return 'PCHFATBLJG'.includes(entityType);
}

/**
 * Validates an International Bank Account Number (IBAN) using the ISO 13616 / MOD-97 algorithm.
 */
function validateIban(ibanStr) {
  if (!ibanStr || typeof ibanStr !== 'string') return false;
  const clean = ibanStr.replace(/[\s-]/g, '').toUpperCase();
  if (clean.length < 15 || clean.length > 34) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(clean)) return false;

  const rearranged = clean.slice(4) + clean.slice(0, 4);
  let numericStr = '';
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    if (code >= 65 && code <= 90) {
      numericStr += (code - 55).toString();
    } else {
      numericStr += rearranged[i];
    }
  }

  let remainder = 0;
  for (let i = 0; i < numericStr.length; i += 7) {
    const chunk = remainder.toString() + numericStr.substring(i, i + 7);
    remainder = parseInt(chunk, 10) % 97;
  }
  return remainder === 1;
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
    category: 'private_key',
    label: 'Cryptographic Private Key (PEM/SSH/RSA)',
    pattern: /(?:-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)/gi,
    severity: 'critical'
  },
  {
    category: 'jwt_token',
    label: 'JSON Web Token (JWT) / Bearer Credential',
    pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,
    severity: 'critical'
  },
  {
    category: 'cvv_code',
    label: 'Card Security Code (CVV/CVC)',
    pattern: /\b(?:cvv[2]?|cvc[2]?|cid|security\s*code)\s*[:=is\s]+['"]?\b(\d{3,4})\b['"]?/gi,
    severity: 'critical'
  },
  {
    category: 'email',
    label: 'Email Address',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    severity: 'medium'
  },
  {
    category: 'pan',
    label: 'Permanent Account Number (Indian PAN Card)',
    pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
    validate: (matchStr) => validatePan(matchStr),
    severity: 'medium'
  },
  {
    category: 'iban',
    label: 'International Bank Account Number (IBAN)',
    pattern: /\b[A-Z]{2}[0-9]{2}(?:[0-9A-Za-z]{11,30}|(?:\s[0-9A-Za-z]{4}){2,7}(?:\s[0-9A-Za-z]{1,4})?)\b/g,
    validate: (matchStr) => validateIban(matchStr),
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
    category: 'pii',
    label: 'Author / Researcher Identity (PII)',
    pattern: /\b(?:authors?|researchers?|investigators?|corresponding\s+author|affiliations?|department\s+of)\s*[:=]\s*[^\n\r]{3,120}/gi,
    severity: 'medium'
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

  // Pre-clean text to repair broken OCR spaces (e.g. "name @ domain . com" -> "name@domain.com")
  let cleanText = text;
  if (typeof cleanOcrText === 'function') {
    cleanText = cleanOcrText(text);
  } else if (typeof globalThis !== 'undefined' && typeof globalThis.cleanOcrText === 'function') {
    cleanText = globalThis.cleanOcrText(text);
  } else {
    // Inline minimal OCR repair for email address spaces
    cleanText = text
      .replace(/([a-zA-Z0-9._%+-]+)\s*@\s*([a-zA-Z0-9.-]+)/g, '$1@$2')
      .replace(/@([a-zA-Z0-9.-]+)\s*\.\s*([a-zA-Z]{2,})/g, '@$1.$2');
  }

  const results = [];

  for (const config of REGEX_CONFIG) {
    // Reset regex lastIndex state
    config.pattern.lastIndex = 0;
    let match;

    while ((match = config.pattern.exec(cleanText)) !== null) {
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
  module.exports = { runRegexChecks, luhnCheck, validatePan, validateIban, REGEX_CONFIG };
} else if (typeof globalThis !== 'undefined') {
  globalThis.runRegexChecks = runRegexChecks;
  globalThis.validatePan = validatePan;
  globalThis.validateIban = validateIban;
}
