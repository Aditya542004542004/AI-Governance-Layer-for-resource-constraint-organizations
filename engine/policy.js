/**
 * engine/policy.js
 * 
 * Two-Layer Policy Decision Engine:
 * Layer 1: Fixed Security Floor (Non-negotiable, hardcoded security rules that cannot be bypassed)
 * Layer 2: Admin Customizable Policy Layer (Can tighten thresholds, but never loosen the Fixed Floor)
 */

// Default customizable thresholds
const DEFAULT_POLICY_CONFIG = {
  blockThreshold: 75,
  redactThreshold: 45,
  enableRegex: true,
  enableLLM: true
};

/**
 * Intelligent redaction engine that handles both structured regex matches
 * and contextual LLM detections (such as ATM PINs, tokens, and credentials).
 * 
 * @param {string} text - Original prompt text
 * @param {Array} regexMatches - Matches from detectors/regex.js
 * @param {Object} llmResult - Result from detectors/llm.js
 * @returns {string} Redacted prompt text
 */
function generateRedactedText(text, regexMatches = [], llmResult = {}) {
  let result = text;

  // 1. Redact structured regex matches (Credit Cards, API Keys, SSNs, Emails)
  if (Array.isArray(regexMatches) && regexMatches.length > 0) {
    for (const match of regexMatches) {
      const matchVal = match.match || match.value;
      if (matchVal) {
        const placeholder = `[REDACTED_${(match.category || 'DATA').toUpperCase()}]`;
        result = result.split(matchVal).join(placeholder);
      }
    }
  }

  // 2. Contextual Redaction Fallback: If LLM flagged sensitivity but Regex missed specific tokens
  if (llmResult && llmResult.sensitive) {
    const category = (llmResult.category || '').toLowerCase();

    // Financial / ATM PINs / CVV / 4-8 digit standalone security numbers
    if (category.includes('financial') || category.includes('proprietary')) {
      // Replaces 4 to 8 digit standalone numbers (e.g. ATM PINs, OTP codes)
      result = result.replace(/\b\d{4,8}\b/g, '[REDACTED_PIN]');
    }

    // Passwords or credential key-value patterns (e.g. pin = 1234, pwd: xyz)
    result = result.replace(/(pin|password|passcode|secret|key|token)\s*[:=]\s*(\S+)/gi, '$1: [REDACTED_SECRET]');
  }

  return result;
}

/**
 * Evaluates prompt detection results against the two-layer policy system.
 * 
 * @param {Object} input
 * @param {string} [input.promptText] - Original prompt text
 * @param {Array} input.regexMatches - Regex detection matches
 * @param {Object} input.llmResult - Local LLM detection result
 * @param {Object} input.riskAnalysis - Result from calculateRiskScore()
 * @param {Object} [input.customPolicyConfig] - Admin policy settings from storage
 * @returns {{ action: 'allow'|'redact'|'block', riskScore: number, reasons: Array<Object>, fixedFloorTriggered: boolean, redactedText: string }}
 */
function evaluatePolicy({
  promptText = '',
  regexMatches = [],
  llmResult = {},
  chunkLLMResults = [],
  unscannable = false,
  fileName = '',
  unscannableReason = '',
  riskAnalysis = { score: 0, breakdown: {} },
  customPolicyConfig = {}
}) {
  const riskScore = riskAnalysis.score;
  const reasons = [];

  // ==========================================
  // LAYER 1: FIXED SECURITY FLOOR (IMMUTABLE)
  // ==========================================

  // Fixed Floor Rule A: Valid Credit Card numbers are ALWAYS blocked
  const creditCardHits = regexMatches.filter(m => m.category === 'credit_card');
  if (creditCardHits.length > 0) {
    reasons.push({
      type: 'fixed_floor_violation',
      category: 'credit_card',
      description: 'Contains verified Credit Card financial data (Fixed Security Floor rule)'
    });
  }

  // Fixed Floor Rule B: API Secrets and Keys are ALWAYS blocked
  const apiKeyHits = regexMatches.filter(m => m.category === 'api_key');
  if (apiKeyHits.length > 0) {
    reasons.push({
      type: 'fixed_floor_violation',
      category: 'api_key',
      description: 'Contains API Keys / Secret Credentials (Fixed Security Floor rule)'
    });
  }

  // Fixed Floor Rule C: PIN / Passcodes are ALWAYS blocked
  const pinHits = regexMatches.filter(m => m.category === 'pin_passcode');
  if (pinHits.length > 0) {
    reasons.push({
      type: 'fixed_floor_violation',
      category: 'pin_passcode',
      description: 'Contains ATM PIN or Secret Passcode (Fixed Security Floor rule)'
    });
  }

  // Fixed Floor Rule D: National Identity / SSNs are ALWAYS blocked
  const nationalIdHits = regexMatches.filter(m => m.category === 'national_id');
  if (nationalIdHits.length > 0) {
    reasons.push({
      type: 'fixed_floor_violation',
      category: 'national_id',
      description: 'Contains Social Security / National Identity Numbers (Fixed Security Floor rule)'
    });
  }

  // Fixed Floor Rule C: Unscannable / Image / Binary File (Fail-Closed Security Floor)
  if (unscannable) {
    reasons.push({
      type: 'fixed_floor_violation',
      category: 'unscannable_file',
      description: `File '${fileName || 'attachment'}' cannot be text-verified (${unscannableReason || 'image/binary format'}). Fail-Closed Security Policy enforced.`
    });
  }

  // Fixed Floor Rule D: Critical Risk Score (>= 90) is ALWAYS blocked
  if (riskScore >= 90 && reasons.length === 0) {
    reasons.push({
      type: 'fixed_floor_violation',
      category: 'critical_risk',
      description: `Critical overall risk rating (${riskScore}/100 exceeds absolute floor limit of 90)`
    });
  }

  // Pre-calculate redacted text for non-blocked policies
  const redactedText = generateRedactedText(promptText, regexMatches, llmResult);

  // If ANY Fixed Floor rule triggered, enforce immediate BLOCK regardless of custom config
  if (reasons.length > 0) {
    return {
      action: 'block',
      riskScore: Math.max(riskScore, 95),
      reasons: reasons,
      fixedFloorTriggered: true,
      redactedText: redactedText
    };
  }

  // ==========================================
  // LAYER 2: CUSTOMIZABLE ADMIN POLICY LAYER
  // ==========================================

  // Resolve admin configuration, ensuring custom settings can tighten but NEVER loosen security
  const policy = {
    blockThreshold: Math.min(89, customPolicyConfig.blockThreshold ?? DEFAULT_POLICY_CONFIG.blockThreshold),
    redactThreshold: Math.min(
      customPolicyConfig.blockThreshold ?? DEFAULT_POLICY_CONFIG.blockThreshold,
      customPolicyConfig.redactThreshold ?? DEFAULT_POLICY_CONFIG.redactThreshold
    )
  };

  // Compile structured regex reasons
  for (const match of regexMatches) {
    reasons.push({
      type: 'structured_pattern',
      category: match.category,
      description: `Detected structured pattern: ${match.label || match.category}`
    });
  }

  // Compile LLM contextual sensitivity reasons
  if (llmResult && llmResult.sensitive && !llmResult.skipped) {
    const confidencePct = Math.round((llmResult.confidence || 0.8) * 100);
    const category = llmResult.category || 'confidential';
    reasons.push({
      type: 'contextual_sensitivity',
      category: category,
      description: `On-device AI flagged contextual sensitivity (${category}) with ${confidencePct}% confidence`
    });
  }

  // Action decision logic
  let action = 'allow';

  if (riskScore >= policy.blockThreshold) {
    action = 'block';
  } else if (riskScore >= policy.redactThreshold || regexMatches.length > 0) {
    action = 'redact';
  }

  return {
    action: action,
    riskScore: riskScore,
    reasons: reasons,
    fixedFloorTriggered: false,
    redactedText: redactedText
  };
}

// Support both ES Modules and script environment exports
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { evaluatePolicy, generateRedactedText, DEFAULT_POLICY_CONFIG };
} else if (typeof globalThis !== 'undefined') {
  globalThis.evaluatePolicy = evaluatePolicy;
  globalThis.generateRedactedText = generateRedactedText;
  globalThis.DEFAULT_POLICY_CONFIG = DEFAULT_POLICY_CONFIG;
}