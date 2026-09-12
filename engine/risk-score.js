/**
 * engine/risk-score.js
 * 
 * Computes a normalized risk score (0–100) by evaluating structured regex findings,
 * contextual LLM confidence, user organizational role, and AI destination trust level.
 * Fully configurable with safe, production-ready defaults out-of-the-box.
 */

// Default weights and multipliers
const DEFAULT_RISK_CONFIG = {
  // Category base risk ratings (0 - 100 scale)
  categoryBaseScores: {
    credit_card: 100,
    api_key: 100,
    national_id: 85,
    pin_passcode: 85,
    email: 40,
    phone: 30,
    medical: 90,
    financial: 85,
    pii: 70,
    proprietary: 80,
    confidential_context: 75
  },
  // Default role risk multipliers
  roleWeights: {
    engineering: 1.0,
    product: 1.0,
    hr: 1.25,
    finance: 1.3,
    executive: 1.2,
    contractor: 1.35,
    default: 1.0
  },
  // Destination trust multipliers (Lower multiplier = higher trust / lower risk impact)
  destinationTrust: {
    'chatgpt.com': 1.0,
    'chat.openai.com': 1.0,
    'gemini.google.com': 1.0,
    'claude.ai': 1.0,
    'unknown': 1.25 // Higher risk multiplier for unknown or untrusted AI tools
  }
};

/**
 * Calculates a normalized 0-100 risk score based on detection results and environmental context.
 * 
 * @param {Object} input
 * @param {Array} input.regexMatches - Output from runRegexChecks()
 * @param {Object} input.llmResult - Output from runLLMCheck()
 * @param {string} [input.userRole='default'] - User role (e.g. 'engineering', 'hr', 'finance')
 * @param {string} [input.destinationDomain='unknown'] - Domain of the target AI chat provider
 * @param {Object} [input.customConfig] - Overrides for weights & risk parameters
 * @returns {{ score: number, breakdown: Object }}
 */
function calculateRiskScore({
  regexMatches = [],
  llmResult = {},
  chunkLLMResults = [],
  userRole = 'default',
  destinationDomain = 'unknown',
  unscannable = false,
  customConfig = {}
}) {
  const config = {
    categoryBaseScores: { ...DEFAULT_RISK_CONFIG.categoryBaseScores, ...(customConfig.categoryBaseScores || {}) },
    roleWeights: { ...DEFAULT_RISK_CONFIG.roleWeights, ...(customConfig.roleWeights || {}) },
    destinationTrust: { ...DEFAULT_RISK_CONFIG.destinationTrust, ...(customConfig.destinationTrust || {}) }
  };

  let maxRegexScore = 0;
  const matchDetails = [];

  // 1. Calculate Regex matches risk score component
  for (const hit of regexMatches) {
    const baseScore = config.categoryBaseScores[hit.category] || 50;
    matchDetails.push({ category: hit.category, baseScore });
    if (baseScore > maxRegexScore) {
      maxRegexScore = baseScore;
    }
  }

  // 2. Calculate LLM contextual risk score component (Multi-chunk sensitive maximum preservation)
  let llmScore = 0;
  let topLLMCategory = null;

  if (Array.isArray(chunkLLMResults) && chunkLLMResults.length > 0) {
    for (const chunkRes of chunkLLMResults) {
      if (chunkRes && chunkRes.sensitive && !chunkRes.skipped) {
        const categoryBase = config.categoryBaseScores[chunkRes.category] || 75;
        const confidence = typeof chunkRes.confidence === 'number' ? chunkRes.confidence : 0.8;
        const cScore = Math.round(categoryBase * confidence);
        if (cScore > llmScore) {
          llmScore = cScore;
          topLLMCategory = chunkRes.category;
        }
      }
    }
  } else if (llmResult && llmResult.sensitive && !llmResult.skipped) {
    const categoryBase = config.categoryBaseScores[llmResult.category] || 75;
    const confidence = typeof llmResult.confidence === 'number' ? llmResult.confidence : 0.8;
    llmScore = Math.round(categoryBase * confidence);
    topLLMCategory = llmResult.category;
  }

  // Combine raw score taking maximum severity
  let rawContentScore = Math.max(maxRegexScore, llmScore);

  // 3. Unscannable Guardrail score boost (Fail-Closed Default)
  if (unscannable && rawContentScore < 80) {
    rawContentScore = 80;
  }

  // 3. Resolve Role Weight Multiplier
  const roleNorm = (userRole || 'default').toLowerCase().trim();
  const roleMultiplier = config.roleWeights[roleNorm] || config.roleWeights['default'] || 1.0;

  // 4. Resolve Destination Trust Multiplier
  const destNorm = (destinationDomain || 'unknown').toLowerCase().trim();
  let destinationMultiplier = config.destinationTrust['unknown'];
  for (const domainKey of Object.keys(config.destinationTrust)) {
    if (destNorm.includes(domainKey)) {
      destinationMultiplier = config.destinationTrust[domainKey];
      break;
    }
  }

  // Compute final combined score with multipliers
  let finalScore = Math.round(rawContentScore * roleMultiplier * destinationMultiplier);

  // If there's a critical regex match (e.g. credit card / API key), enforce a minimum score of 95
  const hasCriticalHit = regexMatches.some(m => m.category === 'credit_card' || m.category === 'api_key');
  if (hasCriticalHit && finalScore < 95) {
    finalScore = 95;
  }

  // Clamp normalized score to [0, 100] range
  finalScore = Math.min(100, Math.max(0, finalScore));

  return {
    score: finalScore,
    breakdown: {
      regexScore: maxRegexScore,
      llmScore: llmScore,
      rawContentScore: rawContentScore,
      roleMultiplier: roleMultiplier,
      destinationMultiplier: destinationMultiplier,
      hasCriticalHit: hasCriticalHit
    }
  };
}

// Support both ES Modules and script environment exports
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { calculateRiskScore, DEFAULT_RISK_CONFIG };
} else if (typeof globalThis !== 'undefined') {
  globalThis.calculateRiskScore = calculateRiskScore;
  globalThis.DEFAULT_RISK_CONFIG = DEFAULT_RISK_CONFIG;
}
