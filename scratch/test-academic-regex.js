const COMMON_ENGLISH_WORDS = new Set([
  'imported', 'attached', 'generated', 'implementation', 'protocol', 'management',
  'variable', 'framework', 'function', 'server', 'endpoint', 'system', 'process',
  'services', 'security', 'database', 'overview', 'architecture', 'application',
  'component', 'interface', 'configuration', 'parameter', 'response', 'request',
  'payload', 'research', 'encrypted', 'encryption', 'algorithm', 'operation',
  'operations', 'generation', 'authentication', 'verification', 'mechanism'
]);

function validateApiKeyMatch(matchStr) {
  if (!matchStr || typeof matchStr !== 'string') return false;
  
  const parts = matchStr.split(/[:=]|\bis\b/i);
  if (parts.length > 1) {
    const candidate = parts[parts.length - 1].trim().replace(/^['"]|['"]$/g, '').toLowerCase();
    if (COMMON_ENGLISH_WORDS.has(candidate)) {
      return false;
    }
  }
  return true;
}

const academicText = `
  CIFER: Secure File Storage and Sharing System Using AES-256 Encryption and OTP-Based Authentication.
  The RESTful API is implemented using Flask. The encryption key is imported from a secured environment variable.
  A 32-byte token is attached to the encrypted payload. According to research on one-time PIN generation in 2022,
  the PIN entry process is masked using several mathematical operations.
`;

const apiKeyPattern = /\b(?:sk-(?:proj-|ant-)?[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}|gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[a-zA-Z0-9]{10,}|[a-zA-Z0-9_-]{32,}|(?:[A-Za-z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN|AUTH|PASS|CREDENTIAL|PRIVATE|DATABASE_URL|DB_URL)[A-Za-z0-9_]*)\s*[:=]\s*(?:['"][^'"]{4,}['"]|\S{8,})|(?:(?:this\s+is\s+)?(?:my\s+)?(?:api|secret|access|auth|bearer)[\s_-]*(?:key|token|code))\s*[:=]\s*['"]?[a-zA-Z0-9_-]{8,}['"]?)\b/gi;

const pinPattern = /\b(?:atm\s*pin|my\s*pin|pin\s*code|passcode|laptop\s*password|wifi\s*password|p\.i\.n\.)\s*[:=is\s]+\b(\d{4,8})\b|\b(?:pin|passcode|password)\s*[:=]\s*['"]?([a-zA-Z0-9!@#$%^&*_-]{4,32})['"]?\b/gi;

console.log('--- Academic Text Matches ---');
let apiMatch;
while ((apiMatch = apiKeyPattern.exec(academicText)) !== null) {
  if (validateApiKeyMatch(apiMatch[0])) {
    console.log('API Key False Positive:', apiMatch[0]);
  }
}

let pinMatch;
while ((pinMatch = pinPattern.exec(academicText)) !== null) {
  console.log('PIN False Positive:', pinMatch[0]);
}

console.log('--- True Positive Matches ---');
console.log('OpenAI:', 'sk-proj-1234567890abcdefghijklmnopqrstuv'.match(apiKeyPattern));
console.log('AWS:', 'AKIAIOSFODNN7EXAMPLE'.match(apiKeyPattern));
console.log('Google:', 'AIzaSyA1234567890abcdef1234567890abc'.match(apiKeyPattern));
console.log('Env DB:', 'DATABASE_URL=postgres://admin:pass@localhost:5432/db'.match(apiKeyPattern));
console.log('Laptop Pwd 1:', 'this is my laptop password 2901901'.match(pinPattern));
console.log('Laptop Pwd 2:', 'laptop password: 2901901'.match(pinPattern));
