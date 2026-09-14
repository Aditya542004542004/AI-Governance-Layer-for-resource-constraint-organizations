const pattern = /\b(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|AIzaSy[a-zA-Z0-9_-]{33}|xox[baprs]-[a-zA-Z0-9]{10,}|[a-zA-Z0-9_-]{32,}|(?:[A-Za-z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN|AUTH|PASS|CREDENTIAL|PRIVATE|DATABASE_URL|DB_URL)[A-Za-z0-9_]*)\s*[:=]\s*[^\s"']{4,}|(?:(?:this\s+is\s+)?(?:my\s+)?(?:api|secret|access|auth|bearer)[\s_-]*(?:key|token|code)?)\s*(?:is|:|=)?\s*[a-zA-Z0-9_-]{8,})\b/gi;

console.log('Env 1 (DATABASE_URL):', 'DATABASE_URL=postgres://admin:secret123@localhost:5432/db'.match(pattern));
console.log('Env 2 (GEMINI_API_KEY):', 'GEMINI_API_KEY=AIzaSyA1234567890abcdef1234567890abc'.match(pattern));
console.log('Env 3 (JWT_SECRET):', 'JWT_SECRET=my_super_secret_jwt_token_123'.match(pattern));
console.log('Env 4 (AWS_SECRET_ACCESS_KEY):', 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'.match(pattern));
console.log('Clean prompt (What is photosynthesis):', 'What is photosynthesis?'.match(pattern));
