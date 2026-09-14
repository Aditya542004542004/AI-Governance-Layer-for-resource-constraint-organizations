const pattern = /\b(?:(?:this\s+is\s+)?(?:my\s+)?(?:laptop|wifi|phone|atm|system|vault|user|account|device|admin)?\s*(?:pin|passcode|password|p\.i\.n\.|secret\s*code))\s*(?:is|:|=)?\s*([a-zA-Z0-9!@#$%^&*_-]{4,32})\b/gi;

console.log('Test 1 (laptop password):', 'this is my laptop password 2901901'.match(pattern));
console.log('Test 2 (wifi password):', 'my wifi password is Admin1234!'.match(pattern));
console.log('Test 3 (ATM pin):', 'my ATM pin is 4321'.match(pattern));
console.log('Test 4 (passcode):', 'passcode: 987654'.match(pattern));
console.log('Test 5 (Question):', 'What is a password?'.match(pattern));
