/**
 * test/run-tests.js
 * 
 * Central Test Suite Runner.
 * Executes regex detector unit tests and fixed policy floor immutability tests.
 */

const { runAllRegexTests } = require('./test-regex.js');
const { testFixedFloorBypassProtection } = require('./test-policy-floor.js');
const { runAllFileGovernanceTests } = require('./test-file-governance.js');
const { testEmbeddedSecretSignalPreservation } = require('./test-signal-dilution.js');

async function main() {
  console.log('===============================================================');
  console.log('         AI GOVERNANCE LAYER — UNIT TEST SUITE RUNNER         ');
  console.log('===============================================================');

  try {
    runAllRegexTests();
    testFixedFloorBypassProtection();
    testEmbeddedSecretSignalPreservation();
    await runAllFileGovernanceTests();

    console.log('===============================================================');
    console.log('  SUCCESS: ALL UNIT TESTS PASSED (0 FAILURES, 100% SUCCESS)    ');
    console.log('===============================================================\n');
  } catch (err) {
    console.error('\n===============================================================');
    console.error('  FAILURE: UNIT TEST SUITE ENCOUNTERED AN ERROR');
    console.error('===============================================================');
    console.error(err.message);
    console.error(err.stack);
    process.exit(1);
  }
}

main();
