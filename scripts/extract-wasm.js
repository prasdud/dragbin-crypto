#!/usr/bin/env node

/**
 * Extract WASM bundles.
 * This allows us to bundle them directly, achieving zero runtime dependencies.
 */

const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, '..', 'src', 'wasm');

// Ensure output directory exists
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

console.log('Extracting WASM bundles...');

try {
  // Extract Kyber WASM
  const kyberPath = require.resolve('kyber-crystals');
  const kyberSource = fs.readFileSync(kyberPath, 'utf8');
  const kyberOutput = path.join(OUTPUT_DIR, 'kyber.wasm.js');

  // Wrap in a module that exports the kyber object
  const kyberWrapper = `// Auto-generated WASM bundle. Do not edit manually.

${kyberSource}

export default kyber;
`;

  fs.writeFileSync(kyberOutput, kyberWrapper);
  console.log('✓ Extracted Kyber WASM to', kyberOutput);

  // Extract Argon2 WASM
  const argon2Path = require.resolve('hash-wasm/dist/argon2.umd.min.js');
  const argon2Source = fs.readFileSync(argon2Path, 'utf8');
  const argon2Output = path.join(OUTPUT_DIR, 'argon2.wasm.js');

  // Wrap in a module that creates an exports object and re-exports the function
  const argon2Wrapper = `// Auto-generated WASM bundle. Do not edit manually.

const exports = {};

${argon2Source}

export const argon2id = exports.argon2id;
`;

  fs.writeFileSync(argon2Output, argon2Wrapper);
  console.log('✓ Extracted Argon2 WASM to', argon2Output);

  console.log('\n✅ WASM extraction complete!');
} catch (error) {
  console.error('❌ Error extracting WASM:', error.message);
  process.exit(1);
}
