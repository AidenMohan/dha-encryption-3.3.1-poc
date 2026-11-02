# READ THE [WRITEUP](https://github.com/AidenMohan/DoD-Mishap)



# dha-encryption ≤ 3.3.1

## Cryptographic Weaknesses in dha-encryption npm Package

**Package:** [dha-encryption](https://www.npmjs.com/package/dha-encryption)

**Affected versions:** ≤ 3.3.1

**CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)

**Vendor:** dha-sdk

**Discovered by:** Aiden Mohan

---

## Overview

The `dha-encryption` npm package provides AES-GCM encryption keyed from a password via PBKDF2. It contains three cryptographic weaknesses that, combined, allow an attacker with access to ciphertext to recover plaintext credentials offline in seconds.

The package is used by `dha-login` as the authentication layer across multiple progressive web applications.

## Vulnerabilities

### 1. Hardcoded Default Salt

`getKeyFromPassword()` uses `"h0n3yp0t!@"` as the default PBKDF2 salt. If callers do not override the `seed` parameter, all deployments share the same salt, enabling precomputed attacks.

```js
async function getKeyFromPassword(t, e = "h0n3yp0t!@") {
```

### 2. Insufficient PBKDF2 Iterations

The library uses **1,337** iterations of PBKDF2-SHA256. [OWASP recommends a minimum of 600,000](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2) — making this implementation **448× below standard**. When the password is a 4-digit PIN, the entire keyspace (10,000 values) is exhaustible in seconds on commodity hardware.

### 3. Deterministic IV Derivation (AES-GCM Nonce Reuse)

The AES-256-GCM key and IV are both derived from the same `deriveBits` output:

```
PBKDF2(password, salt, 1337, 384 bits) → first 256 bits = AES key, last 128 bits = IV
```

The same password and salt always produce the same IV. Reusing a nonce with AES-GCM is a [known catastrophic failure](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) — it destroys the authentication tag guarantee and enables plaintext recovery across ciphertexts encrypted under the same key.

## Impact

An attacker with access to ciphertext produced by this library (via physical device access, backup extraction, XSS, or malware) can:

1. Brute-force the full 4-digit PIN keyspace in under 15 seconds
2. Decrypt stored credentials and security question answers
3. Use recovered answers to reset the PIN and gain a full authenticated session

No server interaction is required. The attack is entirely offline.

## Proof of Concept

`poc.mjs` demonstrates all three weaknesses using only the public npm package:

```
npm install dha-encryption@3.3.1
node poc.mjs
```

Sample output:

```
  3 — ITERATION COUNT vs OWASP MINIMUM

  dha-encryption:   1,337 iterations
  OWASP minimum:    600,000 iterations
  Factor below:     448×

  1 — DETERMINISTIC IV REUSE (AES-GCM nonce catastrophe)

  PIN:          5678
  Default salt: h0n3yp0t!@
  IV (call 1):  518e3c0d6c60af40192aec669cc21671
  IV (call 2):  518e3c0d6c60af40192aec669cc21671
  Identical:    true

  2 — FULL 4-DIGIT PIN BRUTE-FORCE (offline, ~13 s)

  Victim PIN:       4092
  Plaintext:        {"username":"jane.doe.mil","answer1":"Fort Campbell","answer2":"Peterson"}

  Ciphertext (hex): b63738b82a3dec443a111cf8a8ff59b1…
  Ciphertext size:  90 bytes

  Brute-forcing all 10,000 PINs against ciphertext…

  ✓ PIN recovered:  4092
  ✓ Plaintext:      {"username":"jane.doe.mil","answer1":"Fort Campbell","answer2":"Peterson"}
  ✓ Attempts:       4,093 of 10,000
  ✓ Time:           2.33 s
```

## Remediation

- Increase PBKDF2 iterations to ≥ 600,000 per OWASP guidance
- Generate a cryptographically random IV per encryption operation
- Remove the hardcoded default salt; require a unique per-user salt

## References

- [OWASP Password Storage Cheat Sheet — PBKDF2](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2)
- [NIST SP 800-38D — AES-GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [dha-encryption on npm](https://www.npmjs.com/package/dha-encryption)
- [writeup](https://github.com/AidenMohan/DoD-Mishap)
