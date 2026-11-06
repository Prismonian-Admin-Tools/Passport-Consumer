'use strict';
const argon2 = require('argon2');
const bcrypt = require('bcryptjs');

// Argon2id — the OWASP Password Storage Cheat Sheet's current first
// recommendation and the Password Hashing Competition winner — replaces
// bcrypt for every NEWLY hashed password. Parameters are OWASP's minimum
// recommended Argon2id profile: 19 MiB memory, 2 iterations, single-
// threaded. (bcrypt's fixed, GPU/ASIC-friendlier structure and 72-byte
// input cap are exactly what Argon2id's memory-hardness exists to raise
// the cost of; see the cheat sheet for the comparison.)
const ARGON2_OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

const BCRYPT_HASH_RE = /^\$2[aby]\$/;

async function hash(plaintext) {
  return argon2.hash(String(plaintext), ARGON2_OPTIONS);
}

/**
 * Verifies against EITHER a current Argon2id hash or a legacy bcrypt one
 * (every hash stored before this module switched algorithms) — so
 * upgrading this file doesn't by itself invalidate a single existing
 * credential or force a mass password reset. A bcrypt hash that verifies
 * here is exactly the case needsRehash() below flags, and userStore.verify()
 * re-hashes it under Argon2id on that same successful login — see its
 * comment for why that's safe to do silently.
 */
async function verify(plaintext, hashed) {
  if (!plaintext || !hashed) return false;
  if (BCRYPT_HASH_RE.test(hashed)) {
    return bcrypt.compareSync(String(plaintext), hashed);
  }
  try {
    return await argon2.verify(hashed, String(plaintext));
  } catch (err) {
    // Malformed/foreign hash string — fail closed, not throw.
    return false;
  }
}

/**
 * True for a hash this module would no longer produce itself: a legacy
 * bcrypt hash, or an Argon2id hash whose parameters predate a later
 * strengthening of ARGON2_OPTIONS (argon2.needsRehash compares the
 * hash's embedded params against the options object above). Callers use
 * this right after a successful verify() to transparently upgrade
 * storage on login, without a forced reset and without this module ever
 * having to know who its callers are.
 */
function needsRehash(hashed) {
  if (!hashed) return true;
  if (BCRYPT_HASH_RE.test(hashed)) return true;
  try {
    return argon2.needsRehash(hashed, ARGON2_OPTIONS);
  } catch (err) {
    return true;
  }
}

// A known-username wrong-password check runs a real Argon2id hash+compare;
// an unknown-username check that skips straight to "no" would otherwise
// return much faster. That gap lets an attacker distinguish valid from
// invalid usernames by timing alone. Computed once, lazily (hashing is
// async, so this can't run synchronously at module-load time like the old
// bcrypt version did), then cached — checking against it costs the same as
// a real compare without re-hashing on every call.
let dummyHashPromise = null;
function dummyHash() {
  if (!dummyHashPromise) dummyHashPromise = hash('passport-timing-safety-dummy-password');
  return dummyHashPromise;
}

/** Burns the same time a real verify() would, for the "user not found" path — see dummyHash() above. */
async function verifyDummy() {
  await argon2.verify(await dummyHash(), 'irrelevant').catch(() => false);
}

module.exports = { hash, verify, verifyDummy, needsRehash };
