'use strict';
const tokens = require('../utils/tokens');

const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24h — a stale link just means requesting a fresh one via /resend-verification.

/**
 * Backs the self-registration email-verification flow (POST /api/v1/
 * register, GET /verify-email, POST /api/v1/resend-verification) — same
 * "store a hash, hand back the plaintext once" pattern as session tokens
 * and app secrets (src/utils/tokens.js), and the same single-use,
 * atomically-consumed shape as oidcCodeStore's authorization codes.
 */
class EmailVerificationStore {
  constructor(pool) {
    this.pool = pool;
  }

  /** Issues a fresh token for uid, invalidating any prior unexpired one first — a resend should make the old link stop working, not leave two live at once. */
  async issue(uid) {
    await this.pool.query('DELETE FROM email_verification_tokens WHERE uid = $1 AND used = false', [uid]);
    const token = tokens.generate('verify');
    const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);
    await this.pool.query(
      'INSERT INTO email_verification_tokens (token_hash, uid, expires_at) VALUES ($1, $2, $3)',
      [tokens.fingerprint(token), uid, expiresAt]
    );
    return token;
  }

  /**
   * Marks the token used and returns its record, all in one statement, so
   * two simultaneous redemption attempts (a doubly-clicked link, a link
   * shared/forwarded) can't both succeed — the second one's UPDATE simply
   * matches zero rows, since `used = false` is part of the WHERE clause.
   */
  async consume(token) {
    if (!token) return null;
    const { rows } = await this.pool.query(
      `UPDATE email_verification_tokens SET used = true
       WHERE token_hash = $1 AND used = false AND expires_at > now()
       RETURNING *`,
      [tokens.fingerprint(token)]
    );
    return rows[0] || null;
  }

  /** Best-effort cleanup — nothing depends on this running promptly; expired/used rows are just never matched by consume(). */
  async deleteExpired() {
    await this.pool.query('DELETE FROM email_verification_tokens WHERE expires_at < now()');
  }
}

module.exports = { EmailVerificationStore };
