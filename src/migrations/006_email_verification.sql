-- Self-registration with required email verification (this fork's real
-- "new account" flow — see README's "Self-service registration" section).
-- Single-use like oidc_auth_codes: consuming a token is an atomic
-- `UPDATE ... WHERE used = false`, so a leaked/replayed token can't be
-- redeemed twice even under a race. Short expiry (24h) — a stale link
-- just means requesting a fresh one via POST /api/v1/resend-verification.
CREATE TABLE IF NOT EXISTS email_verification_tokens (
  token_hash  TEXT PRIMARY KEY,
  uid         UUID NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  used        BOOLEAN NOT NULL DEFAULT false,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_uid ON email_verification_tokens(uid);
