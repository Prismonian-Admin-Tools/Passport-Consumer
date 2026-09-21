-- Passport Consumer as an OpenID Connect Identity Provider (for apps that
-- can't be taught the native login contract and only know how to speak a
-- standard protocol), plus a dormant TOTP MFA scaffold. Ported unchanged
-- from Global-Admin-Account-System — this is core infrastructure, not
-- something the fork's scope decisions touch.

-- Passport Consumer's own RSA keypair(s) for signing OIDC ID tokens. The
-- private key never leaves the server; public_jwk is exactly what
-- /.well-known/jwks.json serves so client libraries can verify a token's
-- signature. Generated lazily on first use (see oidcKeyStore.js) rather
-- than at migration time, since generating a keypair is an application
-- concern, not a schema one.
CREATE TABLE IF NOT EXISTS oidc_signing_keys (
  kid          TEXT PRIMARY KEY,
  private_key  TEXT NOT NULL,
  public_jwk   JSONB NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Authorization codes from the OIDC authorization_code flow: short-lived
-- (minutes), single-use (consumed atomically — see oidcCodeStore.js),
-- and PKCE is mandatory (code_challenge is NOT NULL) rather than
-- optional, per current OAuth best practice for every client type.
CREATE TABLE IF NOT EXISTS oidc_auth_codes (
  code_hash              TEXT PRIMARY KEY,
  uid                    UUID NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  app_id                 UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
  redirect_uri           TEXT NOT NULL,
  scope                  TEXT NOT NULL,
  nonce                  TEXT,
  code_challenge         TEXT NOT NULL,
  used                   BOOLEAN NOT NULL DEFAULT false,
  expires_at             TIMESTAMPTZ NOT NULL,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_expires ON oidc_auth_codes(expires_at);

-- Dormant MFA: a user can enroll (real setup UI — see routes/mfa.js) and
-- get real backup codes, but nothing at login checks mfa_enabled yet
-- unless an app opts in (apps.supports_mfa_challenge).
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  uid         UUID NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  code_hash   TEXT NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_uid ON mfa_backup_codes(uid);

-- Bridges a verified username/password to the second-factor step. Never
-- grants access by itself — only the right to attempt one TOTP or backup
-- code against the (uid, app_id) it was issued for. app_id NULL means
-- Passport Consumer's own frontend rather than a client app. attempts is
-- capped at the application layer (mfaChallengeStore.takeAttempt), not
-- here.
CREATE TABLE IF NOT EXISTS mfa_challenges (
  ticket_hash TEXT PRIMARY KEY,
  uid UUID NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  app_id UUID REFERENCES apps(app_id) ON DELETE CASCADE,
  attempts INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges (expires_at);
