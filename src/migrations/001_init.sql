-- Passport Consumer — initial schema.
--
-- A fresh, independent identity service (own DB, own app registry) forked
-- from Global-Admin-Account-System, so this is written as one consolidated
-- schema rather than replaying that project's 13-migration history. See
-- README.md for the two big differences from that source: a hardcoded
-- two-tier `role` (no ranks table) and self-registration with required
-- email verification.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- The identity itself. uid is the stable, immutable key other apps store
-- against — every other table's foreign key points at this one, and
-- username/password/profile are split out below rather than living here.
CREATE TABLE IF NOT EXISTS users (
  uid         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS usernames (
  uid         UUID PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
  username    TEXT UNIQUE NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS passwords (
  uid                     UUID PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
  password_hash           TEXT NOT NULL,
  password_simhash        TEXT,
  -- Every admin-created account starts here true — no exceptions, enforced
  -- again at the application layer in userStore.create(). A self-registered
  -- account (the user picked their own password already) starts false.
  must_change_password    BOOLEAN NOT NULL DEFAULT true,
  cannot_change_password  BOOLEAN NOT NULL DEFAULT false,
  password_never_expires  BOOLEAN NOT NULL DEFAULT true,
  password_expires_at     TIMESTAMPTZ,
  -- Dormant TOTP MFA scaffold (see src/models/mfaStore.js) — encrypted at
  -- rest the same way the SMTP password is, since a submitted code has to
  -- be checked against the plaintext secret, not a one-way hash.
  mfa_secret              TEXT,
  mfa_enabled             BOOLEAN NOT NULL DEFAULT false,
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- No ranks table here — Global-Admin-Account-System's whole
-- ranks/capabilities/permission-level system is replaced with this one
-- hardcoded, non-editable two-tier column. `admin` gets every management
-- capability; `user` gets none. See migration 005 for the "at least one
-- enabled admin must always exist" trigger this enables.
CREATE TABLE IF NOT EXISTS userdata (
  uid             UUID PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
  role            TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  full_name       TEXT NOT NULL DEFAULT '',
  description     TEXT NOT NULL DEFAULT '',
  email           TEXT,
  -- False until the emailed verification link is clicked (self-registered
  -- accounts) or true immediately at creation (an admin-created account
  -- with an email on file — the admin vouches for the address). See
  -- POST /api/v1/register and userStore.create()'s selfRegistered option.
  email_verified  BOOLEAN NOT NULL DEFAULT false,
  disabled        BOOLEAN NOT NULL DEFAULT false,
  theme           TEXT NOT NULL DEFAULT 'blueSharp',
  avatar_ext      TEXT,
  last_login      TIMESTAMPTZ,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Registered client applications (Prismonian's own apps). Each gets its
-- own secret — this is what proves the CALLER is a legitimate app,
-- separate from the end user's own username/password.
CREATE TABLE IF NOT EXISTS apps (
  app_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug                    TEXT UNIQUE NOT NULL,
  name                    TEXT NOT NULL,
  secret_hash             TEXT NOT NULL,
  disabled                BOOLEAN NOT NULL DEFAULT false,
  -- Only 'passport' (this service's own username/password + opaque token
  -- contract, see routes/apiV1.js) and 'oidc' (routes/oidc.js) are
  -- supported — the source project's oauth/saml/sssd/kerberos dark
  -- release doesn't apply to a Prismonian-only service, so it isn't
  -- carried over at all.
  auth_method             TEXT NOT NULL DEFAULT 'passport' CHECK (auth_method IN ('passport', 'oidc')),
  -- Which callback URLs an OIDC app is allowed to redirect to after
  -- authorizing — checked with an exact string match, never a prefix, so
  -- a registered app can't be used as an open redirect.
  redirect_uris           TEXT[] NOT NULL DEFAULT '{}',
  -- Opt-in: an app that hasn't set this keeps MFA dormant exactly as it
  -- is for every app today — /login never even looks at mfa_enabled for
  -- it. See routes/apiV1.js.
  supports_mfa_challenge  BOOLEAN NOT NULL DEFAULT false,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-(app, user) access override. An account is allowed into an app by
-- default; a row here with blocked = true is an admin explicitly revoking
-- that one user's access to that one app without touching the app-wide
-- `apps.disabled` switch or the user's account as a whole.
CREATE TABLE IF NOT EXISTS app_access (
  app_id      UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
  uid         UUID NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  blocked     BOOLEAN NOT NULL DEFAULT true,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, uid)
);

-- Opaque session tokens. We store a hash of the token, never the token
-- itself, same principle as the password. token_hash is the lookup key so
-- validating a token is a single indexed read.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash    TEXT PRIMARY KEY,
  uid           UUID NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  app_id        UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Slides forward on each successful /validate call, capped by
  -- absoluteTtlDays enforced at the application layer via created_at.
  expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sessions(uid);

CREATE TABLE IF NOT EXISTS failed_logins (
  id          BIGSERIAL PRIMARY KEY,
  username    TEXT,
  app_id      UUID REFERENCES apps(app_id) ON DELETE SET NULL,
  ip          TEXT,
  user_agent  TEXT,
  reason      TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_failed_logins_lookup ON failed_logins(username, ip, created_at);

-- actor_username is denormalized (stored alongside actor_uid) so the audit
-- trail still reads correctly even after that user's account is later
-- deleted — actor_uid alone would go NULL and silently erase who did it.
CREATE TABLE IF NOT EXISTS activity_log (
  id              BIGSERIAL PRIMARY KEY,
  category        TEXT NOT NULL,
  message         TEXT NOT NULL,
  actor_uid       UUID REFERENCES users(uid) ON DELETE SET NULL,
  actor_username  TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_activity_log_category ON activity_log(category);
CREATE INDEX IF NOT EXISTS idx_activity_log_created_at ON activity_log(created_at);

-- Site branding shown on the login screen and header. Single-row table
-- (not config.yml) so an admin can change it from the UI without a
-- restart — config.yml is only read once, at boot.
CREATE TABLE IF NOT EXISTS site_settings (
  id          INTEGER PRIMARY KEY DEFAULT 1,
  site_name   TEXT NOT NULL DEFAULT 'Passport Consumer',
  logo_ext    TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT site_settings_single_row CHECK (id = 1)
);
INSERT INTO site_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Single-row SMTP configuration, editable at runtime from the admin UI —
-- same pattern as site_settings. encrypted_password is AES-256-GCM
-- ciphertext (see src/utils/secretBox.js), not plaintext: decrypted only
-- in memory, only when actually sending mail.
CREATE TABLE IF NOT EXISTS email_settings (
  id                  INTEGER PRIMARY KEY DEFAULT 1,
  enabled             BOOLEAN NOT NULL DEFAULT false,
  host                TEXT,
  port                INTEGER NOT NULL DEFAULT 587,
  secure              BOOLEAN NOT NULL DEFAULT true,
  username            TEXT,
  encrypted_password  TEXT,
  from_address        TEXT,
  from_name           TEXT NOT NULL DEFAULT 'Passport Consumer',
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT email_settings_single_row CHECK (id = 1)
);
INSERT INTO email_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
