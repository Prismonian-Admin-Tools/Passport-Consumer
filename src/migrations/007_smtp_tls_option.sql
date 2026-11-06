-- An internal/self-hosted SMTP relay with a self-signed or expired
-- certificate previously had no way to be used at all: Mailer's
-- createTransport() call passed no `tls` option, so Node's TLS default
-- (verify against the system CA bundle) applied unconditionally to a
-- STARTTLS upgrade, and the admin had no way to work around it short of
-- fixing the relay's certificate. Defaults to true (verify) — same
-- secure-by-default posture as database.ssl in src/db.js — an admin
-- opts OUT for a specific, known-trusted internal relay rather than this
-- being silently permissive for everyone.
ALTER TABLE email_settings ADD COLUMN IF NOT EXISTS reject_unauthorized_tls BOOLEAN NOT NULL DEFAULT true;
