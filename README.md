# Passport Consumer

A fork of `Global-Admin-Account-System` (GAM) for **end users of
Prismonian's own apps** rather than admin-provisioned staff. GAM's whole
job was letting a sysadmin provision every account by hand; Passport
Consumer's is letting an app's own users create their own accounts
(self-registration with required email verification), while keeping the
same overall architecture, security posture, and code style as the
source project. It is a fully independent service: its own Postgres
database, its own app registry, no shared data or code paths with GAM.

Passport Consumer owns accounts, passwords, and a minimal two-tier role
(`user` / `admin` — see [Roles](#roles) below). Apps call it to log users
in (or let them register), then keep their own fine-grained, app-specific
data keyed by the user's `uid`.

## Setup

```bash
npm install
createdb passport_consumer                      # or your provider's equivalent
cp config/config.yml.example config/config.yml   # edit db creds, secrets, publicUrl
npm run migrate
npm run bootstrap -- --username adrian --password "temp-password-123" --app someapp
```

The bootstrap command creates the first account (`role: 'admin'`, forced
to change its password on first login — the same treatment every
admin-created account gets, no special-casing) and, if `--app` is given,
prints that app's `appId` and **secret once** — save it immediately, it
can't be retrieved again (only regenerated, which invalidates the old
one).

```bash
npm start
```

## The app-facing contract (`/api/v1/*`)

Every request needs these headers, identifying the CALLING APPLICATION
(not the end user):

```
X-App-Id: <appId>
X-App-Secret: <appSecret>
```

### `POST /api/v1/register`
```json
{ "username": "newuser", "password": "...", "email": "newuser@example.com", "fullName": "optional" }
```
Self-service account creation — this is the fork's real "new account"
flow. Creates a `role: 'user'` account with `emailVerified: false` and no
forced password-change flag (the caller already picked its own password,
same as any self-service password set), runs the chosen password through
the [password policy](#password-policy), and emails a verification link.
Username and email must both be unique; either collision (or an app not
registered under the `passport` auth method) gets a generic
`invalid_request` — same "don't reveal which part was wrong" posture as
`/login`. No token is returned: the account can't sign in until the link
is clicked.
```json
{ "status": "registered" }
```

### `GET /verify-email?token=...`
**Public** — mounted outside the `X-App-Id`/`X-App-Secret` gate, since a
human clicks this from their inbox, not an app calling the API. Serves a
small standalone confirmation page (`public/verify-email.html`) that
reads `?token=` and calls the also-public `GET /verify-email/confirm`
endpoint to atomically consume the token and mark the account verified.
An invalid, expired, or already-used token shows a plain "try requesting
a new one" message, never a raw error.

### `POST /api/v1/resend-verification`
```json
{ "username": "newuser" }   // or { "email": "newuser@example.com" }
```
Always responds `{ "status": "ok" }` and never reveals whether the
account exists or is already verified. If it exists and isn't verified,
any unexpired token is invalidated and a fresh one is issued and emailed.

### `POST /api/v1/login`
```json
{ "username": "adrian", "password": "..." }
```
Response `status` is always exactly one of:

| status | meaning |
|---|---|
| `good` | valid credentials, account in good standing |
| `good_change_pw` | valid credentials, but must change password before continuing |
| `bad` | wrong username or password (never reveals which) — also returned for every request against an app that isn't registered with the `passport` auth method, since this endpoint isn't that app's login contract |
| `disabled` | account exists and password is correct, but is disabled |
| `unverified` | valid credentials, but the account's email hasn't been confirmed yet (self-registered accounts only — see `/register` above) |
| `good-no-access` | valid credentials, but an admin has blocked this specific user from this specific app (see [Per-app access control](#per-app-access-control)) |
| `good_mfa_required` | valid credentials, but this account has MFA enabled and this app has opted into handling it (see [MFA](#multi-factor-authentication-dormant)) |

`good` / `good_change_pw` responses also include a `token` (opaque
session token, scoped to this app) and `user` (full profile, minus
password). Malformed requests get `invalid_request` (400); bad app
credentials get `invalid_app` (401); too many attempts get
`rate_limited` (429, with `Retry-After`).

### `POST /api/v1/validate`
```json
{ "token": "tok_..." }
```
→ `{ "valid": true, "user": {...} }` or `{ "valid": false }`. Sliding
idle timeout — each successful validate extends the token's life, up to
the absolute TTL in `config.yml`.

### `POST /api/v1/logout`
```json
{ "token": "tok_..." }
```

### `POST /api/v1/change-password`
```json
{ "token": "tok_...", "currentPassword": "...", "newPassword": "...", "confirmPassword": "..." }
```
`currentPassword` is only required if the account is NOT under a forced
password change — that's the whole point of "forced."

### `POST /api/v1/update-profile`
```json
{ "token": "tok_...", "fullName": "...", "description": "...", "theme": "..." }
```

## User object shape

```json
{
  "uid": "uuid",
  "username": "adrian",
  "role": "admin",
  "email": null,
  "emailVerified": false,
  "fullName": "",
  "description": "",
  "disabled": false,
  "mustChangePassword": false,
  "cannotChangePassword": false,
  "passwordNeverExpires": true,
  "passwordExpiresAt": null,
  "passwordExpired": false,
  "theme": "blueSharp",
  "avatarExt": null,
  "lastLogin": "2026-08-14T...",
  "createdAt": "...",
  "updatedAt": "..."
}
```

`uid` is the stable key — store your app's own fine-grained data
(per-app permissions, custom flags, whatever) keyed by `uid`, not
`username`. Usernames can be renamed by an admin; `uid` never changes.
`mfaEnabled` is included on the admin-panel/frontend profile shape but
omitted from the one handed to calling apps (see
[MFA](#multi-factor-authentication-dormant)).

### Data model

An "account" is really four tables, not one: `users` is a minimal
identity anchor (`uid`, `created_at`) — the thing every other table's
foreign key actually points to — with `usernames`, `passwords`, and
`userdata` each holding one focused slice, one row per `uid`:

| table | holds |
|---|---|
| `users` | `uid` (the stable identity), `created_at` |
| `usernames` | `username` |
| `passwords` | `password_hash`, `password_simhash`, `mustChangePassword`, `cannotChangePassword`, `passwordNeverExpires`, `passwordExpiresAt`, MFA secret/flag |
| `userdata` | `role`, `fullName`, `description`, `email`, `emailVerified`, `disabled`, `theme`, `avatarExt`, `lastLogin` |

This is purely internal: `src/models/userStore.js` joins all four back
into the single shape shown above before anything else in the codebase
ever sees a "user," so no route, the CLI, or an app calling `/api/v1/*`
can tell the difference.

## Roles

No ranks, no capabilities table, no permission-level hierarchy — just a
hardcoded, non-editable, two-value column on `userdata`:

| role | can do |
|---|---|
| `admin` | Everything: manage users, apps, activity log, branding, password policy, email settings. Any admin can manage any other (non-self) account. |
| `user` | Nothing in the admin panel — self-service on their own account only (profile, password, theme, MFA enrollment, active sessions). |

That's the entire model. `POST /api/v1/register` (self-registration)
always creates a `role: 'user'` account; a `role: 'admin'` account is
only ever created deliberately — bootstrap, the CLI, or an existing
admin using the Users tab — never through self-registration.

**At least one enabled admin must always exist**, enforced twice: at the
application layer (`src/routes/users.js`, `scripts/passport-cli.js`) and,
authoritatively, by a Postgres trigger (`enforce_min_one_admin`, migration
005) that sees every code path atomically — a demote, disable, or delete
that would leave zero enabled admins is rejected outright, closing the
race where two concurrent changes could each see "more than one admin
left" and together leave none.

## Per-app access control

Disabling an app (`PATCH /api/apps/:appId`) blocks every user from it.
For a narrower cut, an admin can also block one specific user from one
specific app without touching the app or the account as a whole:

```
POST   /api/apps/:appId/access/:uid/block
POST   /api/apps/:appId/access/:uid/unblock
GET    /api/apps/:appId/access          # currently blocked users
```

A blocked user's credentials still work everywhere else; against this
one app, `/api/v1/login` returns `good-no-access` instead of `good` /
`good_change_pw`, and any token they already held for it stops validating.

## Auth methods

Every registered app has an `authMethod`, defaulting to `passport` (this
service's own username/password + register/login/opaque-token contract).
Only two values exist: `passport` and `oidc` (see
[Federated identity](#federated-identity-passport-consumer-as-an-openid-connect-provider)
below). The source project's `oauth` (bare OAuth2 without OIDC on top),
`saml`, `sssd`, and `kerberos` were an unimplemented dark release for
eventual domain-logon support — out of scope for a Prismonian-only
service, so they were removed from the schema, the model, the CLI, and
the frontend entirely rather than carried over unused.

Whatever the value, `/api/v1/login` and `/api/v1/register` are
specifically the `passport` contract — an app registered under `oidc`
always gets the same generic failure back from them (`bad` /
`invalid_request`, never a hint about which protocol it should be using
instead), since that app isn't supposed to be calling those endpoints at
all.

## Federated identity: Passport Consumer as an OpenID Connect Provider

Some apps can be taught the native `passport` contract above; others —
off-the-shelf software, anything that only knows how to integrate SSO via
a standard protocol — can't. For those, an app registered with
`authMethod: "oidc"` can point any standard OIDC client library at
Passport Consumer itself as the identity provider. Apps that *do* support
the native contract keep using `/api/v1/login`/`/register` as before —
this is a second, parallel front door, not a replacement.

It's built entirely out of infrastructure Passport Consumer already has:

- **`client_id` / `client_secret` are an app's existing `appId` / app
  secret** — the same pair already used for `X-App-Id` / `X-App-Secret`.
  There's no separate OIDC credential type to register or lose track of.
- **The OIDC `access_token` IS the opaque `tok_...` token** the native
  protocol already issues via the same session store. An OIDC-
  authenticated sign-in shows up in "Active Sessions" and can be revoked
  ("sign out everywhere") exactly like a native one.
- Only the **`id_token`** is new: a short-lived (5 minute) RS256-signed
  JWT asserting who just authenticated, exactly as long as the initial
  code-for-token exchange, per spec — not meant for ongoing API calls.

Supported: authorization-code flow only (no implicit/hybrid). **PKCE
(S256) is mandatory** for every client, confidential or not, per current
best practice. Standard endpoints:

```
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /oidc/authorize      (response_type=code, PKCE required)
POST /oidc/token          (grant_type=authorization_code)
GET  /oidc/userinfo       (Authorization: Bearer <access_token>)
```

Registering an OIDC app also needs `redirectUris` — an allow-list
Passport Consumer checks with an **exact string match** (never a prefix)
before it will send an authorization code anywhere, so a registered app
can't be used as an open redirect. Manage them from the Apps tab's "OIDC
info" button, `PUT /api/apps/:appId/redirect-uris`, or
`apps set-redirect-uris` / `apps oidc-info` in the CLI.

There's no consent screen: an app has to be registered by an admin before
it can appear at `/oidc/authorize` at all, the same trust boundary
`/api/v1/login` already relies on. If the browser hitting
`/oidc/authorize` isn't signed into Passport Consumer's own frontend (or
has a forced password change pending), it's redirected to
`/?continue=<the original authorize URL>`; the frontend finishes login
(or the forced change) and then navigates the browser back to that URL as
a real page load, so the OIDC route runs again now-authenticated.
Passport Consumer only *consumes* OIDC identity for its own login — it
doesn't offer signing into it via an external IdP.

`oidc_signing_keys` holds Passport Consumer's own RSA keypair for signing
ID tokens, generated once (at first boot) and reused for the life of the
install; `/.well-known/jwks.json` publishes only the public half.
`oidc_auth_codes` holds authorization codes, single-use and short-lived
(60 seconds) — consuming one is an atomic `UPDATE ... WHERE used = false`,
so a code can't be redeemed twice even under a race.

## Multi-factor authentication (dormant)

A user can enroll in TOTP (authenticator-app codes) from My Account: a
real QR code, confirming with a live code before it's considered set up,
and one-time backup codes shown exactly once, same pattern as an app
secret. `mfaEnabled` is on the frontend profile shape, so admins can see
who's enrolled. It's opt-in per app (`apps.supportsMfaChallenge`) for the
`/api/v1/login` contract — an app that hasn't declared support keeps
`mfa_enabled` completely dormant, same as before this existed — while
Passport Consumer's own frontend always enforces it once a user turns it
on, since there's no third-party compatibility concern for first-party
code.

`passwords.mfa_secret` is encrypted at rest the same way the SMTP
password is (`src/utils/secretBox.js`) — Passport Consumer has to read a
submitted code's expected value back in plaintext to check it, so it
can't be a one-way hash, same tradeoff noted for the SMTP password in
[Security notes](#security-notes).

## Password policy

Every self-service password change — self-registration, the forced
first-login change on an admin-created account, and a voluntary later
one, via `PUT /api/account/password`, `/api/v1/register`, or
`/api/v1/change-password` — is checked against two things before it's
accepted. **Neither check runs for a password an admin sets for someone
else**, whether through the Users tab, `PATCH /api/users/:uid`, or the
CLI's `users create` / `users reset-password` — those are always
temporary, and the account holder is forced to replace them on next
login anyway.

**1. Configurable rules.** `password_policy_rules` holds rule *instances*
— a type, a label, enabled/disabled, and a JSON `params` blob — evaluated
by `src/utils/passwordPolicy.js`. The defaults:

| label | type | params |
|---|---|---|
| No years | `noYears` | `{minYear: 1900, maxYear: 2099}` — rejects any 4-digit run in that range |
| 2 symbols minimum | `minCount` | `{charset: "symbols", min: 2}` |
| 3 numbers minimum | `minCount` | `{charset: "numbers", min: 3}` |
| 5 letters minimum | `minCount` | `{charset: "letters", min: 5}` |
| 1 uppercase letter | `minCount` | `{charset: "uppercase", min: 1}` |
| No spaces | `noSpaces` | `{}` |
| Not 70% similar to "password" | `notSimilarTo` | `{values: ["password"], threshold: 0.7}` |

An admin (every admin has this capability — see [Roles](#roles)) can
enable/disable, edit params, or add new *instances* of these types from
the Password Policy tab, `/api/password-policy`, or the CLI's
`password-policy` command group — no code change needed.

**2. Password history.** A new password can't be ≥70% similar to either
of the user's last two (now-retired) passwords — skipped for a brand-new
self-registration, which has no history yet. A password can't be
un-hashed to compare it letter-by-letter against a new one, so this needs
something bcrypt can't give us: alongside the bcrypt hash, Passport
Consumer stores a 64-bit **SimHash** of the password's character-
frequency histogram (`password_simhash` on `passwords`, and in
`password_history` for the two most recently retired passwords) —
computed once, at set-time, while the plaintext is still in memory, and
never reversible back to the original password. See the comment above
`simhash64()` in `src/utils/passwordPolicy.js` for the full reasoning;
treat a rejection as "please pick something more different," not a
security guarantee.

## Email notifications

Passport Consumer can send account-lifecycle emails via SMTP, configured
at `/api/email-settings` (Email tab, admin only) or `email set-smtp` /
`email enable` in the CLI. The SMTP password is encrypted at rest
(AES-256-GCM, keyed from `server.encryptionKey` — see
`src/utils/secretBox.js`) and only ever decrypted in memory to actually
send mail; it's never returned by any read endpoint. Sending is a no-op
(never an error toward the caller) whenever email is disabled,
unconfigured, or the recipient has no address on file.

| email | sent when |
|---|---|
| Verify your email | a new account self-registers (`POST /api/v1/register`) or requests a fresh link (`POST /api/v1/resend-verification`) |
| Account created | an admin creates a new user (any interface) |
| Password change required | an admin flips `mustChangePassword` on an *existing* account (not at creation — that gets "Account created" instead) |
| Password changed | any time a password is actually changed, self-service or admin/CLI |
| Password expired | the hourly sweep (`src/jobs/passwordExpirySweep.js`) finds an account past `passwordExpiresAt` |
| Password expiry soon! | the same sweep, once a password is within 7 days of expiring |
| Unknown logon point | a successful login from an IP Passport Consumer hasn't seen for that account before — tracked in `known_logins`; a brand-new account's very first login is never flagged, since there's nothing yet to compare it to |

Add an email address to an account from the Users tab, `PATCH /api/
users/:uid`, or `users set-email <username> <email>` in the CLI.

## Admin-panel features (Passport Consumer's own frontend)

- **Dashboard** — quick stats and a recent-activity feed for admins;
  a plain `user` sees only their own role/password status.
- **Users** — create, edit, bulk enable/disable/delete, CSV import (each
  imported row gets its own random temp password, downloadable as a CSV
  afterward), full password-policy control per user (force change, can't-
  change, expiry date), and an at-a-glance "unverified email" badge for
  self-registered accounts that haven't clicked their link yet — point
  the user at their app's own resend flow, or use
  `POST /api/v1/resend-verification` directly. Admin only.
- **Active Sessions** — every app currently holding a live token for a
  given account, with per-session or "sign out everywhere" revocation.
  Available both to a user for their own account (`/api/account/sessions`)
  and, for an admin, for anyone (`/api/users/:uid/sessions`).
- **Two-factor authentication** — TOTP enrollment (QR code, backup codes)
  from My Account for any signed-in user. See
  [Multi-factor authentication](#multi-factor-authentication-dormant) above.
- **Apps** — register/regenerate/disable client applications, set an
  app's auth method (`passport` or `oidc`), manage per-app user access,
  and (for `oidc` apps) view connection info and manage redirect URIs.
  Admin only.
- **Activity** — filterable (category, actor, date range) audit log with
  CSV export at `/api/activity/export`. The acting username is stored
  denormalized on each entry, so it survives that account later being
  deleted — only the `actor_uid` foreign key goes null. Admin only.
- **Password Policy** — see [Password policy](#password-policy) above.
  Admin only.
- **Email** — SMTP settings and a test-send button; see
  [Email notifications](#email-notifications) above. Admin only.
- **Settings** — site name and logo shown on the login screen and header,
  stored in the database (not `config.yml`) so it takes effect without a
  restart. Admin only.

There is no "Ranks" tab — the role model is the two fixed values above,
not a configurable table, so there's nothing left to administer there.

## CLI (no login required)

Everything above, plus `reset-attempts`, is also available from the
command line — it talks directly to the database using `config.yml`'s
credentials, the same way `scripts/bootstrap.js` does. No HTTP, no
session, works whether or not the server is even running.

```bash
node scripts/passport-cli.js --help
# or: npm run cli -- --help
```

```
users list | show <username> | create <username> <user|admin> [--password P] [--full-name N] [--description D] [--email E]
users set-role <username> <user|admin> | set-email <username> <email> | reset-password <username> [--password P] [--keep-must-change]
users disable/enable <username> | rename <username> <new> | delete <username>

apps list | create <slug> [--name N] [--auth-method passport|oidc] [--redirect-uris uri1,uri2] | set-auth-method <slug> <passport|oidc> | regenerate-secret <slug> | disable/enable/delete <slug>
apps set-redirect-uris <slug> <uri1,uri2,...> | oidc-info <slug>
apps block <slug> <username> | unblock <slug> <username>

sessions list <username> | revoke-all <username>

activity list [--category C] [--actor A] [--from ISO] [--to ISO] [--limit N]
activity export <file.csv> [--category C] [--actor A] [--from ISO] [--to ISO]

branding show | set-name <name> | remove-logo

password-policy list | create <type> <label> [--params '{...}'] | set-enabled <id> <on|off> | delete <id>

email show | set-smtp [--host H] [--port P] [--secure true|false] [--username U] [--password P] [--from-address A] [--from-name N]
email enable | disable | send-test <address>

reset-attempts <username>     # clear a login lockout for one account
reset-attempts --all          # clear every recorded attempt for everyone
```

There's no `ranks` command group — a role is just `user` or `admin`,
passed directly to `users create` / `users set-role`.

Password requirements and history checks (see
[Password policy](#password-policy)) are enforced only on self-service
changes — `users create` / `users reset-password` bypass them entirely,
same as an admin reset through the web UI. An account created here starts
`emailVerified: true` if given an email (the admin who typed the address
in vouches for it); self-registration is the only flow that starts
unverified.

Passwords left out of `create`/`reset-password` are generated randomly
and printed once. Every admin-created/reset account is forced to change
its password on first login after either — no flag turns that off.

## Security notes

- Nobody — including admins — can ever retrieve a stored password. An
  admin can only reset one.
- A self-registered account can't sign in until its email is verified
  (`/api/v1/login` returns `unverified`, no token issued); an
  admin-created account always starts with `mustChangePassword: true`
  instead — no flag turns either gate off at creation.
- Session tokens are stored as SHA-256 hashes, scoped to `(uid, appId)`
  — a token issued to one app is meaningless to another, even if leaked.
- Email verification tokens follow the same pattern: only a hash is
  stored, they're single-use (an atomic `UPDATE ... WHERE used = false`,
  so a doubly-clicked or forwarded link can't be redeemed twice), and
  expire after 24 hours.
- Failed-login lockout is keyed on `(username, ip)` together, so it
  can't be used to lock out a shared IP by spraying one account, or
  vice versa.
- Per-app request-rate limiting protects the service from one
  misbehaving/compromised app hammering it — including `/register` and
  `/resend-verification`, which deliberately don't get a separate
  throttle on top of it (see the comment in `src/routes/apiV1.js`).
- The password-history similarity check (see [Password policy](#password-policy))
  is the one deliberate exception to "passwords are never recoverable":
  `password_simhash` stores a lossy fuzzy fingerprint of each password's
  character histogram — not reversible to the original password, but
  more information than a cryptographic hash reveals. That tradeoff is
  the unavoidable cost of the "70% similar to your last two passwords"
  feature; there is no way to detect near-duplicate passwords from
  one-way hashes alone.
- The one credential Passport Consumer does store reversibly is the SMTP
  password (`email_settings.encrypted_password`), because sending mail
  requires authenticating with it again on every send. It's encrypted
  (AES-256-GCM, keyed from `server.encryptionKey`), not plaintext, and
  never returned by any API response — but someone with both database and
  encryption-key access could recover it.
- The same reversible-encryption tradeoff applies to the dormant MFA
  secret (`passwords.mfa_secret`) — Passport Consumer has to check a
  submitted 6-digit code against it, which a one-way hash can't support.
- OIDC ID tokens are signed (RS256), not encrypted — they carry the same
  claims (username, name, email) an app already gets back from
  `/api/v1/login` or `/oidc/userinfo`, not anything more sensitive.
  Passport Consumer's private signing key never leaves the server; only
  its public half is ever published, at `/.well-known/jwks.json`.
- OIDC redirect URIs are matched exactly, never as a prefix — a
  registered app's callback URL can't be used to redirect an
  authorization code somewhere else by appending to it.
- Every uid/appId/token lookup fails closed on a malformed input (see
  `src/utils/uuid.js`) rather than reaching Postgres with attacker-
  controlled data — a single bad `X-App-Id` header can't crash the
  process or become a type-cast error surfacing as an unhandled
  rejection.
