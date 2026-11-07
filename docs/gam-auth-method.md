# Adding a `gam` auth method (federating with Global-Admin-Account-System)

This is a **design/implementation guide for a feature that does not
exist yet** — `apps.auth_method` accepts exactly two values today,
`passport` and `oidc` (`src/models/appStore.js`'s `AUTH_METHODS`). There
is no code anywhere in this codebase that speaks to
Global-Admin-Account-System ("GAM"). If you're picking this up, this
document is the starting point, not a changelog.

## Why this would exist

Passport Consumer is this fork's own, independent identity service for
**end users who self-register** into Prismonian's own apps (see the
README's "Self-service registration" section). Global-Admin-Account-
System is the separate, sibling service this project was forked from —
it's Prismonian's **internal staff/admin** identity provider: ranks
(`trustedInstaller`/`systemAdministrator`/`elevatedStaff`/`staff`), no
self-registration, admin-provisioned accounts only.

Some Prismonian app is presumably going to want **both kinds of user**
signing into the same login screen — a consumer who self-registered via
Passport Consumer, and a Prismonian employee whose account lives in GAM
(support staff moderating that app, say). That app shouldn't have to
integrate two separate identity providers, maintain two sets of
credentials, or know which one a given username belongs to. A `gam` auth
method lets that app keep calling Passport Consumer's own
`/api/v1/login` contract exactly as it does today, with Passport
Consumer forwarding the credential check to GAM behind the scenes for
apps registered under this method.

**This is the inverse of [OIDC federation](../README.md#federated-identity-passport-consumer-as-an-openid-connect-provider).**
There, Passport Consumer is the identity provider and some other system
consumes it. Here, Passport Consumer would be the **relying party**,
and GAM is the identity provider. Don't reuse the OIDC code path for
this — GAM speaks the same proprietary `/api/v1/login` token contract
Passport Consumer does (same lineage), not OIDC.

## The contract you'd be calling

GAM's app-facing login contract (`POST /api/v1/login` on a GAM
instance, documented in that project's own README) is structurally
almost identical to Passport Consumer's own, because Passport Consumer
was forked from it:

```
POST https://<gam-host>/api/v1/login
X-App-Id: <a GAM-issued appId — NOT a Passport Consumer appId>
X-App-Secret: <that app's GAM-issued secret>
Content-Type: application/json

{ "username": "...", "password": "..." }
```

Response `status` is one of: `good`, `good_change_pw`, `bad`,
`disabled`, `good-no-access`, `good_mfa_required` (if GAM's calling-app
record has `supportsMfaChallenge` set). **There is no `unverified`** —
GAM has no self-registration or email-verification concept at all, and
no `/register` or `/resend-verification` endpoints either.

The critical detail: **the `X-App-Id`/`X-App-Secret` pair GAM expects
is a credential issued BY GAM, to Passport Consumer itself** — it has
nothing to do with the `appId`/`appSecret` the Prismonian app presents
to Passport Consumer's own `/api/v1/*`. Passport Consumer would need to
be registered as **one single app inside GAM** (e.g. `bootstrap -- --
app passport-consumer-bridge` run once against the GAM instance), and
hold that one GAM credential pair itself — not one per Prismonian app
that opts into `auth_method: 'gam'`. Several Passport Consumer apps
federating with GAM all share that same one upstream credential.

## What would actually need to change

### 1. Schema
Add `'gam'` to the `auth_method` CHECK constraint
(`src/migrations/001_init.sql` — write a new migration, don't edit that
one) and to `AUTH_METHODS` in `src/models/appStore.js`.

### 2. Passport Consumer's own GAM credential
This is a **service-level** secret (one per Passport Consumer
deployment, not per registered app), so it belongs in `config.yml`
alongside `server.sessionSecret`/`server.encryptionKey`/`database.*` —
not in a database table edited from the admin panel like SMTP settings,
since there's nothing here an admin would plausibly change without a
restart, and no multi-value history to keep. Something like:

```yaml
gam:
  baseUrl: "https://gam.internal.prismonian.com"
  appId: "..."
  appSecret: "..."       # the secret GAM printed ONCE at bootstrap/apps create time
  timeoutMs: 5000
```

Validate it the same way `src/config.js` already validates
`sessionSecret`/`encryptionKey` — fail closed at startup if
`gam.appSecret` looks like a placeholder, rather than discovering a
misconfiguration on the first login attempt.

### 3. A GAM client module
New file, e.g. `src/utils/gamClient.js` — a thin wrapper, structurally
similar to how `src/utils/mailer.js` wraps nodemailer: one `login(username,
password)` method that POSTs to `${gam.baseUrl}/api/v1/login` with the
configured headers and returns GAM's parsed JSON. Things to get right,
all lessons already paid for elsewhere in this codebase:

- **Timeout.** An outbound HTTP call inside a request handler that never
  times out is exactly the kind of thing that can tie up the whole
  event loop under load — set `gam.timeoutMs` and abort cleanly. A GAM
  outage should fail a login attempt, not hang the request indefinitely.
- **Don't leak which system is down.** A GAM connection failure,
  timeout, or 5xx should collapse to the same generic failure
  `/api/v1/login` already uses for "this app isn't using the right
  contract" — never reveal to the calling app (or an attacker) that
  there's a second system behind this one, let alone that it's
  unreachable right now.
- **TLS verification.** This is a service-to-service call over whatever
  network sits between the two systems — same "verify by default,
  explicit opt-out only for a known-trusted internal host" posture as
  `database.ssl` (`src/db.js`) and the SMTP relay TLS option
  (`src/utils/mailer.js`), not a new one invented from scratch.

### 4. The login route itself
In `src/routes/apiV1.js`'s `POST /login`, the existing gate —

```js
if (req.callingApp.auth_method !== 'passport') {
  return res.json({ status: 'bad' });
}
```

— needs a branch for `req.callingApp.auth_method === 'gam'` that calls
the new client instead of `userStore.verify()`. The hard part isn't
calling GAM; it's **what to do with a successful result**, because
every downstream piece of this codebase — `sessionStore`, `app_access`
(per-app blocking), `activityLog`, the admin panel's Users tab —
assumes a `uid` that exists in Passport Consumer's own `users` table.

**Recommended approach: a shadow account.** On a successful GAM login,
look up (by username) or create a Passport Consumer user row that
mirrors the GAM identity, then proceed exactly as the native path does
(`sessionStore.issue`, `touchLogin`, the unknown-logon-point email,
etc.) against that shadow `uid`. Concretely:

- Add a marker so these rows are recognizable later — e.g.
  `userdata.gam_username TEXT` (nullable; non-null means "this account
  is a GAM mirror, not a Passport Consumer native account") — rather
  than overloading an existing column.
- **The shadow account's `role` in Passport Consumer is always `user`,
  never derived from the GAM account's rank.** GAM's rank governs
  administration rights *inside GAM*; it says nothing about whether this
  person should be able to administer *Passport Consumer*. Collapsing a
  GAM `systemAdministrator` into a Passport Consumer `admin` by accident
  here would be a privilege-escalation bug, not a convenience.
- Passport Consumer's own password fields (`password_hash`, etc.) are
  meaningless for a shadow account — nobody should ever be able to log
  into one through the native `/api/v1/login` path with a
  Passport-Consumer-local password. Either enforce `cannot_change_password:
  true` and a hash that can never match (e.g. store nothing usable, or a
  dedicated `is_gam_shadow` flag checked before the native `verify()`
  path runs at all), or keep shadow accounts out of `usernames`/
  `passwords` entirely and rethink the four-table join for this one
  case — this needs a real decision, not a guess; don't ship whichever
  of these is easiest without confirming the native login path can't be
  used to impersonate a shadow account.
- Refresh the mirrored fields (disabled, display info) on every
  successful login, not just at creation — a GAM account disabled or
  renamed after its first federated login shouldn't keep working here
  indefinitely on stale data.
- `app_access` (per-app blocking) works unchanged once there's a real
  `uid` — an admin can still block one specific GAM-federated user from
  one specific Prismonian app without touching GAM at all.

### 5. `/api/v1/register` and `/api/v1/resend-verification`
GAM has no self-registration concept. An app registered under
`auth_method: 'gam'` should get the same generic non-functional
response from these that an `oidc` app gets today — add `'gam'` to
whatever check currently only allows `'passport'` through.

### 6. MFA
Out of scope for a first version. GAM has its own dormant MFA; Passport
Consumer's `good_mfa_required`/`/login/mfa` dance is built around
Passport Consumer's *own* `mfa_enabled`/`mfa_secret` columns, which a
shadow account has no meaningful value for. Decide explicitly (and
document it when you do) whether a GAM account with MFA enabled there
should be rejected, passed through via a second round-trip to GAM's own
`/login/mfa`, or just not supported — don't let this fall through
silently as an unconsidered gap.

### 7. Activity log
`activityLog.add('auth', ...)` calls elsewhere already say
`"signed in via ${req.callingApp.slug}"` — say `"signed in via
${req.callingApp.slug} (GAM-federated)"` or similar here too, so the
audit trail doesn't quietly conflate the two credential sources.

## What stays the same

Per-app access blocking, session issuance/revocation/"sign out
everywhere", rate limiting, OIDC federation (an app can independently
also be `oidc` — these are different apps' settings, not combinable on
one app), and the admin panel's Users tab all keep working unmodified
once there's a real shadow `uid` — none of them currently care how an
account was authenticated, only that it has one.

## Testing this for real

Reproducing a federation bug by reading code gets you nowhere — stand up
an actual (or stubbed) GAM instance and drive the real HTTP path, the
same way the SMTP mailer bugs in this codebase were found: a fresh
Postgres database, migrations run, a real Passport Consumer process,
and either a cloned GAM instance or a minimal stand-in server that
speaks just enough of `/api/v1/login` to exercise `good`/`bad`/
`disabled`/`good-no-access`/`good_mfa_required`, a slow/timeout
response, and a connection refused. Confirm: a successful GAM login
issues a real Passport Consumer token the calling app can use against
`/validate` and `/logout` exactly like a native login; a GAM-side
block/disable is reflected on the NEXT login, not retroactively on an
already-issued token; and a GAM outage fails closed with the same
generic response shape as every other "can't tell you why" case in this
contract.
