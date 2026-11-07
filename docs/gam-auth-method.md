# Adding a `gam` Authentication Method (Federation with Global-Admin-Account-System)

This document is a design and implementation guide for a feature that
does not yet exist in this codebase. The `apps.auth_method` column
currently accepts exactly two values, `passport` and `oidc` (see
`AUTH_METHODS` in `src/models/appStore.js`). No code in this repository
communicates with Global-Admin-Account-System ("GAM"). This document is
intended as the starting point for an implementer, not a record of work
already completed.

## 1. Rationale

Passport Consumer is an independent identity service for end users who
self-register into Prismonian's own applications (see the README's
"Self-service registration" section). Global-Admin-Account-System is
the separate, sibling service from which this project was forked; it is
Prismonian's internal staff/administrative identity provider, built
around ranks (`trustedInstaller`, `systemAdministrator`,
`elevatedStaff`, `staff`), with no self-registration and
administrator-provisioned accounts only.

A Prismonian application may require both account types to authenticate
through a single login screen — a consumer who self-registered through
Passport Consumer, and a Prismonian employee whose account resides in
GAM (for example, support staff moderating that application). Such an
application should not be required to integrate two separate identity
providers, maintain two sets of credentials, or determine in advance
which provider a given username belongs to. A `gam` authentication
method would allow that application to continue calling Passport
Consumer's existing `/api/v1/login` contract exactly as it does today,
with Passport Consumer forwarding the credential check to GAM for any
application registered under this method.

This is the inverse of [OIDC federation](../README.md#federated-identity-passport-consumer-as-an-openid-connect-provider).
In that case, Passport Consumer functions as the identity provider and
another system consumes it. In this case, Passport Consumer would
function as the relying party, with GAM as the identity provider. The
existing OIDC code path should not be reused for this purpose: GAM
speaks the same proprietary `/api/v1/login` token contract that
Passport Consumer does, by virtue of shared lineage, not OIDC.

## 2. The Contract to Be Consumed

GAM's application-facing login contract (`POST /api/v1/login` on a GAM
instance, documented in that project's own README) is structurally
almost identical to Passport Consumer's own, as a consequence of
Passport Consumer having been forked from it:

```
POST https://<gam-host>/api/v1/login
X-App-Id: <a GAM-issued appId, distinct from any Passport Consumer appId>
X-App-Secret: <that application's GAM-issued secret>
Content-Type: application/json

{ "username": "...", "password": "..." }
```

The `status` field in the response is one of: `good`, `good_change_pw`,
`bad`, `disabled`, `good-no-access`, or `good_mfa_required` (the last
only if GAM's calling-application record has `supportsMfaChallenge`
set). There is no `unverified` status — GAM has no self-registration or
email-verification concept, and no `/register` or
`/resend-verification` endpoints.

A critical point requiring attention: the `X-App-Id`/`X-App-Secret`
pair GAM expects is a credential issued by GAM to Passport Consumer
itself, and is unrelated to the `appId`/`appSecret` a Prismonian
application presents to Passport Consumer's own `/api/v1/*`
endpoints. Passport Consumer would need to be registered as a single
application within GAM (for example, via `bootstrap -- --app
passport-consumer-bridge`, run once against the GAM instance) and would
hold that one GAM credential pair at the service level — not one per
Prismonian application that opts into `auth_method: 'gam'`. Multiple
Passport Consumer applications federating with GAM would share the
same upstream credential.

## 3. Required Changes

### 3.1 Schema

Add `'gam'` to the `auth_method` CHECK constraint (originally defined in
`src/migrations/001_init.sql`; this should be introduced via a new
migration, not an edit to that file) and to `AUTH_METHODS` in
`src/models/appStore.js`.

### 3.2 Passport Consumer's GAM Credential

This is a service-level secret — one per Passport Consumer deployment,
not one per registered application — and should be stored in
`config.yml` alongside `server.sessionSecret`, `server.encryptionKey`,
and `database.*`, rather than in a database table editable from the
admin panel in the manner of SMTP settings, since no value here would
plausibly be changed by an administrator without a restart, and no
revision history is required. A representative structure:

```yaml
gam:
  baseUrl: "https://gam.internal.prismonian.com"
  appId: "..."
  appSecret: "..."       # the secret GAM displays once, at bootstrap or app-creation time
  timeoutMs: 5000
```

This value should be validated at startup using the same approach
`src/config.js` already applies to `sessionSecret`/`encryptionKey` —
failing closed if `gam.appSecret` appears to be a placeholder, rather
than allowing the misconfiguration to surface on the first login
attempt.

### 3.3 A GAM Client Module

A new file, for example `src/utils/gamClient.js`, should provide a thin
wrapper structurally similar to how `src/utils/mailer.js` wraps
nodemailer: a single `login(username, password)` method that issues a
POST to `${gam.baseUrl}/api/v1/login` with the configured headers and
returns GAM's parsed response. The following considerations, each
already addressed elsewhere in this codebase, apply equally here:

- **Timeout.** An outbound HTTP call within a request handler that
  never times out can tie up the event loop under load. `gam.timeoutMs`
  should be enforced, with the call aborted cleanly on expiry. A GAM
  outage should result in a failed login attempt, not an indefinitely
  hung request.
- **Failure disclosure.** A GAM connection failure, timeout, or 5xx
  response should collapse to the same generic failure `/api/v1/login`
  already returns when an application is not using the expected
  contract. The existence of a second system behind this one, and
  whether that system is currently reachable, should not be disclosed
  to the calling application or to an attacker.
- **TLS verification.** This is a service-to-service call across
  whatever network separates the two systems, and should follow the
  same "verify by default, with an explicit opt-out limited to a
  known-trusted internal host" posture already applied to
  `database.ssl` (`src/db.js`) and the SMTP relay TLS option
  (`src/utils/mailer.js`), rather than introducing a new policy.

### 3.4 The Login Route

In `src/routes/apiV1.js`'s `POST /login`, the existing gate —

```js
if (req.callingApp.auth_method !== 'passport') {
  return res.json({ status: 'bad' });
}
```

— would require a branch for `req.callingApp.auth_method === 'gam'`
that invokes the new client in place of `userStore.verify()`. The more
significant design question is not the GAM call itself but how to
handle a successful result, since every downstream component in this
codebase — `sessionStore`, `app_access` (per-application blocking),
`activityLog`, and the admin panel's Users tab — assumes a `uid` that
exists in Passport Consumer's own `users` table.

**Recommended approach: a shadow account.** On a successful GAM login,
the implementation should look up (by username) or create a Passport
Consumer user row mirroring the GAM identity, then proceed as the
native login path does (`sessionStore.issue`, `touchLogin`, the
unknown-logon-point email, and so on) against that shadow `uid`.
Specifically:

- A marker should be added so these rows can be identified later —
  for example, a nullable `userdata.gam_username TEXT` column, where a
  non-null value indicates the account is a GAM mirror rather than a
  Passport Consumer native account — rather than overloading an
  existing column.
- **The shadow account's `role` in Passport Consumer must always be
  `user`, and must never be derived from the GAM account's rank.**
  GAM's rank governs administrative rights within GAM; it has no
  bearing on whether a given person should be able to administer
  Passport Consumer. Mapping a GAM `systemAdministrator` to a Passport
  Consumer `admin` would constitute a privilege-escalation defect, not
  a convenience.
- Passport Consumer's own password fields (`password_hash`, and
  related columns) are not meaningful for a shadow account; it must not
  be possible to authenticate to one through the native
  `/api/v1/login` path using a Passport-Consumer-local password.
  Either `cannot_change_password: true` should be enforced together
  with a hash that can never match (for example, storing no usable
  value), with a dedicated flag checked before the native `verify()`
  path executes, or shadow accounts should be excluded from
  `usernames`/`passwords` entirely, which would require revisiting the
  four-table join for this case. This decision should be made
  deliberately; whichever approach is simplest to implement should not
  be adopted without first confirming that the native login path cannot
  be used to impersonate a shadow account.
- Mirrored fields (disabled status, display information) should be
  refreshed on every successful login, not only at creation, so that a
  GAM account disabled or renamed after its first federated login does
  not continue operating on stale data.
- `app_access` (per-application blocking) functions without
  modification once a real `uid` exists — an administrator retains the
  ability to block a specific GAM-federated user from a specific
  Prismonian application without any change on the GAM side.

### 3.5 `/api/v1/register` and `/api/v1/resend-verification`

GAM has no self-registration concept. An application registered under
`auth_method: 'gam'` should receive the same generic, non-functional
response from these endpoints that an `oidc` application receives
today; `'gam'` should be added to whichever check currently permits
only `'passport'` through.

### 3.6 Multi-Factor Authentication

This is out of scope for an initial implementation. GAM has its own
dormant MFA mechanism; Passport Consumer's `good_mfa_required`/
`/login/mfa` flow is built around Passport Consumer's own
`mfa_enabled`/`mfa_secret` columns, which carry no meaningful value for
a shadow account. A deliberate decision should be made, and documented,
as to whether a GAM account with MFA enabled should be rejected, passed
through via a second round-trip to GAM's own `/login/mfa`, or left
unsupported. This should not be allowed to pass unaddressed as an
unconsidered gap.

### 3.7 Activity Log

Existing `activityLog.add('auth', ...)` calls elsewhere record
`"signed in via ${req.callingApp.slug}"`. The equivalent call for this
path should record `"signed in via ${req.callingApp.slug}
(GAM-federated)"` or similar, so that the audit trail does not conflate
the two credential sources.

## 4. Unaffected Components

Per-application access blocking, session issuance and revocation
(including "sign out everywhere"), rate limiting, OIDC federation (an
application may independently also be configured as `oidc` — these are
settings of different applications, not combinable on a single
application), and the admin panel's Users tab all continue to function
without modification once a genuine shadow `uid` exists. None of these
components are currently concerned with how an account was
authenticated, only with the fact that it has an account.

## 5. Verification Approach

Reproducing a federation defect by code inspection alone is not a
reliable method of verification. A real or stubbed GAM instance should
be stood up and the actual HTTP path exercised, following the same
approach used to identify the SMTP mailer defects previously found in
this codebase: a fresh PostgreSQL database, migrations applied, a
running Passport Consumer process, and either a cloned GAM instance or
a minimal substitute server implementing enough of `/api/v1/login` to
exercise `good`, `bad`, `disabled`, `good-no-access`,
`good_mfa_required`, a delayed/timeout response, and a refused
connection. The following should be confirmed: a successful GAM login
issues a genuine Passport Consumer token usable by the calling
application against `/validate` and `/logout`, identically to a native
login; a block or disable applied on the GAM side takes effect on the
subsequent login attempt rather than retroactively against an
already-issued token; and a GAM outage fails closed using the same
generic response shape applied to every other non-disclosed failure
case in this contract.
