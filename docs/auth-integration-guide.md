# Integrating with Passport Consumer's Authentication API

This document is a reference for developers integrating a Prismonian
application with Passport Consumer's proprietary authentication
protocol (the `passport` auth method). It covers obtaining credentials,
every endpoint in the contract, every response an integration must
handle, and the recommended end-to-end flow.

This is a server-to-server API. All calls described here are expected
to originate from the integrating application's own backend, not from
an end user's browser or mobile client directly — the application
secret described below must never be embedded in client-side code.

## 1. Obtaining Credentials

Before an application can call this API, it must be registered with
Passport Consumer by an administrator, either from the admin panel's
Apps tab or via the CLI:

```bash
node scripts/passport-cli.js apps create <slug> --name "<display name>"
```

This returns an `appId` and an `appSecret`. **The secret is displayed
exactly once, at creation time, and cannot be retrieved again** — only
regenerated, which immediately invalidates the previous one. Store it
the way any credential of equivalent sensitivity is stored (a secrets
manager, an encrypted environment variable store); it must not be
checked into source control or logged.

By default, a newly registered application uses the `passport` auth
method, which is the subject of this document. (A second method,
`oidc`, exists for applications that can only integrate via a standard
OpenID Connect client library; see the README's "Federated identity"
section if that applies instead. The two are mutually exclusive per
application.)

## 2. Required Headers

Every request to `/api/v1/*` must include:

```
X-App-Id: <appId>
X-App-Secret: <appSecret>
Content-Type: application/json
```

A request with a missing, unknown, or incorrect `X-App-Id`/`X-App-Secret`
pair receives `401` with `{ "status": "invalid_app" }` before any other
processing occurs. An application that has been disabled by an
administrator (`apps disable <slug>`) also receives `invalid_app` for
every call, indistinguishable from a bad credential.

## 3. Rate Limiting

Two independent limits apply:

- **Per-application.** Every call to `/api/v1/*` from a given
  application counts against a shared budget
  (`rateLimit.perApp.maxRequestsPerMinute` in `config.yml`). Exceeding
  it returns `429` with `{ "status": "rate_limited", "retryAfterSeconds":
  N }` and a `Retry-After` header. This protects Passport Consumer from
  a single misbehaving or compromised integration; it is not specific
  to login attempts.
- **Per login attempt.** `/login` additionally tracks failed attempts
  by `(username, source IP)`, independent of which application is
  calling. Too many failures in the configured window returns the same
  `429` / `rate_limited` shape. An integration should surface this to
  the end user as "too many attempts, try again later" without
  distinguishing it from the per-application limit.

An integration should treat `429` as retryable after the indicated
delay and must not retry immediately in a loop.

## 4. Endpoint Reference

### `POST /api/v1/register`

Creates a new, self-registered end-user account.

**Request:**
```json
{ "username": "newuser", "password": "...", "email": "newuser@example.com", "fullName": "optional" }
```

`username`, `password`, and `email` are required; `fullName` is
optional. The password is checked against the configured password
policy before the account is created. `username` and `email` must both
be unique across all accounts; a collision in either field, or a
request from an application not registered under the `passport` auth
method, returns `400` with a generic `invalid_request` — the response
does not indicate which field collided, matching the non-disclosure
posture of every other endpoint in this contract.

**Response (success):**
```json
{ "status": "registered" }
```

No session token is returned. The account cannot sign in until the
emailed verification link has been followed — see `/login`'s
`unverified` status below. Verification happens outside this API (the
user clicks a link sent to the address they provided); the integrating
application does not need to build anything to support it beyond, at
most, a "check your email" message after a successful `/register` call.

### `POST /api/v1/resend-verification`

```json
{ "username": "newuser" }
```
or
```json
{ "email": "newuser@example.com" }
```

Always returns `{ "status": "ok" }`, regardless of whether the account
exists or is already verified — an integration must not infer account
existence from this response. If the account exists and is unverified,
a new verification link invalidates and replaces any previous one.

### `POST /api/v1/login`

```json
{ "username": "adrian", "password": "..." }
```

The `status` field in the response is always exactly one of the
following. An integration must handle every value; none should be
treated as unexpected.

| `status` | Meaning | Token issued? |
|---|---|---|
| `good` | Valid credentials, account in good standing. | Yes |
| `good_change_pw` | Valid credentials, but the account must change its password before continuing. | Yes |
| `bad` | Incorrect username or password. Also returned for any application not registered under the `passport` method — this response never indicates which. | No |
| `disabled` | The account exists and the password is correct, but the account has been disabled by an administrator. | No |
| `unverified` | Valid credentials, but the account has an email address on file that has not yet been confirmed. (An account with no email at all is never blocked this way — there is nothing to confirm.) | No |
| `good-no-access` | Valid credentials, but an administrator has blocked this specific user from this specific application (see the README's "Per-app access control"). The account's credentials remain valid everywhere else. | No |
| `good_mfa_required` | Valid credentials, but the account has multi-factor authentication enabled and this application has opted in to handling the second factor (see §5 below). | No — see §5 |

For `good` and `good_change_pw`, the response also includes:

```json
{
  "status": "good",
  "token": "tok_...",
  "user": { "uid": "...", "username": "...", "role": "user", "email": "...", "emailVerified": true, "...": "..." }
}
```

`token` is an opaque session token, valid only for the calling
application (a token issued to one application is meaningless if
presented by another). `user` is the account's profile, documented in
§6 below.

Malformed request bodies return `400` with `invalid_request`. See §3 for
`429` / `rate_limited`.

**An integration must branch on `good_change_pw` distinctly from
`good`.** Both return a usable token, but `good_change_pw` means the
account is required to change its password before doing anything else
— the integration should route the user to a password-change flow
(calling `/change-password`, below) rather than treating the session as
fully active.

### `POST /api/v1/login/mfa`

Completes a `good_mfa_required` challenge. See §5.

### `POST /api/v1/validate`

```json
{ "token": "tok_..." }
```

**Response:**
```json
{ "valid": true, "user": { "...": "..." } }
```
or
```json
{ "valid": false }
```

This is the call an integration should make to check whether a
previously stored token is still good — for example, on each incoming
request to the integration's own backend, if it is using this token as
its session mechanism. A successful validate slides the token's idle
timeout forward; it will eventually expire regardless of use, at the
absolute TTL configured in `config.yml`. `valid: false` is also
returned (and the token invalidated) if the account has since been
disabled or blocked from this specific application — an integration
should treat this identically to "session expired, log in again."

### `POST /api/v1/logout`

```json
{ "token": "tok_..." }
```

Revokes the token for this application only. Always returns `{ "ok":
true }`, including when the token was already invalid — logout is
idempotent by design.

### `POST /api/v1/change-password`

```json
{ "token": "tok_...", "currentPassword": "...", "newPassword": "...", "confirmPassword": "..." }
```

`currentPassword` is required only if the account is not currently
under a forced password change — an account that reached `/login` with
`good_change_pw` is not required to supply it, since the entire point
of a forced change is that the account holder may not remember or have
been given a usable current password. `newPassword` is checked against
the same password policy `/register` uses. On success, every token this
account holds across every application is revoked, and a fresh token
for the calling application is issued and returned — the response
shape matches `/login`'s success case.

### `POST /api/v1/update-profile`

```json
{ "token": "tok_...", "fullName": "...", "description": "...", "theme": "..." }
```

Self-service update of the fields an end user is permitted to change
directly. All fields are optional; only the fields present in the
request are updated. This call is refused while a password change is
pending (the same condition `good_change_pw` signals) — an integration
should not call this until the account is in `good` standing.

## 5. Multi-Factor Authentication (Opt-In)

Multi-factor authentication exists on the account but does nothing at
login unless the calling application has explicitly opted in
(`supportsMfaChallenge`, toggled by an administrator from the Apps
tab's MFA switch, or set directly via `PUT /api/apps/:appId/mfa-support`
— there is no CLI command for this one). An application that has not
opted in will never see `good_mfa_required`; its accounts' MFA status
is simply not consulted at login.

For an application that has opted in, `/login` returns:
```json
{ "status": "good_mfa_required", "mfaTicket": "..." }
```

No token is issued at this point. The integration must collect a
second-factor code from the user (a live TOTP code or one of the
account's backup codes) and submit it:

```json
POST /api/v1/login/mfa
{ "mfaTicket": "...", "token": "<the 6-digit code or backup code>" }
```

A correct code completes the login exactly as `/login` would have —
the response matches `/login`'s `good`/`good_change_pw` success shape.
An incorrect code counts against the same failed-attempt lockout as a
wrong password (§3); the ticket itself also has a limited number of
attempts and a short expiry, after which the integration must call
`/login` again to obtain a new one.

An application that has not opted in to MFA handling should not assume
its users cannot enable it — they can, from their own account settings
in Passport Consumer's own frontend — but doing so has no effect on
that application's login flow until the application opts in.

## 6. The User Profile Object

The `user` object returned by `/login`, `/validate`, `/change-password`,
and `/update-profile` has this shape:

```json
{
  "uid": "a0e28711-ab55-4760-abf5-11cbc7075bd0",
  "username": "adrian",
  "role": "user",
  "email": "adrian@example.com",
  "emailVerified": true,
  "fullName": "",
  "description": "",
  "displayName": null,
  "officeLocation": null,
  "department": null,
  "phone": null,
  "networkId": null,
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

`uid` is the stable identifier. **An integration must key its own
application-specific data (permissions, preferences, anything specific
to that integration) on `uid`, never on `username`** — an administrator
can rename an account, and `uid` is the only field guaranteed not to
change for the life of the account. `role` reflects Passport Consumer's
own two-tier admin/user distinction and has no bearing on any
permission model the integrating application maintains internally.

## 7. Recommended Integration Flow

A typical application integration follows this sequence:

1. **Sign-up.** The application's own sign-up form collects a username,
   password, and email, and the application's backend calls
   `POST /register`. On `{ "status": "registered" }`, the application
   tells the user to check their email.
2. **Verification.** The user follows the link in the verification
   email (sent directly by Passport Consumer; the application is not
   involved in this step).
3. **Sign-in.** The application's own login form collects a username
   and password, and the application's backend calls `POST /login`.
   The application branches on `status` per the table in §4 — in
   particular, routing `good_change_pw` to a forced password-change
   step and `unverified` to a "please verify your email, resend?"
   prompt (optionally calling `/resend-verification`).
4. **Session maintenance.** The application stores the returned `token`
   against its own session for that user, and calls `/validate` to
   confirm it is still good — typically on each request that needs to
   confirm the user is still authenticated, or on an interval, depending
   on the application's own session design.
5. **Sign-out.** The application calls `/logout` with the token when
   the user signs out, and discards its own local session state
   regardless of the response.

## 8. Error-Handling Checklist

An integration should, at minimum:

- Treat `bad`, `disabled`, `unverified`, and `good-no-access` as
  distinct user-facing messages — do not collapse them all to a single
  generic "login failed," since the correct next action differs for
  each (retry, contact support, check email, contact support about this
  specific application).
- Never display the raw `invalid_app` or `invalid_request` responses to
  an end user — these indicate a defect in the integration itself (a
  bad credential, a malformed request), not something the end user can
  act on.
- Respect `Retry-After` on every `429` response rather than retrying
  immediately.
- Never log a request body containing a password, nor the `appSecret`
  header, in plaintext in any persistent log.
