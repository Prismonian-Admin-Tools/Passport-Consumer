'use strict';

// This guards Passport Consumer's OWN frontend — separate entirely from
// the app-facing /api/v1/* login contract. A person visits Passport
// Consumer directly to manage their account, and admins use it to manage
// everyone else's.

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Not authenticated' });
}

/**
 * Gates a route on the caller's CURRENT role being 'admin' — re-fetched
 * from the DB on every request rather than trusting req.session.user.role
 * (cached at login), otherwise a user who's demoted keeps acting as an
 * admin for as long as their session cookie lives. Replaces the source
 * project's requireCapability/requireAnyCapability entirely: there's no
 * per-capability granularity left to gate on now that ranks are gone —
 * 'admin' gets every management capability, 'user' gets none.
 */
function requireAdmin(userStore) {
  return async (req, res, next) => {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not authenticated' });
    const user = await userStore.findByUid(req.session.user.uid);
    if (!user || user.disabled) return res.status(401).json({ error: 'Not authenticated' });
    if (user.role !== 'admin') return res.status(403).json({ error: 'This requires an admin account' });
    next();
  };
}

/**
 * Kills the session outright if the account was disabled mid-session, and
 * blocks every route except a small allowlist while a forced password
 * change is pending. The onboarding wizard this mirrored in the source
 * project (needs_onboarding, /account/onboarding) doesn't exist in this
 * fork — self-registration with email verification is the "new account"
 * flow here, and an admin-created account just gets the same forced-
 * change treatment every account has always had, no wizard attached.
 */
function requireGoodStanding(userStore) {
  const ALLOWED_WHILE_CHANGE_REQUIRED = new Set(['/session', '/logout', '/account/password', '/account']);
  return async (req, res, next) => {
    if (!req.session || !req.session.user) return next();
    const user = await userStore.findByUid(req.session.user.uid);
    if (!user) {
      return req.session.destroy(() => res.status(401).json({ error: 'Account no longer exists' }));
    }
    if (user.disabled) {
      return req.session.destroy(() => res.status(403).json({ error: 'This account has been disabled.' }));
    }
    if (user.must_change_password && !ALLOWED_WHILE_CHANGE_REQUIRED.has(req.path)) {
      return res.status(428).json({ error: 'A password change is required before continuing.', requirePasswordChange: true });
    }
    next();
  };
}

module.exports = { requireAuth, requireAdmin, requireGoodStanding };
