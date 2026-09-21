'use strict';
const express = require('express');
const path = require('path');
const { asyncHandler } = require('../middleware/asyncHandler');

/**
 * Public — a human clicks this from their inbox, not an app calling the
 * API, so unlike everything under /api/v1/* it needs no X-App-Id/
 * X-App-Secret headers. Mounted directly on `app` in server.js, outside
 * the requireApp gate, alongside the OIDC mount (see decision #2 in
 * README's Self-service registration section).
 *
 * Two routes: GET /verify-email serves the static confirmation page
 * (public/verify-email.html) regardless of whether the token is any
 * good — it's a plain page shell with its own client-side JS. That JS
 * reads ?token= itself and calls GET /verify-email/confirm, the actual
 * (also public) endpoint that atomically consumes the token and marks
 * the account verified, to learn whether to show success or failure.
 */
module.exports = function verifyEmailRoutes({ userStore, emailVerificationStore, activityLog }) {
  const router = express.Router();
  const pagePath = path.join(__dirname, '..', '..', 'public', 'verify-email.html');

  router.get('/verify-email', (req, res) => {
    res.sendFile(pagePath);
  });

  router.get('/verify-email/confirm', asyncHandler(async (req, res) => {
    const token = req.query.token;
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ ok: false, error: 'Missing verification token.' });
    }

    const record = await emailVerificationStore.consume(token);
    if (!record) {
      // Covers not-found, already-used, and expired alike — same non-
      // revealing posture as the rest of the app-facing contract: telling
      // a caller WHICH of those it was gains an attacker more than it
      // helps a legitimate user, who can just request a fresh link either
      // way.
      return res.json({ ok: false, error: 'This verification link is invalid or has expired. Request a new one and try again.' });
    }

    const profile = await userStore.markEmailVerified(record.uid);
    await activityLog.add('auth', `${profile.username} verified their email address`, profile.uid, profile.username);
    res.json({ ok: true });
  }));

  return router;
};
