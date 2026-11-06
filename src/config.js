'use strict';
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const CONFIG_PATH = process.env.PASSPORT_CONFIG || path.join(__dirname, '..', 'config', 'config.yml');

function loadConfig() {
  const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
  const cfg = yaml.load(raw);
  const root = path.join(__dirname, '..');
  cfg.avatars.directory = path.resolve(root, cfg.avatars.directory);
  cfg.activity.file = path.resolve(root, cfg.activity.file);
  cfg.failedLogins.file = path.resolve(root, cfg.failedLogins.file);
  // Required separately from sessionSecret — see config.yml.example.
  // Deliberately not defaulted to sessionSecret: that's exactly the
  // key-reuse this field exists to end.
  if (!cfg.server || !cfg.server.encryptionKey) {
    throw new Error(
      'config.server.encryptionKey is required (signs nothing — encrypts the SMTP password, MFA secrets, and the ' +
      'OIDC signing key at rest). Add a random value to config.yml; see config.yml.example.'
    );
  }
  assertStrongSecret('server.sessionSecret', cfg.server.sessionSecret);
  assertStrongSecret('server.encryptionKey', cfg.server.encryptionKey);
  if (cfg.server.sessionSecret === cfg.server.encryptionKey) {
    throw new Error(
      'config.server.sessionSecret and config.server.encryptionKey must be different values — reusing one key ' +
      'for both session signing and at-rest encryption means a leak of either purpose compromises both.'
    );
  }
  return cfg;
}

// A placeholder secret left in from config.yml.example (or any other
// short/predictable value) is the single most common way a deployment
// ends up with session forgery or recoverable "encrypted" secrets despite
// every line of code above being correct — the algorithm doesn't matter
// if the key is guessable. Fails closed at startup, before the server
// ever binds a port, rather than silently accepting a weak secret that
// only gets noticed during an incident. 32 bytes (256 bits) matches the
// AES-256 key secretBox.js derives from this value, and is already comfortably
// past what session-cookie signing needs on its own.
const MIN_SECRET_LENGTH = 32;
const PLACEHOLDER_SECRETS = new Set([
  'CHANGE_ME_TO_A_RANDOM_STRING',
  'CHANGE_ME_TO_A_DIFFERENT_RANDOM_STRING',
  'CHANGE_ME',
  'changeme',
  'secret',
  'password',
]);

function assertStrongSecret(fieldName, value) {
  if (typeof value !== 'string' || value.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `config.${fieldName} must be a random string of at least ${MIN_SECRET_LENGTH} characters ` +
      `(got ${typeof value === 'string' ? value.length : 0}). Generate one with: openssl rand -base64 48`
    );
  }
  if (PLACEHOLDER_SECRETS.has(value)) {
    throw new Error(
      `config.${fieldName} is still set to the config.yml.example placeholder value — generate a real secret ` +
      `with: openssl rand -base64 48`
    );
  }
}

module.exports = { loadConfig, CONFIG_PATH };
