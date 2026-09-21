'use strict';
// Usage:
//   npm run bootstrap -- --username adrian [--app someapp]
//   (prompts for the temporary password, input hidden)
//
// --password "temporary-pw-123" still works for scripted/CI use, but a
// CLI flag lands in shell history and is visible to any other user on the
// box via `ps aux` for as long as the process runs — the interactive
// prompt (or the PASSPORT_BOOTSTRAP_PASSWORD env var) avoids that.
// Creates the first account as a normal role: 'admin' account, forced to
// change its password on first login like every admin-created account —
// no special-casing, since there's no onboarding-skip path in this fork
// (see decision #1 and #2 in README) — and, optionally, registers a
// first client app, printing its secret ONCE.
const { loadConfig } = require('../src/config');
const { initPool } = require('../src/db');
const { UserStore } = require('../src/models/userStore');
const { AppStore } = require('../src/models/appStore');
const { promptPassword } = require('./lib/passwordInput');
const { warnSecretOutput } = require('./lib/secretWarning');

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? process.argv[i + 1] : fallback;
}

async function main() {
  const username = arg('username');
  const appSlug = arg('app');

  if (!username) {
    console.error('Usage: npm run bootstrap -- --username <name> [--password <pw>] [--app <slug>]');
    process.exit(1);
  }

  let password = arg('password') || process.env.PASSPORT_BOOTSTRAP_PASSWORD || null;
  if (!password) {
    password = await promptPassword('Temporary password for the admin account: ');
  }
  if (!password) {
    console.error('A password is required.');
    process.exit(1);
  }

  const config = loadConfig();
  const pool = initPool(config.database);
  const userStore = new UserStore(pool);
  const appStore = new AppStore(pool);

  const profile = await userStore.create({
    username, password, role: 'admin', fullName: '', description: 'Bootstrap admin account',
  });
  console.log(`\nCreated admin account "${profile.username}" (uid ${profile.uid}).`);
  console.log('mustChangePassword is set — they will be forced to pick a new password on first login.\n');

  if (appSlug) {
    const { app, secret } = await appStore.create({ slug: appSlug, name: appSlug });
    console.log(`Registered app "${app.slug}" (appId ${app.appId}).`);
    warnSecretOutput();
    console.log(`Secret (SAVE THIS NOW — it cannot be shown again): ${secret}\n`);
  }

  await pool.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
