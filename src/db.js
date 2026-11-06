'use strict';
const fs = require('fs');
const { Pool } = require('pg');

let pool = null;

/**
 * `ssl: { rejectUnauthorized: false }` encrypts the wire but verifies
 * nothing about who's on the other end of it — a MITM holding ANY
 * certificate passes. That used to be this function's unconditional
 * behavior whenever database.ssl was just `true`. Now `true` means real
 * certificate verification against the system's trusted CA bundle (fine
 * for a managed Postgres provider with a publicly-trusted cert); point
 * database.sslCaFile at a PEM file for a self-signed/internal CA instead
 * of turning verification off. database.sslRejectUnauthorized: false
 * remains available as an explicit, deliberate opt-out — e.g. local dev
 * against a throwaway self-signed cert — but is never the default.
 */
function buildSslOption(dbConfig) {
  if (!dbConfig.ssl) return false;
  const ssl = { rejectUnauthorized: dbConfig.sslRejectUnauthorized !== false };
  if (dbConfig.sslCaFile) ssl.ca = fs.readFileSync(dbConfig.sslCaFile, 'utf8');
  return ssl;
}

function initPool(dbConfig) {
  pool = new Pool({
    host: dbConfig.host,
    port: dbConfig.port,
    database: dbConfig.name,
    user: dbConfig.user,
    password: dbConfig.password,
    ssl: buildSslOption(dbConfig),
  });
  return pool;
}

function getPool() {
  if (!pool) throw new Error('DB pool not initialized — call initPool() first');
  return pool;
}

module.exports = { initPool, getPool };
