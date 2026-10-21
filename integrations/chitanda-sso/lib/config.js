'use strict';

const path = require('node:path');
const fs = require('node:fs');

function loadEnv(file) {
  if (!fs.existsSync(file)) return {};
  const env = {};
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx <= 0) continue;
    const key = trimmed.slice(0, idx).trim();
    const val = trimmed.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
    env[key] = val;
  }
  return env;
}

const envFile = process.env.SSO_ENV_FILE || path.resolve(__dirname, '..', '.env.local');
const defaultEnv = loadEnv(envFile);

const config = {
  port: parseInt(process.env.PORT || defaultEnv.PORT || '9787', 10),
  host: process.env.HOST || defaultEnv.HOST || '127.0.0.1',
  issuer: process.env.SSO_ISSUER || defaultEnv.SSO_ISSUER || 'https://sso.chitanda.net',
  cookieDomain: process.env.SSO_COOKIE_DOMAIN ?? defaultEnv.SSO_COOKIE_DOMAIN ?? '',
  cookieName: process.env.SSO_COOKIE_NAME || defaultEnv.SSO_COOKIE_NAME || '__Host-chitanda_sso_session',
  dataDir: process.env.SSO_DATA_DIR || defaultEnv.SSO_DATA_DIR || path.resolve(__dirname, '..', 'data'),
  adminUsername: process.env.CHITANDA_ADMIN_USERNAME || defaultEnv.CHITANDA_ADMIN_USERNAME || '',
  adminPasswordHash: process.env.CHITANDA_ADMIN_PASSWORD_HASH || defaultEnv.CHITANDA_ADMIN_PASSWORD_HASH || '',
  sessionTtlMs: 7 * 24 * 60 * 60 * 1000,     // 7 days
  accessTokenTtlSec: 15 * 60,                // 15 mins
  refreshTokenTtlSec: 30 * 24 * 60 * 60,      // 30 days
  authCodeTtlSec: 5 * 60,                    // 5 mins
  dnsApi: {
    baseURL: process.env.DNS_API_BASE_URL || defaultEnv.DNS_API_BASE_URL || 'https://dns.chitanda.net',
    uid: parseInt(process.env.DNS_API_UID || defaultEnv.DNS_API_UID || '1001', 10),
    zoneId: parseInt(process.env.DNS_API_ZONE_ID || defaultEnv.DNS_API_ZONE_ID || '3', 10),
    zone: process.env.DNS_API_ZONE || defaultEnv.DNS_API_ZONE || 'chitanda.net',
    apiKey: process.env.DNS_API_KEY || defaultEnv.DNS_API_KEY || ''
  }
};

if(config.issuer.startsWith('https:')&&(config.cookieDomain||!config.cookieName.startsWith('__Host-')))throw Error('Production SSO requires a host-only __Host- cookie');
module.exports = config;
