'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ADMIN_PASSWORD_HASH_SCHEME = 'scrypt';
const ADMIN_PASSWORD_HASH_VERSION = 'v1';
const DEFAULT_SCRYPT_COST = 32768;
const DEFAULT_SCRYPT_BLOCK_SIZE = 8;
const DEFAULT_SCRYPT_PARALLELIZATION = 1;
const DEFAULT_SCRYPT_KEY_LENGTH = 64;

const getScryptMaxMemory = (cost, blockSize, parallelization) =>
  Math.max(64 * 1024 * 1024, 128 * cost * blockSize + 128 * blockSize * parallelization + 1024 * 1024);

const parsePasswordHash = (value) => {
  const parts = String(value || '').trim().split('$');
  if (parts.length !== 7 || parts[0] !== ADMIN_PASSWORD_HASH_SCHEME || parts[1] !== ADMIN_PASSWORD_HASH_VERSION) {
    return null;
  }
  const cost = parseInt(parts[2], 10);
  const blockSize = parseInt(parts[3], 10);
  const parallelization = parseInt(parts[4], 10);
  try {
    const salt = Buffer.from(parts[5], 'base64url');
    const digest = Buffer.from(parts[6], 'base64url');
    return { cost, blockSize, parallelization, salt, digest };
  } catch {
    return null;
  }
};

const verifyPasswordHash = (password, passwordHash) => {
  return new Promise((resolve) => {
    const record = parsePasswordHash(passwordHash);
    if (!record || !Number.isInteger(record.cost)||record.cost<16384||record.cost>131072||record.blockSize!==8||record.parallelization!==1||record.digest.length!==64||record.salt.length<16) return resolve(false);

    crypto.scrypt(
      String(password || ''),
      record.salt,
      record.digest.length,
      {
        N: record.cost,
        r: record.blockSize,
        p: record.parallelization,
        maxmem: getScryptMaxMemory(record.cost, record.blockSize, record.parallelization)
      },
      (err, derived) => {
        if (err || !derived) return resolve(false);
        const match = derived.length === record.digest.length && crypto.timingSafeEqual(derived, record.digest);
        resolve(match);
      }
    );
  });
};

const createPasswordHash = (password, options = {}) => {
  return new Promise((resolve, reject) => {
    const cost = options.cost || DEFAULT_SCRYPT_COST;
    const blockSize = options.blockSize || DEFAULT_SCRYPT_BLOCK_SIZE;
    const parallelization = options.parallelization || DEFAULT_SCRYPT_PARALLELIZATION;
    const keyLength = options.keyLength || DEFAULT_SCRYPT_KEY_LENGTH;
    const salt = crypto.randomBytes(16);

    crypto.scrypt(
      String(password || ''),
      salt,
      keyLength,
      {
        N: cost,
        r: blockSize,
        p: parallelization,
        maxmem: getScryptMaxMemory(cost, blockSize, parallelization)
      },
      (err, derived) => {
        if (err) return reject(err);
        const hash = [
          ADMIN_PASSWORD_HASH_SCHEME,
          ADMIN_PASSWORD_HASH_VERSION,
          cost,
          blockSize,
          parallelization,
          salt.toString('base64url'),
          derived.toString('base64url')
        ].join('$');
        resolve(hash);
      }
    );
  });
};

// RSA Keys & JWKS
let cachedKeyPair = null;

function ensureKeyPair(dataDir) {
  if (cachedKeyPair) return cachedKeyPair;
  fs.mkdirSync(dataDir, { recursive: true });
  const privPath = path.join(dataDir, 'jwt_private.pem');
  const pubPath = path.join(dataDir, 'jwt_public.pem');
  const metaPath = path.join(dataDir, 'jwt_meta.json');

  let privateKey, publicKey, kid;

  if (fs.existsSync(privPath) && fs.existsSync(pubPath) && fs.existsSync(metaPath)) {
    privateKey = fs.readFileSync(privPath, 'utf8');
    publicKey = fs.readFileSync(pubPath, 'utf8');
    kid = JSON.parse(fs.readFileSync(metaPath, 'utf8')).kid;
  } else {
    const pair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
    kid = crypto.randomBytes(8).toString('hex');

    fs.writeFileSync(privPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });
    fs.writeFileSync(metaPath, JSON.stringify({ kid, createdAt: new Date().toISOString() }), { mode: 0o644 });
  }

  // Generate JWK components from public key
  const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
  const jwks = {
    keys: [
      {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        alg: 'RS256',
        use: 'sig',
        kid
      }
    ]
  };

  cachedKeyPair = { privateKey, publicKey, kid, jwks };
  return cachedKeyPair;
}

function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(typeof input === 'string' ? input : JSON.stringify(input));
  return buf.toString('base64url');
}

function signJwt(payload, privateKey, kid, expiresInSec) {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid
  };
  const body = {
    iat: now,
    nbf: now,
    exp: now + expiresInSec,
    ...payload
  };

  const encodedHeader = base64url(header);
  const encodedPayload = base64url(body);
  const toSign = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(toSign);
  const signature = signer.sign(privateKey, 'base64url');

  return `${toSign}.${signature}`;
}

function verifyJwt(token, publicKey) {
  if (typeof token !== 'string') throw new Error('Invalid token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed token');

  const [encodedHeader, encodedPayload, signature] = parts;
  const header=JSON.parse(Buffer.from(encodedHeader,'base64url'));
  if(header.alg!=='RS256'||header.crit)throw Error('Invalid JWT algorithm');
  const toSign = `${encodedHeader}.${encodedPayload}`;

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(toSign);
  const valid = verifier.verify(publicKey, signature, 'base64url');
  if (!valid) throw new Error('Invalid signature');

  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(payload.exp)||payload.exp <= now) throw new Error('Token expired');
  if (payload.nbf!==undefined&&(!Number.isFinite(payload.nbf)||payload.nbf > now + 30)) throw new Error('Token not yet valid');

  return payload;
}

// TOTP (RFC 6238)
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input) {
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  const buf = crypto.randomBytes(20);
  return base32Encode(buf);
}

function getTotpCode(secret, timeStep = 30, time = Date.now()) {
  const epoch = Math.floor(time / 1000);
  const counter = Math.floor(epoch / timeStep);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));

  const key = base32Decode(secret);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();

  const offset = hmac[hmac.length - 1] & 0xf;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

function verifyTotp(token, secret) {
  if (!token || !secret) return false;
  const cleanToken = String(token).trim();
  if (!/^\d{6}$/.test(cleanToken)) return false;
  const now = Date.now();
  // Check current window and +/- 1 window (for clock drift)
  for (const delta of [-30000, 0, 30000]) {
    if (getTotpCode(secret, 30, now + delta) === cleanToken) {
      return true;
    }
  }
  return false;
}

function getTotpUri(username, secret, issuer = 'Chitanda') {
  const encUser = encodeURIComponent(username);
  const encIssuer = encodeURIComponent(issuer);
  return `otpauth://totp/${encIssuer}:${encUser}?secret=${secret}&issuer=${encIssuer}&algorithm=SHA1&digits=6&period=30`;
}

module.exports = {
  verifyPasswordHash,
  createPasswordHash,
  ensureKeyPair,
  signJwt,
  verifyJwt,
  generateTotpSecret,
  getTotpCode,
  verifyTotp,
  getTotpUri
};
