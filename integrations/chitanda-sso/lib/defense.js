'use strict';

const crypto = require('node:crypto');
const fs=require('node:fs'),path=require('node:path'),config=require('./config');
const { isIP } = require('node:net');

const AUTH_WINDOW_MS = 10 * 60 * 1000; // 10 minutes tracking window
const AUTH_MAX_IP_FAILURES = 8;        // max 8 failures per IP
const AUTH_MAX_USER_FAILURES = 10;     // max 10 failures per username
const AUTH_LOCK_MS = 15 * 60 * 1000;   // 15 minutes lockout

const ipAttempts = new Map();
const userAttempts = new Map();
const genericRateLimits = new Map();
const usedTotpCodes = new Map();

function sanitizeIp(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  // Strip IPv6-mapped IPv4 prefix if present (::ffff:127.0.0.1)
  const clean = trimmed.startsWith('::ffff:') ? trimmed.slice(7) : trimmed;
  return isIP(clean) ? clean : null;
}

function getClientIp(req) {
  const peer=sanitizeIp(req.socket?.remoteAddress)||'unknown';
  return ['127.0.0.1','::1'].includes(peer)?sanitizeIp(req.headers['x-real-ip'])||peer:peer;
}
const defenseFile=path.join(config.dataDir,'login-defense.json');
try{const value=JSON.parse(fs.readFileSync(defenseFile,'utf8'));for(const [map,entries]of [[ipAttempts,value.ips],[userAttempts,value.users]])for(const [key,v]of (entries||[]).slice(0,4096))if(v&&Number.isFinite(v.firstAttempt)&&Number.isFinite(v.count))map.set(key,v);}catch(e){if(e.code!=='ENOENT')throw e;}
function persist(){fs.mkdirSync(config.dataDir,{recursive:true,mode:0o700});const tmp=defenseFile+'.tmp';fs.writeFileSync(tmp,JSON.stringify({ips:[...ipAttempts],users:[...userAttempts]}),{mode:0o600});fs.renameSync(tmp,defenseFile);}
function bound(map){if(map.size>=4096){const now=Date.now();for(const [k,v]of map)if((v.lockedUntil||0)<now&&now-v.firstAttempt>AUTH_WINDOW_MS)map.delete(k);if(map.size>=4096)throw Object.assign(Error('Rate limit capacity reached'),{status:429});}}

function checkLoginAllowed(ip, username = '') {
  const now = Date.now();

  // 1. Check IP lockout
  const ipRecord = ipAttempts.get(ip);
  if (ipRecord && ipRecord.lockedUntil && ipRecord.lockedUntil > now) {
    const remainingSec = Math.ceil((ipRecord.lockedUntil - now) / 1000);
    return {
      allowed: false,
      reason: `连续登录失败过多，该 IP 已被暂时锁定。请于 ${remainingSec} 秒后重试。`
    };
  }

  // 2. Check Username lockout (anti-distributed brute force)
  if (username) {
    const cleanUser = String(username).toLowerCase().trim();
    const userRecord = userAttempts.get(cleanUser);
    if (userRecord && userRecord.lockedUntil && userRecord.lockedUntil > now) {
      const remainingSec = Math.ceil((userRecord.lockedUntil - now) / 1000);
      return {
        allowed: false,
        reason: `账号被多次尝试登录失败，为保护安全已临时锁定。请于 ${remainingSec} 秒后重试。`
      };
    }
  }

  return { allowed: true };
}

function recordLoginFailure(ip, username = '') {
  const now = Date.now();
  bound(ipAttempts);bound(userAttempts);

  // Record for IP
  let ipRecord = ipAttempts.get(ip);
  if (!ipRecord || now - ipRecord.firstAttempt > AUTH_WINDOW_MS) {
    ipRecord = { count: 1, firstAttempt: now, lockedUntil: null };
  } else {
    ipRecord.count += 1;
    if (ipRecord.count >= AUTH_MAX_IP_FAILURES) {
      ipRecord.lockedUntil = now + AUTH_LOCK_MS;
    }
  }
  ipAttempts.set(ip, ipRecord);

  // Record for Username
  if (username) {
    const cleanUser = String(username).toLowerCase().trim();
    let userRecord = userAttempts.get(cleanUser);
    if (!userRecord || now - userRecord.firstAttempt > AUTH_WINDOW_MS) {
      userRecord = { count: 1, firstAttempt: now, lockedUntil: null };
    } else {
      userRecord.count += 1;
      if (userRecord.count >= AUTH_MAX_USER_FAILURES) {
        userRecord.lockedUntil = now + AUTH_LOCK_MS;
      }
    }
    userAttempts.set(cleanUser, userRecord);
  }
  persist();
}

function recordLoginSuccess(ip, username = '') {
  ipAttempts.delete(ip);
  if (username) {
    const cleanUser = String(username).toLowerCase().trim();
    userAttempts.delete(cleanUser);
  }
  persist();
}

// Generic sliding window rate limiter
function checkRateLimit(key, maxRequests = 20, windowMs = 60 * 1000) {
  const now = Date.now();
  let record = genericRateLimits.get(key);
  if (!record || now - record.windowStart > windowMs) {
    if(genericRateLimits.size>=4096){for(const [k,v]of genericRateLimits)if(now-v.windowStart>300000)genericRateLimits.delete(k);if(genericRateLimits.size>=4096)return {allowed:false,retryAfter:60};}
    genericRateLimits.set(key, { count: 1, windowStart: now });
    return { allowed: true, remaining: maxRequests - 1 };
  }

  record.count += 1;
  if (record.count > maxRequests) {
    const retryAfter = Math.ceil((record.windowStart + windowMs - now) / 1000);
    return { allowed: false, retryAfter };
  }

  return { allowed: true, remaining: maxRequests - record.count };
}

// Prevent TOTP replay attack within the active 30s window
function checkAndRecordTotpCode(userId, code) {
  const key = `${userId}:${code}`;
  const now = Date.now();
  const lastUsed = usedTotpCodes.get(key);
  if (lastUsed && now - lastUsed < 60 * 1000) {
    return false; // Code was already consumed recently
  }
  usedTotpCodes.set(key, now);
  return true;
}

// Periodic cleanup of expired entries
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of ipAttempts.entries()) {
    if (now - record.firstAttempt > AUTH_WINDOW_MS && (!record.lockedUntil || record.lockedUntil <= now)) {
      ipAttempts.delete(ip);
    }
  }
  for (const [user, record] of userAttempts.entries()) {
    if (now - record.firstAttempt > AUTH_WINDOW_MS && (!record.lockedUntil || record.lockedUntil <= now)) {
      userAttempts.delete(user);
    }
  }
  for (const [key, record] of genericRateLimits.entries()) {
    if (now - record.windowStart > 10 * 60 * 1000) {
      genericRateLimits.delete(key);
    }
  }
  for (const [key, time] of usedTotpCodes.entries()) {
    if (now - time > 90 * 1000) {
      usedTotpCodes.delete(key);
    }
  }
}, 3 * 60 * 1000).unref();

module.exports = {
  getClientIp,
  checkLoginAllowed,
  recordLoginFailure,
  recordLoginSuccess,
  checkRateLimit,
  checkAndRecordTotpCode
};
