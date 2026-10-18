"use strict";

const crypto = require("node:crypto");
const net = require("node:net");

const ADMIN_SESSION_COOKIE_NAME = "chitanda_admin_session";
const ADMIN_PASSWORD_HASH_SCHEME = "scrypt";
const ADMIN_PASSWORD_HASH_VERSION = "v1";
const ADMIN_PASSWORD_MIN_LENGTH = 8;
const ADMIN_PASSWORD_MAX_BYTES = 4096;
const ADMIN_USERNAME_MAX_LENGTH = 128;
const DEFAULT_SCRYPT_COST = 32768;
const DEFAULT_SCRYPT_BLOCK_SIZE = 8;
const DEFAULT_SCRYPT_PARALLELIZATION = 1;
const DEFAULT_SCRYPT_KEY_LENGTH = 64;

const normalizeInteger = (value, fallback = 0) => {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.trunc(numeric) : fallback;
};

const readEnvFlag = (value, fallback) => {
  if (value === undefined || value === "") {
    return fallback;
  }
  return /^(1|true|yes|on)$/i.test(String(value));
};

const parseSecretList = (value) =>
  String(value || "")
    .split(/[\n,，]/)
    .map((item) => item.trim())
    .filter(Boolean);

const normalizeUsername = (value) => String(value || "").trim();

const timingSafeTextEqual = (left, right) => {
  const leftBuffer = Buffer.from(String(left || ""), "utf8");
  const rightBuffer = Buffer.from(String(right || ""), "utf8");
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
};

const isPowerOfTwo = (value) => Number.isInteger(value) && value > 1 && (value & (value - 1)) === 0;

const getScryptMaxMemory = (cost, blockSize, parallelization) =>
  Math.max(64 * 1024 * 1024, 128 * cost * blockSize + 128 * blockSize * parallelization + 1024 * 1024);

const parseAdminPasswordHash = (value) => {
  const parts = String(value || "").trim().split("$");
  if (parts.length !== 7 || parts[0] !== ADMIN_PASSWORD_HASH_SCHEME || parts[1] !== ADMIN_PASSWORD_HASH_VERSION) {
    return null;
  }

  const cost = normalizeInteger(parts[2]);
  const blockSize = normalizeInteger(parts[3]);
  const parallelization = normalizeInteger(parts[4]);
  if (
    !isPowerOfTwo(cost) ||
    cost < 16384 ||
    cost > 262144 ||
    blockSize < 1 ||
    blockSize > 32 ||
    parallelization < 1 ||
    parallelization > 8 ||
    !/^[A-Za-z0-9_-]+$/.test(parts[5]) ||
    !/^[A-Za-z0-9_-]+$/.test(parts[6])
  ) {
    return null;
  }

  try {
    const salt = Buffer.from(parts[5], "base64url");
    const digest = Buffer.from(parts[6], "base64url");
    if (salt.length < 16 || salt.length > 64 || digest.length < 32 || digest.length > 128) {
      return null;
    }
    return Object.freeze({
      blockSize,
      cost,
      digest,
      parallelization,
      salt
    });
  } catch {
    return null;
  }
};

const deriveScrypt = (password, record) =>
  new Promise((resolve, reject) => {
    crypto.scrypt(
      String(password || ""),
      record.salt,
      record.digest.length,
      {
        N: record.cost,
        r: record.blockSize,
        p: record.parallelization,
        maxmem: getScryptMaxMemory(record.cost, record.blockSize, record.parallelization)
      },
      (error, derivedKey) => (error ? reject(error) : resolve(derivedKey))
    );
  });

const createAdminPasswordHash = async (password, options = {}) => {
  const normalizedPassword = String(password || "");
  if (normalizedPassword.length < ADMIN_PASSWORD_MIN_LENGTH) {
    throw new Error(`Admin password must contain at least ${ADMIN_PASSWORD_MIN_LENGTH} characters.`);
  }
  if (Buffer.byteLength(normalizedPassword, "utf8") > ADMIN_PASSWORD_MAX_BYTES) {
    throw new Error("Admin password is too long.");
  }

  const record = {
    cost: normalizeInteger(options.cost, DEFAULT_SCRYPT_COST),
    blockSize: normalizeInteger(options.blockSize, DEFAULT_SCRYPT_BLOCK_SIZE),
    parallelization: normalizeInteger(options.parallelization, DEFAULT_SCRYPT_PARALLELIZATION),
    salt: Buffer.isBuffer(options.salt) ? options.salt : crypto.randomBytes(16),
    digest: Buffer.alloc(normalizeInteger(options.keyLength, DEFAULT_SCRYPT_KEY_LENGTH))
  };
  if (
    !isPowerOfTwo(record.cost) ||
    record.cost < 16384 ||
    record.cost > 262144 ||
    record.blockSize < 1 ||
    record.blockSize > 32 ||
    record.parallelization < 1 ||
    record.parallelization > 8 ||
    record.salt.length < 16 ||
    record.salt.length > 64 ||
    record.digest.length < 32 ||
    record.digest.length > 128
  ) {
    throw new Error("Invalid scrypt password-hash parameters.");
  }

  const digest = await deriveScrypt(normalizedPassword, record);
  return [
    ADMIN_PASSWORD_HASH_SCHEME,
    ADMIN_PASSWORD_HASH_VERSION,
    record.cost,
    record.blockSize,
    record.parallelization,
    record.salt.toString("base64url"),
    digest.toString("base64url")
  ].join("$");
};

const verifyAdminPasswordHash = async (password, passwordHash) => {
  const record = typeof passwordHash === "string" ? parseAdminPasswordHash(passwordHash) : passwordHash;
  if (!record) {
    return false;
  }
  const incomingPassword = String(password || "");
  const passwordWithinLimit = Buffer.byteLength(incomingPassword, "utf8") <= ADMIN_PASSWORD_MAX_BYTES;
  const derived = await deriveScrypt(passwordWithinLimit ? incomingPassword : "", record);
  return passwordWithinLimit && derived.length === record.digest.length && crypto.timingSafeEqual(derived, record.digest);
};

const createAdminSessionAuth = (options = {}) => {
  const env = options.env || process.env;
  const now = typeof options.now === "function" ? options.now : Date.now;
  const randomBytes = typeof options.randomBytes === "function" ? options.randomBytes : crypto.randomBytes;
  const adminTokens = parseSecretList(
    env.CHITANDA_ADMIN_TOKENS || env.CHITANDA_ADMIN_TOKEN || env.ADMIN_TOKEN || ""
  );
  const adminUsername = normalizeUsername(env.CHITANDA_ADMIN_USERNAME);
  const rawAdminPasswordHash = String(env.CHITANDA_ADMIN_PASSWORD_HASH || "").trim();
  const passwordConfigurationRequested = Boolean(adminUsername || rawAdminPasswordHash);
  const adminPasswordHash = parseAdminPasswordHash(rawAdminPasswordHash);
  const passwordConfigurationValid = Boolean(
    adminUsername &&
    adminUsername.length <= ADMIN_USERNAME_MAX_LENGTH &&
    adminPasswordHash
  );
  const credentialMode = passwordConfigurationRequested ? "password" : adminTokens.length ? "token" : "none";
  const localFallbackEnabled = readEnvFlag(env.CHITANDA_ADMIN_LOCAL_FALLBACK, false);
  const sessionTtlMs = Math.min(
    Math.max(10 * 60 * 1000, normalizeInteger(env.CHITANDA_ADMIN_SESSION_TTL_MS, 12 * 60 * 60 * 1000)),
    7 * 24 * 60 * 60 * 1000
  );
  const sessionPruneMs = Math.max(
    5 * 60 * 1000,
    normalizeInteger(env.CHITANDA_ADMIN_SESSION_PRUNE_MS, 15 * 60 * 1000)
  );
  const authWindowMs = Math.min(
    Math.max(10000, normalizeInteger(env.CHITANDA_ADMIN_AUTH_WINDOW_MS, 10 * 60 * 1000)),
    60 * 60 * 1000
  );
  const authMaxFailures = Math.min(
    Math.max(3, normalizeInteger(env.CHITANDA_ADMIN_AUTH_MAX_FAILURES, 8)),
    100
  );
  const authLockMs = Math.min(
    Math.max(30000, normalizeInteger(env.CHITANDA_ADMIN_AUTH_LOCK_MS, 15 * 60 * 1000)),
    24 * 60 * 60 * 1000
  );
  const authPruneMs = Math.max(authWindowMs, authLockMs) * 2;
  const trustPrivateProxyHeaders = readEnvFlag(env.CHITANDA_ADMIN_TRUST_PRIVATE_PROXY_HEADERS, false);
  const authFailures = new Map();
  const sessions = new Map();

  const parseCookieHeader = (value) => {
    const result = {};
    String(value || "")
      .split(";")
      .map((item) => item.trim())
      .filter(Boolean)
      .forEach((item) => {
        const index = item.indexOf("=");
        if (index <= 0) {
          return;
        }
        const name = item.slice(0, index).trim();
        const rawValue = item.slice(index + 1).trim();
        if (!name) {
          return;
        }
        try {
          result[name] = decodeURIComponent(rawValue);
        } catch {
          result[name] = rawValue;
        }
      });
    return result;
  };

  const isLoopback = (address) => {
    const normalized = String(address || "").replace(/^::ffff:/, "");
    return normalized === "127.0.0.1" || normalized === "::1" || normalized === "localhost";
  };

  const normalizeClientAddress = (address) =>
    String(address || "").replace(/^::ffff:/, "").trim().toLowerCase();

  const isPrivateAddress = (address) => {
    const normalized = normalizeClientAddress(address);
    if (isLoopback(normalized)) {
      return true;
    }
    if (net.isIP(normalized) !== 4) {
      return false;
    }

    const octets = normalized.split(".").map((part) => Number(part));
    return (
      octets[0] === 10 ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168) ||
      (octets[0] === 169 && octets[1] === 254)
    );
  };

  const isTrustedProxyRequest = (request) => {
    const remoteAddress = request?.socket?.remoteAddress;
    return isLoopback(remoteAddress) || (trustPrivateProxyHeaders && isPrivateAddress(remoteAddress));
  };

  const firstHeaderValue = (value) => {
    if (Array.isArray(value)) {
      return firstHeaderValue(value[0]);
    }
    return typeof value === "string" ? value.split(",")[0].trim() : "";
  };

  const parseForwardedFor = (value) => {
    const text = firstHeaderValue(value);
    if (!text) {
      return "";
    }
    const match = /(?:^|;)\s*for="?(\[?[a-f0-9:.]+\]?|[^";,]+)"?/i.exec(text);
    return normalizeClientAddress(match ? match[1].replace(/^\[|\]$/g, "") : text);
  };

  const getClientAddress = (request) => {
    const remoteAddress = normalizeClientAddress(request.socket.remoteAddress);
    if (!isTrustedProxyRequest(request)) {
      return remoteAddress || "unknown";
    }

    const forwarded =
      firstHeaderValue(request.headers["cf-connecting-ip"]) ||
      firstHeaderValue(request.headers["x-real-ip"]) ||
      firstHeaderValue(request.headers["x-forwarded-for"]) ||
      parseForwardedFor(request.headers.forwarded);
    return normalizeClientAddress(forwarded) || remoteAddress || "unknown";
  };

  const isRequestSecure = (request) => {
    if (request?.socket?.encrypted) {
      return true;
    }
    if (!isTrustedProxyRequest(request)) {
      return false;
    }
    const forwardedProto = firstHeaderValue(request.headers["x-forwarded-proto"]).toLowerCase();
    if (forwardedProto) {
      return forwardedProto === "https" || forwardedProto === "wss";
    }
    const forwarded = firstHeaderValue(request.headers.forwarded).toLowerCase();
    const match = /proto=(https?|wss?)/i.exec(forwarded);
    return Boolean(match && (match[1] === "https" || match[1] === "wss"));
  };

  const getAuthKey = (request) => getClientAddress(request);

  const getAuthRetrySeconds = (state, currentTime = now()) =>
    Math.max(1, Math.ceil(Math.max(0, state.lockedUntil - currentTime) / 1000));

  const pruneAuthFailures = (currentTime = now()) => {
    for (const [key, state] of authFailures) {
      const stale = currentTime - state.lastFailureAt > authPruneMs && state.lockedUntil <= currentTime;
      if (stale) {
        authFailures.delete(key);
      }
    }
  };

  const pruneSessions = (currentTime = now()) => {
    for (const [sessionId, session] of sessions) {
      if (!session || session.expiresAt <= currentTime) {
        sessions.delete(sessionId);
      }
    }
  };

  const getAuthLock = (request, currentTime = now()) => {
    pruneAuthFailures(currentTime);
    const state = authFailures.get(getAuthKey(request));
    if (!state || state.lockedUntil <= currentTime) {
      return null;
    }
    return state;
  };

  const recordAuthFailure = (request, currentTime = now()) => {
    const key = getAuthKey(request);
    const current = authFailures.get(key);
    const state =
      current && currentTime - current.firstFailureAt <= authWindowMs
        ? current
        : { count: 0, firstFailureAt: currentTime, lastFailureAt: currentTime, lockedUntil: 0 };

    state.count += 1;
    state.lastFailureAt = currentTime;
    if (state.count >= authMaxFailures) {
      state.lockedUntil = currentTime + authLockMs;
    }
    authFailures.set(key, state);
    return state;
  };

  const clearAuthFailure = (request) => {
    authFailures.delete(getAuthKey(request));
  };

  const isTokenValid = (token) => {
    if (!adminTokens.length || !token) {
      return false;
    }
    const incoming = Buffer.from(token);
    return adminTokens.some((value) => {
      const expected = Buffer.from(value);
      return incoming.length === expected.length && crypto.timingSafeEqual(incoming, expected);
    });
  };

  const isPasswordLoginValid = async (credentials) => {
    if (!passwordConfigurationValid) {
      return false;
    }
    const username = normalizeUsername(credentials?.username);
    const password = typeof credentials?.password === "string" ? credentials.password : "";
    const usernameValid =
      username.length <= ADMIN_USERNAME_MAX_LENGTH && timingSafeTextEqual(username, adminUsername);
    const passwordValid = await verifyAdminPasswordHash(password, adminPasswordHash);
    return usernameValid && passwordValid;
  };

  const getSessionState = (request, currentTime = now()) => {
    pruneSessions(currentTime);
    const cookies = parseCookieHeader(request.headers.cookie);
    const sessionId = cookies[ADMIN_SESSION_COOKIE_NAME] || "";
    if (!sessionId) {
      return { ok: false, expired: false, sessionId: "" };
    }

    const session = sessions.get(sessionId);
    if (!session) {
      return { ok: false, expired: false, sessionId };
    }
    if (session.expiresAt <= currentTime) {
      sessions.delete(sessionId);
      return { ok: false, expired: true, sessionId };
    }

    session.lastSeenAt = currentTime;
    return {
      ok: true,
      sessionId,
      expiresAt: session.expiresAt,
      createdAt: session.createdAt
    };
  };

  const createSession = (currentTime = now()) => {
    pruneSessions(currentTime);
    const sessionId = randomBytes(32).toString("hex");
    sessions.set(sessionId, {
      createdAt: currentTime,
      expiresAt: currentTime + sessionTtlMs,
      lastSeenAt: currentTime
    });
    return { sessionId, expiresAt: currentTime + sessionTtlMs };
  };

  const deleteRequestSession = (request) => {
    const cookies = parseCookieHeader(request.headers.cookie);
    const sessionId = cookies[ADMIN_SESSION_COOKIE_NAME] || "";
    if (sessionId) {
      sessions.delete(sessionId);
    }
  };

  const buildSessionCookie = (request, sessionId = "", clear = false) => {
    const parts = [`${ADMIN_SESSION_COOKIE_NAME}=${clear ? "" : encodeURIComponent(sessionId)}`];
    parts.push("Path=/");
    parts.push(clear ? "Max-Age=0" : `Max-Age=${Math.floor(sessionTtlMs / 1000)}`);
    parts.push("HttpOnly");
    parts.push("SameSite=Strict");
    if (isRequestSecure(request)) {
      parts.push("Secure");
    }
    if (clear) {
      parts.push("Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    }
    return parts.join("; ");
  };

  const verifyRequest = (request) => {
    const currentTime = now();
    if (credentialMode === "none" && localFallbackEnabled && isLoopback(request.socket.remoteAddress)) {
      return { ok: true, mode: "local" };
    }
    const auth = getSessionState(request, currentTime);
    if (auth.ok) {
      return { ok: true };
    }
    const lock = getAuthLock(request, currentTime);
    if (lock) {
      return {
        ok: false,
        statusCode: 429,
        message: "后台请求过于频繁，请稍后再试",
        retryAfterSeconds: getAuthRetrySeconds(lock, currentTime)
      };
    }
    return {
      ok: false,
      statusCode: 401,
      message: auth.expired ? "后台会话已过期，请重新登录" : "请先登录后台",
      clearSessionCookie: Boolean(auth.sessionId)
    };
  };

  const verifyLogin = async (request, rawCredentials) => {
    const currentTime = now();
    const lock = getAuthLock(request, currentTime);
    if (lock) {
      return {
        ok: false,
        statusCode: 429,
        message: "后台请求过于频繁，请稍后再试",
        retryAfterSeconds: getAuthRetrySeconds(lock, currentTime)
      };
    }

    if (credentialMode === "none") {
      if (localFallbackEnabled && isLoopback(request.socket.remoteAddress)) {
        return { ok: true };
      }
      return {
        ok: false,
        statusCode: 401,
        message: "后台账号未配置"
      };
    }

    if (credentialMode === "password" && !passwordConfigurationValid) {
      return {
        ok: false,
        statusCode: 503,
        message: "后台账号配置不可用"
      };
    }

    const credentials =
      rawCredentials && typeof rawCredentials === "object"
        ? rawCredentials
        : { token: String(rawCredentials || "") };
    const valid =
      credentialMode === "password"
        ? await isPasswordLoginValid(credentials)
        : isTokenValid(String(credentials.token || "").trim());

    if (valid) {
      clearAuthFailure(request);
      return { ok: true };
    }

    const failure = recordAuthFailure(request, currentTime);
    if (failure.lockedUntil > currentTime) {
      return {
        ok: false,
        statusCode: 429,
        message: "后台请求过于频繁，请稍后再试",
        retryAfterSeconds: getAuthRetrySeconds(failure, currentTime)
      };
    }

    return {
      ok: false,
      statusCode: 401,
      message: credentialMode === "password" ? "账号或密码不正确" : "后台令牌不正确"
    };
  };

  return Object.freeze({
    cookieName: ADMIN_SESSION_COOKIE_NAME,
    credentialMode,
    hasConfiguredCredentials: credentialMode === "password" ? passwordConfigurationValid : adminTokens.length > 0,
    hasPasswordCredentials: credentialMode === "password" && passwordConfigurationValid,
    hasConfiguredTokens: adminTokens.length > 0,
    localFallbackEnabled,
    sessionPruneMs,
    sessionTtlMs,
    buildSessionCookie,
    createSession,
    deleteRequestSession,
    getClientAddress,
    getSessionState,
    isRequestSecure,
    verifyLogin,
    verifyRequest
  });
};

module.exports = {
  ADMIN_SESSION_COOKIE_NAME,
  createAdminPasswordHash,
  parseAdminPasswordHash,
  verifyAdminPasswordHash,
  createAdminSessionAuth
};
