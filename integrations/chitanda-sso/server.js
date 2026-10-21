'use strict';
process.umask(0o077);

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const QRCode=require('qrcode');

const config = require('./lib/config');
const auth = require('./lib/auth');
const Store = require('./lib/store');
const defense = require('./lib/defense');
const oidc = require('./lib/oidc');
const security = require('./lib/security');
const guard = require('./lib/request-guard')();

const store = new Store();
const keyPair = auth.ensureKeyPair(config.dataDir);
const sourceAccess=process.env.SSO_ACCESS_MODE?require('./lib/source-access')({CT_ACCESS_MODE:process.env.SSO_ACCESS_MODE,CT_BLOCKED_SUBNETS:process.env.SSO_BLOCKED_SUBNETS,CT_SOURCE_EXCEPTIONS:process.env.SSO_SOURCE_EXCEPTIONS}):{permits:()=>true};

const PUBLIC_DIR = path.resolve(__dirname, 'public');

function parseCookies(cookieHeader) {
  const cookies = Object.create(null);
  if (!cookieHeader) return cookies;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    try { if (Object.hasOwn(cookies,name)) return {}; cookies[name] = decodeURIComponent(val); } catch { return {}; }
  }
  return cookies;
}

function serializeCookie(name, val, options = {}) {
  let cookie = `${name}=${encodeURIComponent(val)}`;
  if (options.maxAge !== undefined) cookie += `; Max-Age=${options.maxAge}`;
  if (options.domain) cookie += `; Domain=${options.domain}`;
  if (options.path) cookie += `; Path=${options.path}`;
  if (options.httpOnly) cookie += `; HttpOnly`;
  if (options.secure) cookie += `; Secure`;
  if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
  return cookie;
}

function jsonResponse(res, status, data, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(JSON.stringify(data));
}

function textResponse(res, status, text, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(text);
}

const parseRoles = security.roles;

function isAdmin(session) {
  if (!session) return false;
  const roles = parseRoles(session.roles);
  return roles.includes('admin') || roles.includes('root');
}

function safeTimingCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function sanitizeClientScopes(requestedScope, clientAllowedScopes) {
  const allowed = new Set((clientAllowedScopes || '').split(/\s+/).filter(Boolean));
  const requested = (requestedScope || 'openid profile').split(/\s+/).filter(Boolean);
  const granted = requested.filter(s => allowed.has(s));
  if (!granted.includes('openid') && allowed.has('openid')) {
    granted.unshift('openid');
  }
  return granted.length > 0 ? granted.join(' ') : 'openid';
}

const isAllowedRedirectUri = security.exactRedirect;
const getSafeLogoutRedirect = value => security.safeLogout(value, config.issuer, store.listOAuthClients());

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = ''; let size=0;
    req.on('data', chunk => {
      size+=chunk.length; body += chunk;
      if (size > 65536) {
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if(req.browserSession&&!store.activeSession(req.browserSession.id,req.browserSession.user_id))return reject(Object.assign(Error('Session revoked'),{status:401}));
      const contentType = req.headers['content-type'] || '';
      if (contentType.includes('application/json')) {
        try {
          const value=body?JSON.parse(body):{}; if(!value||typeof value!=='object'||Array.isArray(value))throw Error(); resolve(value);
        } catch {
          reject(Object.assign(Error('Invalid JSON'),{status:400}));
        }
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        const parsed = {};
        const params = new URLSearchParams(body);
        for (const [k, v] of params.entries()) {
          parsed[k] = v;
        }
        resolve(parsed);
      } else {
        resolve({ raw: body });
      }
    });
    req.on('error', reject);
  });
}

function getSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[config.cookieName];
  if (token) {
    const session = store.findSessionByToken(token);
    if (session) { req.browserSession=session;return session; }
  }

  // Fallback to Bearer token
  const authHeader = req.headers.authorization || '';
  if (['/oauth/userinfo','/api/sso/verify'].includes(new URL(req.url,'http://localhost').pathname) && authHeader.startsWith('Bearer ')) {
    const bearer = authHeader.slice(7).trim();
    try {
      const payload = auth.verifyJwt(bearer, keyPair.publicKey);
      if (payload && payload.sub && payload.token_use === 'access' && payload.iss === config.issuer && store.getOAuthClient(payload.aud) && store.activeTokenSession(payload)) {
        const user = store.getUserById(payload.sub);
        if (user) {
          return {
            user_id: user.id,
            username: user.username,
            display_name: user.display_name,
            email: user.email,
            avatar: user.avatar,
            roles: user.roles,
            totp_enabled: user.totp_enabled,
            isJwt: true
          };
        }
      }
    } catch {
      // not a valid JWT
    }
  }

  return null;
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
  '.json': 'application/json'
};

function serveStatic(req, res, pathname) {
  let relativePath = pathname === '/' ? '/index.html' : pathname;
  if (relativePath === '/portal') relativePath = '/portal.html';
  if (relativePath === '/login') relativePath = '/index.html';

  const filePath = path.resolve(PUBLIC_DIR, '.' + relativePath);
  if (!filePath.startsWith(PUBLIC_DIR + path.sep) || !fs.existsSync(filePath)) {
    return false;
  }

  const stat = fs.statSync(filePath);
  if (stat.isDirectory()) return false;

  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  res.writeHead(200, {
    'Content-Type': contentType,
    'Content-Length': stat.size,
    'Cache-Control': (ext === '.html' || ext === '.css' || ext === '.js') ? 'no-cache, no-store, must-revalidate' : 'public, max-age=86400',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN'
  });
  fs.createReadStream(filePath).pipe(res);
  return true;
}

const server = http.createServer(async (req, res) => {
  const ip = defense.getClientIp(req);
  if(!sourceAccess.permits(ip))return jsonResponse(res,403,{error:'source_forbidden'});
  const userAgent = req.headers['user-agent'] || '';
  let parsedUrl; try { parsedUrl = new URL(req.url, config.issuer); } catch { return jsonResponse(res,400,{error:'invalid_request'}); }
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();

  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  try {
    guard.begin(req,res,'all:'+ip,{limit:600,concurrent:16});
    const publicMetadata=pathname.startsWith('/.well-known/');
    if(publicMetadata)res.setHeader('Access-Control-Allow-Origin','*');
    if(method==='OPTIONS'){res.writeHead(204);return res.end();}
    const unsafe=!['GET','HEAD','OPTIONS'].includes(method);
    if(unsafe && (pathname.startsWith('/api/') || pathname.startsWith('/oauth/'))){
      if(req.headers['sec-fetch-site']==='cross-site'||(req.headers.origin&&req.headers.origin!==config.issuer))return jsonResponse(res,403,{error:'invalid_origin'});
      if(parseCookies(req.headers.cookie)[config.cookieName] && req.headers.origin!==config.issuer)return jsonResponse(res,403,{error:'origin_required'});
    }
    if(pathname==='/api/auth/login'||pathname==='/api/auth/change-password'||pathname==='/api/auth/totp/disable')guard.begin(req,res,'password',{limit:1000,concurrent:2});
    // 1. OIDC Discovery
    if (pathname === '/.well-known/openid-configuration' && method === 'GET') {
      return jsonResponse(res, 200, oidc.getDiscoveryConfiguration());
    }

    // 2. JWKS Public Keys
    if (pathname === '/.well-known/jwks.json' && method === 'GET') {
      return jsonResponse(res, 200, keyPair.jwks);
    }

    // 3. OAuth Authorize Endpoint
    if (pathname === '/oauth/authorize' && method === 'GET') {
      const authRl = defense.checkRateLimit(`auth:${ip}`, 60, 60 * 1000);
      if (!authRl.allowed) {
        return textResponse(res, 429, 'Rate limit exceeded, retry later');
      }

      const clientId = parsedUrl.searchParams.get('client_id');
      const redirectUri = parsedUrl.searchParams.get('redirect_uri');
      const responseType = parsedUrl.searchParams.get('response_type') || 'code';
      if(responseType!=='code')return jsonResponse(res,400,{error:'unsupported_response_type'});
      const rawScope = parsedUrl.searchParams.get('scope') || 'openid profile';
      const state = parsedUrl.searchParams.get('state') || '';
      const nonce = parsedUrl.searchParams.get('nonce') || '';
      const codeChallenge = parsedUrl.searchParams.get('code_challenge');
      const codeChallengeMethod = parsedUrl.searchParams.get('code_challenge_method');

      const client = clientId ? store.getOAuthClient(clientId) : null;
      if (!client) {
        return textResponse(res, 400, 'Invalid client_id');
      }

      // Strict redirect_uri validation against client whitelist (prevent open redirect / code stealing)
      if (!redirectUri || !isAllowedRedirectUri(redirectUri, client.redirect_uris)) {
        store.logAudit('OIDC_AUTHORIZE_REJECTED', null, null, ip, userAgent, {
          clientId,
          invalidRedirectUri: redirectUri
        });
        return textResponse(res, 400, 'Invalid redirect_uri: URI is not registered in client whitelist');
      }

      if((codeChallenge && (codeChallengeMethod!=='S256'||!/^[-_a-zA-Z0-9]{43}$/.test(codeChallenge)))||(!client.client_secret&&!codeChallenge))return jsonResponse(res,400,{error:'invalid_request',error_description:'PKCE S256 required'});
      // Enforce scope bounding to client's registered scopes (prevent privilege escalation)
      const scope = sanitizeClientScopes(rawScope, client.scopes);

      const session = getSessionFromRequest(req);
      if (session) {
        // User already has SSO session! Issue authorization code immediately
        const code = store.createAuthCode(clientId, session.user_id, redirectUri, scope, codeChallenge, codeChallengeMethod, nonce, session.id);
        store.logAudit('OIDC_AUTHORIZE_SUCCESS', session.user_id, session.username, ip, userAgent, {
          clientId,
          redirectUri,
          scope,
          hasNonce: Boolean(nonce)
        });

        const target = new URL(redirectUri);
        target.searchParams.set('code', code);
        if (state) target.searchParams.set('state', state);

        res.writeHead(302, { Location: target.toString() });
        return res.end();
      }

      // Not logged in -> redirect to login with query params preserved
      const loginUrl = new URL('/login', config.issuer);
      for (const [k, v] of parsedUrl.searchParams.entries()) {
        loginUrl.searchParams.set(k, v);
      }
      res.writeHead(302, { Location: loginUrl.toString() });
      return res.end();
    }

    // 4. OAuth Token Endpoint
    if (pathname === '/oauth/token' && method === 'POST') {
      // Rate limit token issuance (defense against brute forcing auth codes or client secrets)
      const tokenRl = defense.checkRateLimit(`token:${ip}`, 60, 60 * 1000);
      if (!tokenRl.allowed) {
        return jsonResponse(res, 429, { error: 'slow_down', error_description: 'Rate limit exceeded, retry later' });
      }

      const body = await parseBody(req);
      const grantType = body.grant_type;
      let clientId = body.client_id;
      let clientSecret = body.client_secret;

      // Check Basic auth header
      const authHeader = req.headers.authorization || '';
      if (authHeader.startsWith('Basic ')) {
        const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
        const cut = decoded.indexOf(':'); const u = decoded.slice(0,cut), p = decoded.slice(cut+1);
        clientId = u;
        clientSecret = p;
      }

      if (grantType === 'authorization_code') {
        const code = body.code;
        const redirectUri = body.redirect_uri;
        const codeVerifier = body.code_verifier;

        const authCode = store.getAuthCode(code);
        if (!authCode) {
          return jsonResponse(res, 400, { error: 'invalid_grant', error_description: 'Code is invalid or expired' });
        }

        // RFC 6749 Section 4.1.2: Code Replay Defense
        if (authCode.used === 1) {
          store.logAudit('SECURITY_ALERT_CODE_REPLAY', authCode.user_id, null, ip, userAgent, {
            codePrefix: String(code).slice(0, 10),
            clientId: authCode.client_id
          });
          return jsonResponse(res, 400, {
            error: 'invalid_grant',
            error_description: 'Authorization code has already been consumed (replay detected)'
          });
        }

        // RFC 6749 Section 4.1.3: Verify redirect_uri matches initial authorize request if provided
        if (typeof redirectUri!=='string'||redirectUri !== authCode.redirect_uri) {
          return jsonResponse(res, 400, {
            error: 'invalid_grant',
            error_description: 'redirect_uri does not match original authorization request'
          });
        }

        const client = store.getOAuthClient(authCode.client_id);
        if (!client || clientId!==authCode.client_id) {
          return jsonResponse(res, 401, { error: 'invalid_client' });
        }

        // Verify confidential client secret using timing-safe comparison
        if (client.client_secret) {
          if (!safeTimingCompare(client.client_secret, clientSecret)) {
            store.logAudit('SECURITY_ALERT_CLIENT_AUTH_FAILED', null, null, ip, userAgent, { clientId: client.client_id });
            return jsonResponse(res, 401, { error: 'invalid_client', error_description: 'Client authentication failed' });
          }
        }

        // Verify PKCE code verifier if code challenge was used during authorization
        if (authCode.code_challenge) {
          if (!oidc.verifyPkce(codeVerifier, authCode.code_challenge, authCode.code_challenge_method)) {
            store.logAudit('SECURITY_ALERT_PKCE_FAILED', authCode.user_id, null, ip, userAgent, { clientId: client.client_id });
            return jsonResponse(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
          }
        } else if (!client.client_secret) {
          // Public client without secret MUST have used PKCE
          return jsonResponse(res, 400, {
            error: 'invalid_request',
            error_description: 'Public clients must use PKCE with code_challenge'
          });
        }

        if(!store.activeSession(authCode.session_id,authCode.user_id)||!store.consumeAuthCode(code)||authCode.expires_at<=new Date().toISOString())return jsonResponse(res,400,{error:'invalid_grant'});
        const user = store.getUserById(authCode.user_id);
        if (!user) {
          return jsonResponse(res, 400, { error: 'invalid_grant', error_description: 'User not found' });
        }

        const tokens = oidc.createTokensForUser({ user, client, scope: authCode.scope, keyPair, nonce: authCode.nonce, sessionId: authCode.session_id });
        const refreshToken = store.createRefreshToken(client.client_id, user.id, authCode.scope, authCode.session_id);

        store.logAudit('OIDC_TOKEN_ISSUED', user.id, user.username, ip, userAgent, {
          clientId: client.client_id,
          grantType
        });

        return jsonResponse(res, 200, {
          ...tokens,
          refresh_token: refreshToken
        });
      } else if (grantType === 'refresh_token') {
        const refreshToken = body.refresh_token;
        if (!refreshToken) {
          return jsonResponse(res, 400, { error: 'invalid_request', error_description: 'Missing refresh_token' });
        }

        const record = store.getRefreshToken(refreshToken);
        if (!record) {
          return jsonResponse(res, 400, { error: 'invalid_grant', error_description: 'Refresh token invalid or expired' });
        }

        if (record.revoked === 1) {
          store.revokeSession(record.session_id,record.user_id);
          store.logAudit('SECURITY_ALERT_REFRESH_TOKEN_REPLAY', record.user_id, null, ip, userAgent, {
            clientId: record.client_id,
            tokenPrefix: String(refreshToken).slice(0, 10)
          });
          return jsonResponse(res, 400, {
            error: 'invalid_grant',
            error_description: 'Refresh token has already been consumed (replay detected)'
          });
        }

        const client = store.getOAuthClient(record.client_id);
        if (!client || clientId!==record.client_id) {
          return jsonResponse(res, 400, { error: 'invalid_client' });
        }

        // RFC 6749 Section 6: Client Authentication for refresh token grant
        if (client.client_secret) {
          if (!safeTimingCompare(client.client_secret, clientSecret)) {
            return jsonResponse(res, 401, { error: 'invalid_client', error_description: 'Client authentication failed' });
          }
        }

        if(!store.activeSession(record.session_id,record.user_id)||record.expires_at<=new Date().toISOString()||!store.consumeRefreshToken(refreshToken))return jsonResponse(res,400,{error:'invalid_grant'});
        const user = store.getUserById(record.user_id);
        if (!user) {
          return jsonResponse(res, 400, { error: 'invalid_grant', error_description: 'User not found' });
        }

        // Refresh Token Rotation (RTR): issue fresh access token, id token, and a fresh refresh token
        const tokens = oidc.createTokensForUser({ user, client, scope: record.scope, keyPair, sessionId: record.session_id });
        const newRefreshToken = store.createRefreshToken(client.client_id, user.id, record.scope, record.session_id);

        store.logAudit('OIDC_TOKEN_REFRESHED', user.id, user.username, ip, userAgent, { clientId: client.client_id });

        return jsonResponse(res, 200, {
          ...tokens,
          refresh_token: newRefreshToken
        });
      } else if (grantType === 'client_credentials') {
        // Machine-to-Machine (M2M) grant for backend services / daemons
        if (!clientId || !clientSecret) {
          return jsonResponse(res, 401, { error: 'invalid_client', error_description: 'Client credentials required' });
        }

        const client = store.getOAuthClient(clientId);
        if (!client || !safeTimingCompare(client.client_secret, clientSecret)) {
          store.logAudit('SECURITY_ALERT_M2M_AUTH_FAILED', null, null, ip, userAgent, { clientId });
          return jsonResponse(res, 401, { error: 'invalid_client', error_description: 'Client authentication failed' });
        }

        const grantedScope = sanitizeClientScopes(body.scope, client.scopes);
        const m2mAccessToken = oidc.createM2MAccessToken({ client, scope: grantedScope, keyPair });

        store.logAudit('OIDC_M2M_TOKEN_ISSUED', null, client.client_id, ip, userAgent, {
          clientId: client.client_id,
          scope: grantedScope
        });

        return jsonResponse(res, 200, {
          access_token: m2mAccessToken,
          token_type: 'Bearer',
          expires_in: config.accessTokenTtlSec,
          scope: grantedScope
        });
      } else {
        return jsonResponse(res, 400, { error: 'unsupported_grant_type' });
      }
    }

    // 5. UserInfo Endpoint (OIDC Core 1.0)
    if (pathname === '/oauth/userinfo' && (method === 'GET' || method === 'POST')) {
      const session = getSessionFromRequest(req);
      if (!session) {
        return jsonResponse(res, 401, { error: 'unauthorized', error_description: 'Valid bearer token or session required' }, {
          'WWW-Authenticate': 'Bearer error="invalid_token"'
        });
      }
      const user = store.getUserById(session.user_id);
      if (!user) {
        return jsonResponse(res, 404, { error: 'user_not_found' });
      }
      return jsonResponse(res, 200, oidc.getUserInfoClaims(user));
    }

    // 6. Introspection Endpoint (RFC 7662)
    if (pathname === '/oauth/introspect' && method === 'POST') {
      const rl = defense.checkRateLimit(`introspect:${ip}`, 300, 60 * 1000);
      if (!rl.allowed) {
        return jsonResponse(res, 429, { error: 'slow_down', error_description: 'Rate limit exceeded, retry later' });
      }

      const body = await parseBody(req);
      const token = body.token;

      let clientId=body.client_id,clientSecret=body.client_secret;
      const ah=req.headers.authorization||'';
      if(ah.startsWith('Basic ')){const v=Buffer.from(ah.slice(6),'base64').toString(),cut=v.indexOf(':');clientId=v.slice(0,cut);clientSecret=v.slice(cut+1);}
      const caller=typeof clientId==='string'?store.getOAuthClient(clientId):null;
      if(!caller||!caller.client_secret||!safeTimingCompare(caller.client_secret,clientSecret))return jsonResponse(res,401,{error:'invalid_client'});
      // Check opaque refresh token first if applicable
      if (typeof token === 'string' && token.startsWith('rft_')) {
        const rf = store.getRefreshToken(token);
        if (rf && rf.client_id===clientId && rf.revoked === 0 && rf.expires_at > new Date().toISOString() && store.activeSession(rf.session_id,rf.user_id)) {
          return jsonResponse(res, 200, {
            active: true,
            scope: rf.scope,
            client_id: rf.client_id,
            sub: rf.user_id,
            token_type: 'refresh_token'
          });
        }
        return jsonResponse(res, 200, { active: false });
      }

      try {
        const payload = auth.verifyJwt(token, keyPair.publicKey);
        // Verify user still exists
        const user = store.getUserById(payload.sub);
        if (payload.iss!==config.issuer||payload.aud!==clientId||payload.token_use!=='access'||(!user&&!payload.client_id)||(user&&!store.activeTokenSession(payload))) {
          return jsonResponse(res, 200, { active: false });
        }
        return jsonResponse(res, 200, {
          active: true,
          scope: payload.scope || 'openid profile',
          client_id: payload.aud,
          sub: payload.sub,
          exp: payload.exp,
          username: user?.username||payload.username,
          name:user?.display_name||payload.name, roles:user?parseRoles(user.roles):['service'], sid:payload.sid
        });
      } catch {
        return jsonResponse(res, 200, { active: false });
      }
    }

    // 7. RFC 7009 OAuth Token Revocation Endpoint
    if (pathname === '/oauth/revoke' && method === 'POST') {
      const rl = defense.checkRateLimit(`revoke:${ip}`, 60, 60 * 1000);
      if (!rl.allowed) {
        return jsonResponse(res, 429, { error: 'slow_down', error_description: 'Rate limit exceeded, retry later' });
      }

      const body = await parseBody(req);
      const token = body.token;
      const tokenTypeHint = body.token_type_hint;

      let clientId=body.client_id,clientSecret=body.client_secret;
      const ah=req.headers.authorization||'';
      if(ah.startsWith('Basic ')){const v=Buffer.from(ah.slice(6),'base64').toString(),cut=v.indexOf(':');clientId=v.slice(0,cut);clientSecret=v.slice(cut+1);}
      const caller=typeof clientId==='string'?store.getOAuthClient(clientId):null;
      if(!caller||!caller.client_secret||!safeTimingCompare(caller.client_secret,clientSecret))return jsonResponse(res,401,{error:'invalid_client'});
      if(typeof token==='string')store.revokeRefreshToken(token,clientId);
      // RFC 7009 specifies returning HTTP 200 on revocation
      return jsonResponse(res, 200, { ok: true });
    }

    // 7.1 OIDC End Session / Logout Endpoint (RP-Initiated Logout)
    if ((pathname === '/oauth/logout' || pathname === '/oauth/end_session') && (method === 'GET' || method === 'POST')) {
      const cookies = parseCookies(req.headers.cookie);
      const token = cookies[config.cookieName];
      if (token) {
        const session = store.findSessionByToken(token);
        if (session) {
          store.revokeSession(session.id);
          store.logAudit('LOGOUT', session.user_id, session.username, ip, userAgent, 'Logged out via logout endpoint');
        }
      }

      const rawRedirect = parsedUrl.searchParams.get('post_logout_redirect_uri') || parsedUrl.searchParams.get('redirect_uri');
      const safeRedirect = getSafeLogoutRedirect(rawRedirect);

      const clearCookie = serializeCookie(config.cookieName, '', {
        domain: config.cookieDomain,
        path: '/',
        httpOnly: true,
        secure: true,
        maxAge: 0,
        sameSite: 'Lax'
      });

      res.writeHead(302, {
        'Set-Cookie': clearCookie,
        Location: safeRedirect
      });
      return res.end();
    }

    // 8. API Verify Endpoint (for Nginx auth_request & microservices)
    if (pathname === '/api/sso/verify' && method === 'GET') {
      const session = getSessionFromRequest(req);
      if (!session) {
        return textResponse(res, 401, 'Unauthorized');
      }
      const roles = parseRoles(session.roles);
      return textResponse(res, 200, 'OK', {
        'X-User-Id': session.user_id,
        'X-User-Name': session.username,
        'X-User-Display': encodeURIComponent(session.display_name || ''),
        'X-User-Email': encodeURIComponent(session.email || ''),
        'X-User-Roles': roles.join(',')
      });
    }

    // 9. API Auth Login (Dual-Dimension Defense & TOTP Replay Protection)
    if (pathname === '/api/auth/login' && method === 'POST') {
      const connRl = defense.checkRateLimit(`login_conn:${ip}`, 30, 60 * 1000);
      if (!connRl.allowed) {
        return jsonResponse(res, 429, { ok: false, error: '登录请求过于频繁，请稍后再试' });
      }

      const body = await parseBody(req);
      if(typeof body.username!=='string'||typeof body.password!=='string'||body.username.length>128||Buffer.byteLength(body.password)>4096)return jsonResponse(res,400,{error:'invalid_request'});
      const username = body.username.trim();
      const password = body.password;
      const totpCode = body.totp_code ? String(body.totp_code).trim() : null;

      const defenseCheck = defense.checkLoginAllowed(ip, username);
      if (!defenseCheck.allowed) {
        return jsonResponse(res, 429, { ok: false, error: defenseCheck.reason });
      }

      if (!username || !password) {
        return jsonResponse(res, 400, { ok: false, error: '请输入管理员账号与密码' });
      }

      const user = store.getUserByUsername(username);
      if (!user) {
        defense.recordLoginFailure(ip, username);
        store.logAudit('LOGIN_FAILED', null, username, ip, userAgent, 'Username not found');
        return jsonResponse(res, 401, { ok: false, error: '账号或密码错误' });
      }

      const validPassword = await auth.verifyPasswordHash(password, user.password_hash);
      if (!validPassword) {
        defense.recordLoginFailure(ip, username);
        store.logAudit('LOGIN_FAILED', user.id, username, ip, userAgent, 'Invalid password');
        return jsonResponse(res, 401, { ok: false, error: '账号或密码错误' });
      }

      if(!store.getUserById(user.id)||store.getUserById(user.id).password_hash!==user.password_hash)return jsonResponse(res,401,{error:'credentials_changed'});
      // Check TOTP
      if (user.totp_enabled && user.totp_secret) {
        if (!totpCode) {
          return jsonResponse(res, 200, {
            ok: false,
            require_totp: true,
            message: '该账号已启用两步验证，请输入动态口令'
          });
        }
        const validTotp = auth.verifyTotp(totpCode, user.totp_secret);
        if (!validTotp) {
          defense.recordLoginFailure(ip, username);
          store.logAudit('LOGIN_FAILED_TOTP', user.id, username, ip, userAgent, 'Invalid TOTP code');
          return jsonResponse(res, 401, { ok: false, error: '动态验证码错误或已过期' });
        }
        // TOTP replay protection
        const notReplayed = defense.checkAndRecordTotpCode(user.id, totpCode);
        if (!notReplayed) {
          return jsonResponse(res, 401, { ok: false, error: '动态验证码已被使用，请等待 30 秒轮换后输入新口令' });
        }
      }

      // Login success: reset failure tracking for this IP and username
      defense.recordLoginSuccess(ip, username);
      const sessionToken = crypto.randomBytes(32).toString('base64url');
      const session = store.createSession(user.id, sessionToken, ip, userAgent);

      store.logAudit('LOGIN_SUCCESS', user.id, username, ip, userAgent, 'Successfully logged in');

      // Set cross-domain root cookie
      const cookie = serializeCookie(config.cookieName, sessionToken, {
        domain: config.cookieDomain,
        path: '/',
        httpOnly: true,
        secure: true,
        maxAge: Math.floor(config.sessionTtlMs / 1000),
        sameSite: 'Lax'
      });

      return jsonResponse(res, 200, {
        ok: true,
        user: {
          id: user.id,
          username: user.username,
          displayName: user.display_name,
          email: user.email,
          avatar: user.avatar,
          roles: parseRoles(user.roles)
        }
      }, {
        'Set-Cookie': cookie
      });
    }

    // 10. API Auth Me
    if (pathname === '/api/auth/me' && method === 'GET') {
      const session = getSessionFromRequest(req);
      if (!session) {
        return jsonResponse(res, 401, { ok: false, error: '未登录' });
      }
      return jsonResponse(res, 200, {
        ok: true,
        user: {
          id: session.user_id,
          username: session.username,
          displayName: session.display_name,
          email: session.email,
          avatar: session.avatar,
          roles: parseRoles(session.roles),
          totpEnabled: Boolean(session.totp_enabled)
        }
      });
    }

    // 11. API Password Change
    if (pathname === '/api/auth/change-password' && method === 'POST') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });

      // Rate limit password change attempts (defense against session abuse / brute force)
      const rl = defense.checkRateLimit(`pwd:${session.user_id}`, 5, 5 * 60 * 1000);
      if (!rl.allowed) {
        return jsonResponse(res, 429, { ok: false, error: `修改密码尝试过于频繁，请于 ${rl.retryAfter} 秒后再试` });
      }

      const body = await parseBody(req);
      const oldPassword = String(body.old_password || '');
      const newPassword = String(body.new_password || '');

      if (newPassword.length < 8) {
        return jsonResponse(res, 400, { ok: false, error: '新密码长度不得少于 8 位' });
      }

      const user = store.getUserById(session.user_id);
      const oldValid = await auth.verifyPasswordHash(oldPassword, user.password_hash);
      if (!oldValid) {
        store.logAudit('PASSWORD_CHANGE_FAILED', user.id, user.username, ip, userAgent, 'Old password verification failed');
        return jsonResponse(res, 400, { ok: false, error: '当前旧密码输入错误' });
      }

      const newHash = await auth.createPasswordHash(newPassword);
      if(!store.activeSession(session.id,user.id))return jsonResponse(res,401,{error:'session_revoked'});
      store.updateUserPassword(user.id, newHash);

      // Rotate session: revoke ALL existing sessions for user (including the stale one)
      store.revokeAllSessionsForUser(user.id);

      // Create a brand-new session token and record
      const newSessionToken = crypto.randomBytes(32).toString('base64url');
      store.createSession(user.id, newSessionToken, ip, userAgent);

      store.logAudit('PASSWORD_CHANGED', user.id, user.username, ip, userAgent, 'Password changed successfully; all prior sessions rotated');

      // Issue rotated cookie
      const rotatedCookie = serializeCookie(config.cookieName, newSessionToken, {
        domain: config.cookieDomain,
        path: '/',
        httpOnly: true,
        secure: true,
        maxAge: Math.floor(config.sessionTtlMs / 1000),
        sameSite: 'Lax'
      });

      return jsonResponse(res, 200, { ok: true, message: '密码修改成功，所有历史会话已安全轮换' }, {
        'Set-Cookie': rotatedCookie
      });
    }

    // 12. API Profile Update
    if (pathname === '/api/auth/profile' && method === 'POST') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });

      const body = await parseBody(req);
      const displayName = String(body.display_name || '').trim();
      const email = String(body.email || '').trim();
      const avatar = String(body.avatar || '').trim();

      store.updateUserProfile(session.user_id, displayName, email, avatar);
      store.logAudit('PROFILE_UPDATED', session.user_id, session.username, ip, userAgent, { displayName, email });

      return jsonResponse(res, 200, { ok: true, message: '个人信息更新成功' });
    }

    // 13. API Sessions List & Revoke
    if (pathname === '/api/auth/sessions' && method === 'GET') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });

      const sessions = store.listSessionsForUser(session.user_id);
      return jsonResponse(res, 200, {
        ok: true,
        currentSessionId: session.id,
        sessions
      });
    }

    if (pathname.startsWith('/api/auth/sessions/') && method === 'DELETE') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });

      const sessionId = pathname.slice('/api/auth/sessions/'.length);
      // Strictly scope revocation to current user's session (prevent IDOR)
      store.revokeSession(sessionId, session.user_id);
      store.logAudit('SESSION_REVOKED', session.user_id, session.username, ip, userAgent, { sessionId });

      return jsonResponse(res, 200, { ok: true, message: '该会话已注销' });
    }

    // 14. API TOTP Setup & Verification
    if (pathname === '/api/auth/totp/setup' && method === 'POST') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });

      const current=store.getUserById(session.user_id);
      if(current.totp_enabled)return jsonResponse(res,409,{error:'请先验证并关闭现有两步验证'});
      const secret = auth.generateTotpSecret();
      guard.begin(req,res,'mfa-setup:'+session.user_id,{limit:10,concurrent:1});
      const uri = auth.getTotpUri(session.username, secret, 'Chitanda');

      const qrSvg=await QRCode.toString(uri,{type:'svg',width:180,margin:1});
      if(!store.activeSession(session.id,session.user_id))return jsonResponse(res,401,{error:'session_revoked'});
      store.setTotpSecret(session.user_id,secret);
      return jsonResponse(res, 200, {
        ok: true,
        secret,
        qrSvg,
        uri
      });
    }

    if (pathname === '/api/auth/totp/verify' && method === 'POST') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });

      // Rate limit TOTP verification attempts
      const rl = defense.checkRateLimit(`totp_verify:${session.user_id}`, 5, 5 * 60 * 1000);
      if (!rl.allowed) {
        return jsonResponse(res, 429, { ok: false, error: `验证码尝试过于频繁，请于 ${rl.retryAfter} 秒后再试` });
      }

      const body = await parseBody(req);
      const code = String(body.code || '').trim();
      const user = store.getUserById(session.user_id);

      if (!user.totp_secret) {
        return jsonResponse(res, 400, { ok: false, error: '尚未生成两步验证密钥，请重新发起' });
      }

      const valid = auth.verifyTotp(code, user.totp_secret);
      if (!valid) {
        return jsonResponse(res, 400, { ok: false, error: '两步验证码错误，请核对手机时间后重试' });
      }

      // Check replay
      const notReplayed = defense.checkAndRecordTotpCode(session.user_id, code);
      if (!notReplayed) {
        return jsonResponse(res, 400, { ok: false, error: '该动态验证码已被使用，请等待 30 秒轮换后输入新口令' });
      }

      store.enableTotp(session.user_id);
      store.logAudit('TOTP_ENABLED', session.user_id, session.username, ip, userAgent, 'TOTP 2FA enabled');

      return jsonResponse(res, 200, { ok: true, message: '两步验证已成功启用！' });
    }

    if (pathname === '/api/auth/totp/disable' && method === 'POST') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });

      const body = await parseBody(req);
      const quota=defense.checkRateLimit('mfa-disable:'+session.user_id,5,300000);if(!quota.allowed)return jsonResponse(res,429,{error:'操作过于频繁，请稍后重试'},{'Retry-After':String(quota.retryAfter)});
      const password = String(body.password || '');
      const user = store.getUserById(session.user_id);

      const validPass = await auth.verifyPasswordHash(password, user.password_hash);
      if (!validPass) {
        return jsonResponse(res, 400, { ok: false, error: '登录密码验证失败，无法关闭两步验证' });
      }

      store.disableTotp(session.user_id);
      store.logAudit('TOTP_DISABLED', session.user_id, session.username, ip, userAgent, 'TOTP 2FA disabled');

      return jsonResponse(res, 200, { ok: true, message: '两步验证已关闭' });
    }

    // 15. API OAuth Clients management (Protected by Admin Role)
    if (pathname === '/api/clients' && method === 'GET') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });
      if (!isAdmin(session)) {
        return jsonResponse(res, 403, { ok: false, error: '无权操作：该功能仅管理员可访问' });
      }
      const clients = store.listOAuthClients();
      return jsonResponse(res, 200, { ok: true, clients });
    }

    if (pathname === '/api/clients' && method === 'POST') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });
      if (!isAdmin(session)) {
        return jsonResponse(res, 403, { ok: false, error: '无权操作：该功能仅管理员可访问' });
      }

      const body = await parseBody(req);
      const name = String(body.name || '').trim();
      const rawUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [body.redirect_uri];
      const scopes = String(body.scopes || 'openid profile').trim();

      if (!name || name.length > 64) {
        return jsonResponse(res, 400, { ok: false, error: '应用名称不能为空且长度不得超过 64 字符' });
      }

      const validatedUris = [];
      for (const u of rawUris) {
        if (!u || typeof u !== 'string') continue;
        try {
          const parsed = new URL(u.trim());
          if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') continue;
          if (parsed.hash) continue;
          validatedUris.push(parsed.toString());
        } catch {}
      }

      if (!validatedUris.length) {
        return jsonResponse(res, 400, { ok: false, error: '回调地址无效，必须包含至少一个合法的 http:// 或 https:// 地址且不能包含 hash 片段' });
      }

      const client = store.createOAuthClient(name, validatedUris, scopes);
      store.logAudit('OAUTH_CLIENT_CREATED', session.user_id, session.username, ip, userAgent, { clientId: client.clientId, name });

      return jsonResponse(res, 200, { ok: true, client });
    }

    if (pathname.startsWith('/api/clients/') && method === 'DELETE') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });
      if (!isAdmin(session)) {
        return jsonResponse(res, 403, { ok: false, error: '无权操作：该功能仅管理员可访问' });
      }

      const clientId = pathname.slice('/api/clients/'.length);
      store.deleteOAuthClient(clientId);
      store.logAudit('OAUTH_CLIENT_DELETED', session.user_id, session.username, ip, userAgent, { clientId });

      return jsonResponse(res, 200, { ok: true, message: '应用已删除' });
    }

    // 16. API Audit logs (Protected by Admin Role)
    if (pathname === '/api/audit-logs' && method === 'GET') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });
      if (!isAdmin(session)) {
        return jsonResponse(res, 403, { ok: false, error: '无权操作：该功能仅管理员可访问' });
      }

      const logs = store.listAuditLogs(50);
      return jsonResponse(res, 200, { ok: true, logs });
    }

    // 17. API Ecosystem Apps Management (CRUD & Reorder)
    if (pathname === '/api/apps' && method === 'GET') {
      const apps = store.listEcosystemApps();
      return jsonResponse(res, 200, { ok: true, apps });
    }

    if (pathname === '/api/apps' && method === 'POST') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });
      if (!isAdmin(session)) {
        return jsonResponse(res, 403, { ok: false, error: '无权操作：该功能仅管理员可访问' });
      }

      const body = await parseBody(req);
      const name = String(body.name || '').trim();
      const url = String(body.url || '').trim();
      const icon = String(body.icon || '🌸').trim();
      const iconBg = String(body.icon_bg || '#f1e9f4').trim();
      const tag = String(body.tag || '全域服务').trim();
      const tagColor = String(body.tag_color || '').trim();
      const description = String(body.description || '').trim();
      const footerText = String(body.footer_text || '').trim();

      if (!name || !url) {
        return jsonResponse(res, 400, { ok: false, error: '应用名称与访问链接不能为空' });
      }

      try {
        if(!security.safeAppUrl(url))throw Error('Invalid URL');
      } catch {
        return jsonResponse(res, 400, { ok: false, error: '访问链接必须是合法的 URL 地址' });
      }

      const app = store.createEcosystemApp({
        name,
        url,
        icon,
        icon_bg: iconBg,
        tag,
        tag_color: tagColor,
        description,
        footer_text: footerText
      });

      store.logAudit('ECOSYSTEM_APP_CREATED', session.user_id, session.username, ip, userAgent, { appId: app.id, name });
      return jsonResponse(res, 200, { ok: true, app });
    }

    if (pathname === '/api/apps/reorder' && method === 'PUT') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });
      if (!isAdmin(session)) {
        return jsonResponse(res, 403, { ok: false, error: '无权操作：该功能仅管理员可访问' });
      }

      const body = await parseBody(req);
      const appIds = Array.isArray(body.app_ids) ? body.app_ids : [];
      if (!appIds.length) {
        return jsonResponse(res, 400, { ok: false, error: '排序应用列表不能为空' });
      }

      store.reorderEcosystemApps(appIds);
      store.logAudit('ECOSYSTEM_APPS_REORDERED', session.user_id, session.username, ip, userAgent, { count: appIds.length });
      return jsonResponse(res, 200, { ok: true, message: '应用排序已更新' });
    }

    if (pathname.startsWith('/api/apps/') && method === 'PUT') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });
      if (!isAdmin(session)) {
        return jsonResponse(res, 403, { ok: false, error: '无权操作：该功能仅管理员可访问' });
      }

      const appId = pathname.slice('/api/apps/'.length);
      const body = await parseBody(req);

      if (body.url !== undefined) {
        try { if(!security.safeAppUrl(body.url))throw Error('Invalid URL'); } catch {
          return jsonResponse(res, 400, { ok: false, error: '访问链接必须是合法的 URL 地址' });
        }
      }

      const updated = store.updateEcosystemApp(appId, {
        name: body.name !== undefined ? String(body.name).trim() : undefined,
        url: body.url !== undefined ? String(body.url).trim() : undefined,
        icon: body.icon !== undefined ? String(body.icon).trim() : undefined,
        icon_bg: body.icon_bg !== undefined ? String(body.icon_bg).trim() : undefined,
        tag: body.tag !== undefined ? String(body.tag).trim() : undefined,
        tag_color: body.tag_color !== undefined ? String(body.tag_color).trim() : undefined,
        description: body.description !== undefined ? String(body.description).trim() : undefined,
        footer_text: body.footer_text !== undefined ? String(body.footer_text).trim() : undefined
      });

      if (!updated) {
        return jsonResponse(res, 404, { ok: false, error: '应用不存在' });
      }

      store.logAudit('ECOSYSTEM_APP_UPDATED', session.user_id, session.username, ip, userAgent, { appId });
      return jsonResponse(res, 200, { ok: true, app: updated });
    }

    if (pathname.startsWith('/api/apps/') && method === 'DELETE') {
      const session = getSessionFromRequest(req);
      if (!session) return jsonResponse(res, 401, { ok: false, error: '未登录' });
      if (!isAdmin(session)) {
        return jsonResponse(res, 403, { ok: false, error: '无权操作：该功能仅管理员可访问' });
      }

      const appId = pathname.slice('/api/apps/'.length);
      store.deleteEcosystemApp(appId);
      store.logAudit('ECOSYSTEM_APP_DELETED', session.user_id, session.username, ip, userAgent, { appId });
      return jsonResponse(res, 200, { ok: true, message: '应用已删除' });
    }

    // 18. Serve Static Frontend Files
    if(!['GET','HEAD'].includes(method))return jsonResponse(res,405,{error:'method_not_allowed'});
    const served = serveStatic(req, res, pathname);
    if (served) return;

    // 404 Not Found
    return jsonResponse(res, 404, { error: 'Not Found' });

  } catch (err) {
    console.error('SSO request rejected:',err.status||500);
    if(!res.headersSent&&!res.destroyed)return jsonResponse(res,err.status||500,{error:err.status?err.message:'Internal Server Error'},err.retryAfter?{'Retry-After':String(err.retryAfter)}:{});
  }
});

server.requestTimeout=15000;server.headersTimeout=10000;server.maxRequestsPerSocket=100;

function start() {
  server.listen(config.port, config.host, () => {
    console.log(`[Chitanda SSO] Service listening on http://${config.host}:${config.port}`);
    console.log(`[Chitanda SSO] Public Issuer: ${config.issuer}`);
    console.log(`[Chitanda SSO] Root Cookie Domain: ${config.cookieDomain}`);
  });
}

if (require.main === module) {
  start();
}

module.exports = { server, start, store };
