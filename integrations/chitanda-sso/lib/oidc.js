'use strict';

const crypto = require('node:crypto');
const config = require('./config');
const auth = require('./auth');

function getDiscoveryConfiguration() {
  return {
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/oauth/authorize`,
    token_endpoint: `${config.issuer}/oauth/token`,
    userinfo_endpoint: `${config.issuer}/oauth/userinfo`,
    jwks_uri: `${config.issuer}/.well-known/jwks.json`,
    revocation_endpoint: `${config.issuer}/oauth/revoke`,
    introspection_endpoint: `${config.issuer}/oauth/introspect`,
    end_session_endpoint: `${config.issuer}/oauth/logout`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'roles'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'preferred_username', 'email', 'avatar', 'picture', 'roles', 'nonce'],
    code_challenge_methods_supported: ['S256'],
    claims_parameter_supported: false,
    request_parameter_supported: false
  };
}

function verifyPkce(codeVerifier, codeChallenge, codeChallengeMethod) {
  if (!codeChallenge) return false;
  if (typeof codeVerifier!=='string'||!/^[-._~a-zA-Z0-9]{43,128}$/.test(codeVerifier)) return false;
  if (codeChallengeMethod === 'S256') {
    const computed = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return computed === codeChallenge;
  }
  return false;
}

const parseRoles = require('./security').roles;

function createTokensForUser({ user, client, scope, keyPair, nonce, sessionId }) {
  const roles = parseRoles(user.roles);
  const now = Math.floor(Date.now() / 1000);

  const tokenPayload = {
    iss: config.issuer,
    sub: user.id,
    sid: sessionId,
    aud: client ? client.client_id : config.issuer,
    username: user.username,
    display_name: user.display_name,
    name: user.display_name,
    email: user.email,
    avatar: user.avatar,
    picture: user.avatar || '/favicon.png',
    roles,
    scope: scope || 'openid profile'
  };

  const accessToken = auth.signJwt(
    {
      ...tokenPayload,
      token_use: 'access'
    },
    keyPair.privateKey,
    keyPair.kid,
    config.accessTokenTtlSec
  );

  const idTokenPayload = {
    ...tokenPayload,
    token_use: 'id',
    preferred_username: user.username,
    name: user.display_name
  };
  if (nonce) {
    idTokenPayload.nonce = nonce;
  }

  const idToken = auth.signJwt(
    idTokenPayload,
    keyPair.privateKey,
    keyPair.kid,
    config.accessTokenTtlSec
  );

  return {
    access_token: accessToken,
    id_token: idToken,
    token_type: 'Bearer',
    expires_in: config.accessTokenTtlSec,
    scope: scope || 'openid profile'
  };
}

function createM2MAccessToken({ client, scope, keyPair }) {
  const payload = {
    iss: config.issuer,
    sub: client.client_id,
    aud: client.client_id,
    client_id: client.client_id,
    scope: scope || 'openid',
    token_use: 'access',
    roles: ['service']
  };

  return auth.signJwt(
    payload,
    keyPair.privateKey,
    keyPair.kid,
    config.accessTokenTtlSec
  );
}

function getUserInfoClaims(user) {
  const roles = parseRoles(user.roles);
  return {
    sub: user.id,
    preferred_username: user.username,
    name: user.display_name,
    email: user.email,
    avatar: user.avatar,
    picture: user.avatar || '/favicon.png',
    roles,
    email_verified: false
  };
}

module.exports = {
  getDiscoveryConfiguration,
  verifyPkce,
  createTokensForUser,
  createM2MAccessToken,
  getUserInfoClaims
};
