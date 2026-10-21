'use strict';

const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const config = require('./config');
const tokenHash=value=>'sha256:'+crypto.createHash('sha256').update(typeof value==='string'?value:'').digest('hex');

class Store {
  constructor(dataDir = config.dataDir) {
    this.dataDir = dataDir;
    fs.mkdirSync(this.dataDir, { recursive: true, mode:0o700 });
    this.dbPath = path.join(this.dataDir, 'sso.sqlite');
    this.db = new DatabaseSync(this.dbPath);
    fs.chmodSync(this.dbPath,0o600);
    this.init();
  }

  init() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;

      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT,
        email TEXT,
        avatar TEXT,
        totp_secret TEXT,
        totp_enabled INTEGER DEFAULT 0,
        roles TEXT DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        ip TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        last_active_at TEXT NOT NULL,
        revoked INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_secret TEXT NOT NULL,
        name TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        allowed_origins TEXT,
        scopes TEXT NOT NULL,
        is_system INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS auth_codes (
        code TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        scope TEXT,
        code_challenge TEXT,
        code_challenge_method TEXT,
        nonce TEXT,
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        scope TEXT,
        expires_at TEXT NOT NULL,
        revoked INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        user_id TEXT,
        username TEXT,
        ip TEXT,
        user_agent TEXT,
        details TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS totp_uses (
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, code_hash)
      );

      CREATE TABLE IF NOT EXISTS ecosystem_apps (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        icon TEXT DEFAULT '🌸',
        icon_bg TEXT DEFAULT '#fbf0f4',
        tag TEXT DEFAULT '全域服务',
        tag_color TEXT DEFAULT '',
        description TEXT,
        footer_text TEXT,
        sort_order INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);

    // Schema migration checks for existing production databases
    try {
      const authCols = this.db.prepare('PRAGMA table_info(auth_codes)').all();
      if (!authCols.some(c => c.name === 'nonce')) {
        this.db.exec('ALTER TABLE auth_codes ADD COLUMN nonce TEXT');
      }
    } catch {}

    for(const table of ['auth_codes','refresh_tokens']){
      const columns=this.db.prepare('PRAGMA table_info('+table+')').all();
      if(!columns.some(c=>c.name==='session_id'))this.db.exec('ALTER TABLE '+table+' ADD COLUMN session_id TEXT');
    }
    for(const [table,column,prefix] of [['auth_codes','code','code_'],['refresh_tokens','token','rft_']])for(const row of this.db.prepare('SELECT '+column+' AS value FROM '+table+' WHERE '+column+' LIKE ?').all(prefix+'%'))this.db.prepare('UPDATE '+table+' SET '+column+'=? WHERE '+column+'=?').run(tokenHash(row.value),row.value);
    this.seedDefaults();
  }

  seedDefaults() {
    // 1. Seed default admin if not exists
    const existingAdmin = this.getUserByUsername(config.adminUsername);
    const now = new Date().toISOString();
    if (!existingAdmin && this.db.prepare('SELECT COUNT(*) AS n FROM users').get().n===0) {
      if(!config.adminUsername||!config.adminPasswordHash)throw Error('Initial administrator credentials must be configured');
      const adminId = 'usr_' + crypto.randomBytes(8).toString('hex');
      const stmt = this.db.prepare(`
        INSERT INTO users (id, username, password_hash, display_name, email, avatar, totp_enabled, roles, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
      `);
      stmt.run(
        adminId,
        config.adminUsername,
        config.adminPasswordHash,
        '千反田爱瑠',
        'admin@chitanda.net',
        '/favicon.png',
        JSON.stringify(['admin', 'root']),
        now,
        now
      );
      this.logAudit('USER_INIT', adminId, config.adminUsername, '127.0.0.1', 'System', 'Initial admin account initialized');
    }

    // 2. Seed system OAuth clients
    const clients = [
      {
        id: 'moegallery',
        secret: 'sec_' + crypto.randomBytes(32).toString('hex'),
        name: 'MoeGallery 媒体库',
        redirectUris: [
          'https://anime.chitanda.net/api/v1/auth/callback',
          'https://anime.chitanda.net/callback',
          'http://127.0.0.1:8111/callback'
        ],
        allowedOrigins: ['https://anime.chitanda.net', 'http://127.0.0.1:8111'],
        scopes: 'openid profile email library:read library:write library:manage'
      },
      {
        id: 'data-platform',
        secret: 'sec_' + crypto.randomBytes(32).toString('hex'),
        name: 'Chitanda 数据中台',
        redirectUris: [
          'https://datahub.chitanda.net/tunnel/sso/callback'
        ],
        allowedOrigins: ['https://datahub.chitanda.net'],
        scopes: 'openid profile tunnel:admin'
      },
      {
        id: 'chitanda-home',
        secret: 'sec_' + crypto.randomBytes(32).toString('hex'),
        name: 'Chitanda 主站后台',
        redirectUris: [
          'https://www.chitanda.net/admin/callback',
          'https://chitanda.net/admin/callback',
          'http://127.0.0.1:5081/admin/callback'
        ],
        allowedOrigins: ['https://www.chitanda.net', 'https://chitanda.net', 'http://127.0.0.1:5081'],
        scopes: 'openid profile admin'
      }
    ];

    for (const c of clients) {
      const existing = this.getOAuthClient(c.id);
      if (!existing) {
        const stmt = this.db.prepare(`
          INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uris, allowed_origins, scopes, is_system, created_at)
          VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        `);
        stmt.run(c.id, c.secret, c.name, JSON.stringify(c.redirectUris), JSON.stringify(c.allowedOrigins), c.scopes, now);
      }
    }

    // 3. Seed default ecosystem apps if empty
    const appCountRow = this.db.prepare('SELECT COUNT(*) as count FROM ecosystem_apps').get();
    if (!appCountRow || appCountRow.count === 0) {
      const defaultApps = [
        {
          id: 'app_chitanda_home',
          name: 'Chitanda Home',
          url: 'https://www.chitanda.net',
          icon: '🌸',
          icon_bg: '#fbf0f4',
          tag: '主站门户',
          tag_color: '',
          description: '官方静态站点与个人展示中心，支持中英双语与 Bangumi 追番数据联动。',
          footer_text: 'www.chitanda.net',
          sort_order: 1
        },
        {
          id: 'app_moegallery',
          name: 'MoeGallery',
          url: 'https://anime.chitanda.net',
          icon: '🎨',
          icon_bg: '#f1f0fb',
          tag: '媒体库',
          tag_color: 'purple',
          description: '自建二次元动漫图集与媒体库系统，内置流媒体检索、图片优化及 REST API。',
          footer_text: 'anime.chitanda.net',
          sort_order: 2
        },
        {
          id: 'app_data_platform',
          name: '数据中台管理',
          url: 'https://datahub.chitanda.net/tunnel/',
          icon: '⚡',
          icon_bg: '#fbf5e8',
          tag: '数据通道',
          tag_color: 'amber',
          description: '跨境私有协议隧道管控中心，多跳优化节点转发、流量监控与智能拓扑调度。',
          footer_text: 'datahub.chitanda.net',
          sort_order: 3
        },
        {
          id: 'app_dns_manager',
          name: 'DNS 管理系统',
          url: 'https://dns.chitanda.net',
          icon: '🌐',
          icon_bg: '#eaf1f7',
          tag: 'DNS 调度',
          tag_color: '',
          description: '全域权威域名智能解析系统，支持华为云/Cloudflare 双线分区与自动容灾。',
          footer_text: 'dns.chitanda.net',
          sort_order: 4
        },
        {
          id: 'app_status_monitor',
          name: '服务状态监控',
          url: 'https://status.chitanda.net',
          icon: '📊',
          icon_bg: '#eef7ee',
          tag: '监控探测',
          tag_color: '',
          description: '境内外各节点延迟、实时可用性看板与网络链路质量持续观测。',
          footer_text: 'status.chitanda.net',
          sort_order: 5
        },
        {
          id: 'app_deeplx',
          name: 'DeepLX 翻译引擎',
          url: 'https://deeplx.chitanda.net',
          icon: '📝',
          icon_bg: '#f5eff9',
          tag: '自动化工具',
          tag_color: 'purple',
          description: '高性能多语种文本自动化翻译接口，为主站与媒体库内容提供即时本地化支持。',
          footer_text: 'deeplx.chitanda.net',
          sort_order: 6
        },
        {
          id: 'app_ip_lookup',
          name: 'IP 地理查询',
          url: 'https://ip.chitanda.net',
          icon: '🔍',
          icon_bg: '#edf2f8',
          tag: '节点定位',
          tag_color: '',
          description: '精准回应客户端公网 IPv4/IPv6 与出口运营商归属，辅助网络调优测试。',
          footer_text: 'ip.chitanda.net',
          sort_order: 7
        }
      ];

      const appStmt = this.db.prepare(`
        INSERT INTO ecosystem_apps (id, name, url, icon, icon_bg, tag, tag_color, description, footer_text, sort_order, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const a of defaultApps) {
        appStmt.run(a.id, a.name, a.url, a.icon, a.icon_bg, a.tag, a.tag_color, a.description, a.footer_text, a.sort_order, now, now);
      }
    }
  }

  // User management
  getUserById(id) {
    return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  }

  getUserByUsername(username) {
    return this.db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  }

  updateUserPassword(id, newHash) {
    const now = new Date().toISOString();
    return this.db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').run(newHash, now, id);
  }

  updateUserProfile(id, displayName, email, avatar) {
    const now = new Date().toISOString();
    return this.db.prepare('UPDATE users SET display_name = ?, email = ?, avatar = ?, updated_at = ? WHERE id = ?')
      .run(displayName, email, avatar, now, id);
  }

  setTotpSecret(id, secret) {
    const now = new Date().toISOString();
    return this.db.prepare('UPDATE users SET totp_secret = ?, updated_at = ? WHERE id = ?').run(secret, now, id);
  }

  enableTotp(id) {
    const now = new Date().toISOString();
    return this.db.prepare('UPDATE users SET totp_enabled = 1, updated_at = ? WHERE id = ?').run(now, id);
  }

  disableTotp(id) {
    const now = new Date().toISOString();
    return this.db.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL, updated_at = ? WHERE id = ?').run(now, id);
  }

  // Session management
  consumeTotp(userId, secret, code, now = Date.now()) {
    // Keep all accepted codes for the entire +/- one-step validity window,
    // including across service restarts. Never store the six-digit code itself.
    this.db.prepare('DELETE FROM totp_uses WHERE expires_at <= ?').run(now);
    const result=this.db.prepare('INSERT OR IGNORE INTO totp_uses (user_id, code_hash, expires_at) VALUES (?, ?, ?)')
      .run(userId, tokenHash(secret+':'+code), now+90000);
    return result.changes===1;
  }

  createSession(userId, token, ip, userAgent, ttlMs = config.sessionTtlMs) {
    const id = 'ses_' + crypto.randomBytes(12).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlMs).toISOString();
    const nowStr = now.toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, ip, user_agent, created_at, expires_at, last_active_at, revoked)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
    `);
    stmt.run(id, userId, tokenHash, ip, userAgent, nowStr, expiresAt, nowStr);
    return { id, token, expiresAt };
  }

  findSessionByToken(token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const session = this.db.prepare(`
      SELECT s.*, u.username, u.display_name, u.email, u.avatar, u.roles, u.totp_enabled
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ? AND s.revoked = 0
    `).get(tokenHash);

    if (!session) return null;

    const now = new Date().toISOString();
    if (session.expires_at < now) {
      this.revokeSession(session.id);
      return null;
    }

    // Touch last active
    this.db.prepare('UPDATE sessions SET last_active_at = ? WHERE id = ?').run(now, session.id);
    return session;
  }

  listSessionsForUser(userId) {
    return this.db.prepare(`
      SELECT id, ip, user_agent, created_at, expires_at, last_active_at, revoked
      FROM sessions
      WHERE user_id = ? AND revoked = 0 AND expires_at > ?
      ORDER BY last_active_at DESC
    `).all(userId, new Date().toISOString());
  }

  revokeSession(sessionId, userId = null) {
    if (userId) {
      return this.db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ? AND user_id = ?').run(sessionId, userId);
    }
    return this.db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(sessionId);
  }

  revokeAllSessionsForUser(userId, exceptSessionId = null) {
    if (exceptSessionId) {
      return this.db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ?').run(userId, exceptSessionId);
    }
    return this.db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ?').run(userId);
  }

  activeSession(id,userId){
    if(typeof id!=='string'||typeof userId!=='string')return false;
    return !!this.db.prepare('SELECT 1 FROM sessions WHERE id=? AND user_id=? AND revoked=0 AND expires_at>?').get(id,userId,new Date().toISOString());
  }
  activeTokenSession(payload){return this.activeSession(payload.sid,payload.sub);}

  // OAuth Clients
  getOAuthClient(clientId) {
    const row = this.db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(clientId);
    if (!row) return null;
    return {
      ...row,
      redirect_uris: JSON.parse(row.redirect_uris || '[]'),
      allowed_origins: JSON.parse(row.allowed_origins || '[]')
    };
  }

  listOAuthClients() {
    return this.db.prepare('SELECT client_id, name, redirect_uris, allowed_origins, scopes, is_system, created_at FROM oauth_clients')
      .all()
      .map(r => ({
        ...r,
        redirect_uris: JSON.parse(r.redirect_uris || '[]'),
        allowed_origins: JSON.parse(r.allowed_origins || '[]')
      }));
  }

  createOAuthClient(name, redirectUris, scopes = 'openid profile') {
    const clientId = 'cli_' + crypto.randomBytes(8).toString('hex');
    const clientSecret = 'sec_' + crypto.randomBytes(24).toString('hex');
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uris, allowed_origins, scopes, is_system, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?)
    `).run(clientId, clientSecret, name, JSON.stringify(redirectUris), JSON.stringify([]), scopes, now);
    return { clientId, clientSecret, name, redirectUris, scopes };
  }

  deleteOAuthClient(clientId) {
    return this.db.prepare('DELETE FROM oauth_clients WHERE client_id = ? AND is_system = 0').run(clientId);
  }

  // Auth Codes (OIDC & PKCE)
  createAuthCode(clientId, userId, redirectUri, scope, codeChallenge, codeChallengeMethod, nonce = null, sessionId = null) {
    const code = 'code_' + crypto.randomBytes(24).toString('base64url');
    const expiresAt = new Date(Date.now() + config.authCodeTtlSec * 1000).toISOString();
    this.db.prepare(`
      INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at, session_id, used)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).run(tokenHash(code), clientId, userId, redirectUri, scope, codeChallenge || null, codeChallengeMethod || null, nonce || null, expiresAt, sessionId);
    return code;
  }

  getAuthCode(code){return this.db.prepare('SELECT * FROM auth_codes WHERE code = ?').get(tokenHash(code));}

  consumeAuthCode(code) {
    const row = this.getAuthCode(code);
    if (!row) return null;
    if (row.used === 1) {
      // Auth code replay detected!
      return { replay: true, ...row };
    }
    if (row.expires_at < new Date().toISOString()) return null;
    this.db.prepare('UPDATE auth_codes SET used = 1 WHERE code = ?').run(tokenHash(code));
    return row;
  }

  // Refresh Tokens
  createRefreshToken(clientId, userId, scope, sessionId=null) {
    const token = 'rft_' + crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + config.refreshTokenTtlSec * 1000).toISOString();
    this.db.prepare(`
      INSERT INTO refresh_tokens (token, client_id, user_id, scope, expires_at, session_id, revoked)
      VALUES (?, ?, ?, ?, ?, ?, 0)
    `).run(tokenHash(token), clientId, userId, scope, expiresAt, sessionId);
    return token;
  }

  getRefreshToken(token){return this.db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(tokenHash(token));}

  consumeRefreshToken(token) {
    const row = this.getRefreshToken(token);
    if (!row) return null;
    if (row.revoked === 1) {
      // Refresh token replay detected!
      return { replay: true, ...row };
    }
    if (row.expires_at < new Date().toISOString()) return null;
    // Single-use token rotation: revoke consumed token immediately
    this.db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?').run(tokenHash(token));
    return row;
  }

  revokeRefreshToken(token,clientId) {
    return this.db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ? AND client_id = ?').run(tokenHash(token),clientId);
  }

  // Audit Logs
  logAudit(event, userId, username, ip, userAgent, details) {
    const now = new Date().toISOString();
    const strDetails = typeof details === 'object' ? JSON.stringify(details) : String(details || '');
    this.db.prepare(`
      INSERT INTO audit_logs (event, user_id, username, ip, user_agent, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(event, userId || null, username || null, ip || null, userAgent || null, strDetails, now);
  }

  listAuditLogs(limit = 50) {
    return this.db.prepare(`
      SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?
    `).all(limit);
  }

  // Ecosystem Apps Management
  listEcosystemApps() {
    return this.db.prepare('SELECT * FROM ecosystem_apps ORDER BY sort_order ASC, created_at ASC').all();
  }

  getEcosystemApp(id) {
    return this.db.prepare('SELECT * FROM ecosystem_apps WHERE id = ?').get(id);
  }

  createEcosystemApp({ name, url, icon, icon_bg, tag, tag_color, description, footer_text }) {
    const id = 'app_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    const maxRow = this.db.prepare('SELECT MAX(sort_order) as max_sort FROM ecosystem_apps').get();
    const sort_order = ((maxRow && maxRow.max_sort) || 0) + 1;
    this.db.prepare(`
      INSERT INTO ecosystem_apps (id, name, url, icon, icon_bg, tag, tag_color, description, footer_text, sort_order, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      name,
      url,
      icon || '🌸',
      icon_bg || '#f1e9f4',
      tag || '全域服务',
      tag_color || '',
      description || '',
      footer_text || '',
      sort_order,
      now,
      now
    );
    return this.getEcosystemApp(id);
  }

  updateEcosystemApp(id, { name, url, icon, icon_bg, tag, tag_color, description, footer_text, sort_order }) {
    const now = new Date().toISOString();
    const existing = this.getEcosystemApp(id);
    if (!existing) return null;
    this.db.prepare(`
      UPDATE ecosystem_apps
      SET name = ?, url = ?, icon = ?, icon_bg = ?, tag = ?, tag_color = ?, description = ?, footer_text = ?,
          sort_order = COALESCE(?, sort_order), updated_at = ?
      WHERE id = ?
    `).run(
      name !== undefined ? name : existing.name,
      url !== undefined ? url : existing.url,
      icon !== undefined ? icon : existing.icon,
      icon_bg !== undefined ? icon_bg : existing.icon_bg,
      tag !== undefined ? tag : existing.tag,
      tag_color !== undefined ? tag_color : existing.tag_color,
      description !== undefined ? description : existing.description,
      footer_text !== undefined ? footer_text : existing.footer_text,
      sort_order !== undefined ? sort_order : existing.sort_order,
      now,
      id
    );
    return this.getEcosystemApp(id);
  }

  deleteEcosystemApp(id) {
    return this.db.prepare('DELETE FROM ecosystem_apps WHERE id = ?').run(id);
  }

  reorderEcosystemApps(appIds = []) {
    if (!Array.isArray(appIds)) return;
    const stmt = this.db.prepare('UPDATE ecosystem_apps SET sort_order = ? WHERE id = ?');
    for (let i = 0; i < appIds.length; i++) {
      stmt.run(i + 1, String(appIds[i]));
    }
  }
}

module.exports = Store;
