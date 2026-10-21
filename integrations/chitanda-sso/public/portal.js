'use strict';

// Compact Pure JavaScript QR Code Generator for TOTP
const QRCodeGenerator={createQrSvg:()=>'<p>请在验证器中手动添加下方密钥，密钥仅保留在本站。</p>'};

document.addEventListener('DOMContentLoaded', async () => {
  document.addEventListener('click',event=>{const b=event.target.closest('[data-revoke-session],[data-delete-client]');if(b?.dataset.revokeSession)window.revokeSession(b.dataset.revokeSession);if(b?.dataset.deleteClient)window.deleteClient(b.dataset.deleteClient);});
  let currentUser = null;

  // 1. Live Clock
  function updateClock() {
    const el = document.getElementById('live-clock');
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleTimeString('zh-CN', { hour12: false });
  }
  setInterval(updateClock, 1000);
  updateClock();

  // 2. Load User Profile
  async function loadMe() {
    try {
      const res = await fetch('/api/auth/me');
      if (!res.ok) {
        window.location.href = '/login';
        return null;
      }
      const data = await res.json();
      if (!data.ok || !data.user) {
        window.location.href = '/login';
        return null;
      }
      currentUser = data.user;
      document.getElementById('sidebar-username').textContent = currentUser.displayName || currentUser.username;
      document.getElementById('sidebar-role').textContent = (currentUser.roles || []).join(', ') || 'Administrator';

      const badge = document.getElementById('totp-status-badge');
      const btnEnable = document.getElementById('btn-enable-totp');
      const btnDisable = document.getElementById('btn-disable-totp');
      if (currentUser.totpEnabled) {
        badge.className = 'tag';
        badge.innerHTML = '<span class="status-dot"></span>已启用';
        btnEnable.style.display = 'none';
        btnDisable.style.display = 'inline-flex';
      } else {
        badge.className = 'tag offline';
        badge.textContent = '未启用';
        btnEnable.style.display = 'inline-flex';
        btnDisable.style.display = 'none';
      }
      loadAsideData();
      return currentUser;
    } catch {
      window.location.href = '/login';
      return null;
    }
  }

  // 2.1 Update Aside Profile, Telemetry & Security Stream
  async function loadAsideData() {
    if (!currentUser) return;

    // Aside profile
    const asideAvatar = document.getElementById('aside-avatar');
    if (asideAvatar) {
      asideAvatar.textContent = (currentUser.displayName || currentUser.username || '千').slice(0, 1);
    }
    const asideDisplay = document.getElementById('aside-displayname');
    if (asideDisplay) {
      asideDisplay.textContent = currentUser.displayName || '千反田爱瑠';
    }
    const asideUsername = document.getElementById('aside-username');
    if (asideUsername) {
      asideUsername.textContent = `UID: ${currentUser.username}`;
    }
    const asideRoles = document.getElementById('aside-roles');
    if (asideRoles) {
      asideRoles.textContent = (currentUser.roles || ['admin']).join(', ');
    }
    const asideTotpBadge = document.getElementById('aside-totp-badge');
    if (asideTotpBadge) {
      if (currentUser.totpEnabled) {
        asideTotpBadge.className = 'tag';
        asideTotpBadge.innerHTML = '<span class="status-dot"></span>已启用';
      } else {
        asideTotpBadge.className = 'tag offline';
        asideTotpBadge.textContent = '未启用';
      }
    }

    // Load active sessions count for ribbon
    try {
      const sessRes = await fetch('/api/auth/sessions');
      const sessData = await sessRes.json();
      if (sessRes.ok && sessData.ok && sessData.sessions) {
        const el = document.getElementById('metric-sessions-count');
        if (el) el.textContent = `${sessData.sessions.length} 个活跃`;
      }
    } catch {}

    // Load client count for ribbon
    try {
      const cliRes = await fetch('/api/clients');
      const cliData = await cliRes.json();
      if (cliRes.ok && cliData.ok && cliData.clients) {
        const el = document.getElementById('metric-clients-count');
        if (el) el.textContent = `${cliData.clients.length} 个应用`;
      }
    } catch {}

      // Count ecosystem apps
      const appsEl = document.getElementById('metric-apps-count');
      if (appsEl && Array.isArray(cachedApps) && cachedApps.length) {
        appsEl.textContent = `${cachedApps.length} 个应用`;
      }

    // Load recent security feed into aside
    try {
      const auditRes = await fetch('/api/audit-logs');
      const auditData = await auditRes.json();
      const feedContainer = document.getElementById('aside-live-feed');
      if (auditRes.ok && auditData.ok && auditData.logs && feedContainer) {
        const topLogs = auditData.logs.slice(0, 4);
        if (topLogs.length === 0) {
          feedContainer.innerHTML = '<div style="text-align:center; color:#a494ab; font-size:12px; padding:10px 0;">暂无安全事件</div>';
        } else {
          feedContainer.innerHTML = '';
          topLogs.forEach(l => {
            const item = document.createElement('div');
            item.className = 'feed-item';
            item.innerHTML = `
              <div class="feed-item-top">
                <span class="feed-event">${escapeHtml(l.event)}</span>
                <span class="feed-time">${formatShortTime(l.created_at)}</span>
              </div>
              <div class="feed-details" title="${escapeHtml(l.details || '')}">
                <span>${escapeHtml(l.ip || '127.0.0.1')}</span> · <span>${escapeHtml(l.details || '系统正常流转')}</span>
              </div>
            `;
            feedContainer.appendChild(item);
          });
        }
      }
    } catch {}
  }

  function formatShortTime(isoStr) {
    if (!isoStr) return '';
    try {
      const d = new Date(isoStr);
      const hours = String(d.getHours()).padStart(2, '0');
      const mins = String(d.getMinutes()).padStart(2, '0');
      const secs = String(d.getSeconds()).padStart(2, '0');
      return `${hours}:${mins}:${secs}`;
    } catch {
      return isoStr;
    }
  }

  // Copy Cookie Button
  const btnCopyCookie = document.getElementById('aside-btn-copy-cookie');
  if (btnCopyCookie) {
    btnCopyCookie.addEventListener('click', () => {
      const match = document.cookie.match(/chitanda_sso_session=([^;]+)/);
      const val = match ? match[1] : '';
      if (!val) {
        navigator.clipboard.writeText('chitanda_sso_session (HttpOnly)').then(() => {
          showToast('已复制 Cookie 字段名 (生产环境开启了 HttpOnly 防护)', 'info');
        });
        return;
      }
      navigator.clipboard.writeText(`chitanda_sso_session=${val}`).then(() => {
        showToast('漫游 Cookie 已成功复制到剪贴板', 'success');
      }).catch(() => {
        showToast('复制失败，请手动在浏览器调试工具中查看', 'error');
      });
    });
  }

  const user = await loadMe();
  if (!user) return;
  loadApps();

  // 3. Tab Switching
  const navButtons = document.querySelectorAll('nav [data-tab]');
  const tabContents = document.querySelectorAll('.tab-content');
  const breadcrumbTitle = document.getElementById('breadcrumb-title');

  const tabMetadata = {
    apps: {
      kicker: 'ECOSYSTEM APPS',
      title: '全域应用导航',
      desc: '已通过统一身份凭据打通的 Chitanda 旗下服务，支持免登录漫游进入。',
      breadcrumb: '全域应用'
    },
    security: {
      kicker: 'ACCOUNT SECURITY',
      title: '安全与凭据管理',
      desc: '管理管理员登录密码、两步动态验证 (TOTP) 及个人公开资料。',
      breadcrumb: '安全与 2FA'
    },
    sessions: {
      kicker: 'DEVICE MANAGEMENT',
      title: '活跃登录会话',
      desc: '当前账号在各设备上的已授权登录凭据，可实时远程注销指定终端。',
      breadcrumb: '登录会话'
    },
    clients: {
      kicker: 'OIDC CLIENTS',
      title: '授权应用管理',
      desc: '配置允许接入 Chitanda SSO 协议的 OAuth 2.0 / OIDC 客户端与回调白名单。',
      breadcrumb: '授权应用'
    },
    audit: {
      kicker: 'SECURITY AUDIT',
      title: '安全审计记录',
      desc: '全域身份授权、登录成功、密码变更及失败防御事件的不可篡改日志。',
      breadcrumb: '审计日志'
    }
  };

  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      navButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      tabContents.forEach(tc => tc.style.display = 'none');
      const activeContent = document.getElementById(`tab-${targetTab}`);
      if (activeContent) activeContent.style.display = 'block';

      // Layout toggle:
      // Tab 'apps' keeps 2 columns with the right aside dashboard cards.
      // Tabs 'security', 'sessions', 'clients', 'audit' are full-width per row without the aside.
      const portalBody = document.querySelector('.portal-body');
      const portalAside = document.querySelector('.portal-aside');
      if (targetTab === 'apps') {
        if (portalAside) portalAside.style.display = '';
        if (portalBody) {
          portalBody.classList.remove('fullwidth');
          portalBody.classList.add('has-aside');
        }
      } else {
        if (portalAside) portalAside.style.display = 'none';
        if (portalBody) {
          portalBody.classList.remove('has-aside');
          portalBody.classList.add('fullwidth');
        }
      }

      const meta = tabMetadata[targetTab];
      if (meta) {
        const kickerEl = document.getElementById('portal-kicker');
        const titleEl = document.getElementById('portal-title');
        const descEl = document.getElementById('portal-desc');
        if (kickerEl) kickerEl.textContent = meta.kicker;
        if (titleEl) titleEl.textContent = meta.title;
        if (descEl) descEl.textContent = meta.desc;
        if (breadcrumbTitle) breadcrumbTitle.textContent = meta.breadcrumb;
      }

      // Lazy load tab data
      if (targetTab === 'apps') loadApps();
      if (targetTab === 'sessions') loadSessions();
      if (targetTab === 'clients') loadClients();
      if (targetTab === 'audit') loadAuditLogs();
    });
  });

  // 4. Logout
  document.getElementById('btn-logout').addEventListener('click', async () => {
    try {
      await fetch('/oauth/logout', { method: 'POST' });
    } catch {
      // ignore
    }
    window.location.href = '/login';
  });

  // 5. Change Password
  const formPassword = document.getElementById('form-password');
  formPassword.addEventListener('submit', async (e) => {
    e.preventDefault();
    const oldPass = document.getElementById('old-pass').value;
    const newPass = document.getElementById('new-pass').value;
    const confirmPass = document.getElementById('confirm-pass').value;

    if (newPass !== confirmPass) {
      showToast('两次输入的新密码不一致', 'error');
      return;
    }

    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password: oldPass, new_password: newPass })
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        showToast(data.message || '密码修改成功', 'success');
        formPassword.reset();
      } else {
        showToast(data.error || '密码修改失败', 'error');
      }
    } catch (err) {
      showToast('请求异常，请稍后重试', 'error');
    }
  });

  // 6. TOTP Setup
  const dialogTotp = document.getElementById('dialog-totp');
  const btnEnableTotp = document.getElementById('btn-enable-totp');
  const btnDisableTotp = document.getElementById('btn-disable-totp');
  const formVerifyTotp = document.getElementById('form-verify-totp');
  const totpError = document.getElementById('totp-error');
  const reauthDialog = document.getElementById('dialog-reauth');
  const reauthForm = document.getElementById('form-reauth');
  const reauthPassword = document.getElementById('reauth-password');
  const reauthCode = document.getElementById('reauth-code');
  let finishReauth = null;
  function requestReauth(disable = false) {
    if (finishReauth) return Promise.resolve(null);
    reauthForm.reset();
    document.getElementById('reauth-title').textContent = disable ? '关闭两步验证' : '设置两步验证';
    document.getElementById('reauth-code-field').hidden = !disable;
    document.getElementById('reauth-code-field').style.display = disable ? 'grid' : 'none';
    reauthCode.required = disable;
    return new Promise(resolve => { finishReauth = resolve; reauthDialog.showModal(); });
  }
  reauthForm.addEventListener('submit', event => {
    event.preventDefault();
    const finish = finishReauth;
    finishReauth = null;
    const credentials = { password: reauthPassword.value, code: reauthCode.value.trim() };
    reauthDialog.close();
    reauthForm.reset();
    finish?.(credentials);
  });
  reauthDialog.addEventListener('close', () => {
    reauthForm.reset();
    if (finishReauth) { const finish = finishReauth; finishReauth = null; finish(null); }
  });

  btnEnableTotp.addEventListener('click', async () => {
    const credentials = await requestReauth();
    if (!credentials) return;
    try {
      const res = await fetch('/api/auth/totp/setup', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(credentials)});
      const data = await res.json();
      if (!res.ok || !data.ok) {
        showToast(data.error || '获取两步验证密钥失败', 'error');
        return;
      }

      document.getElementById('totp-secret-box').textContent = data.secret;
      document.getElementById('totp-qr-box').innerHTML = data.qrSvg||QRCodeGenerator.createQrSvg(data.uri);
      totpError.style.display = 'none';
      document.getElementById('totp-verify-input').value = '';
      dialogTotp.showModal();
    } catch {
      showToast('网络请求异常', 'error');
    }
  });

  formVerifyTotp.addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = document.getElementById('totp-verify-input').value.trim();
    totpError.style.display = 'none';

    try {
      const res = await fetch('/api/auth/totp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        showToast(data.message || '两步验证已成功启用', 'success');
        dialogTotp.close();
        loadMe();
      } else {
        totpError.textContent = data.error || '验证码错误';
        totpError.style.display = 'block';
      }
    } catch {
      totpError.textContent = '网络错误';
      totpError.style.display = 'block';
    }
  });

  btnDisableTotp.addEventListener('click', async () => {
    const credentials = await requestReauth(true);
    if (!credentials) return;

    try {
      const res = await fetch('/api/auth/totp/disable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials)
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        showToast('两步验证已关闭', 'success');
        loadMe();
      } else {
        showToast(data.error || '操作失败', 'error');
      }
    } catch {
      showToast('网络异常', 'error');
    }
  });

  // 7. Sessions Management
  async function loadSessions() {
    const tbody = document.getElementById('sessions-tbody');
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#a494ab;">加载中...</td></tr>';
    try {
      const res = await fetch('/api/auth/sessions');
      const data = await res.json();
      if (!res.ok || !data.ok) return;

      tbody.innerHTML = '';
      data.sessions.forEach(s => {
        const tr = document.createElement('tr');
        const isCurrent = s.id === data.currentSessionId;

        tr.innerHTML = `
          <td>
            <div style="display:flex;align-items:center;gap:8px;">
              <span>💻</span>
              <span style="font-size:12px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(s.user_agent)}">
                ${escapeHtml(s.user_agent ? s.user_agent.slice(0, 50) + '...' : '未知浏览器')}
              </span>
            </div>
          </td>
          <td><code>${escapeHtml(s.ip || '127.0.0.1')}</code></td>
          <td><small style="color:#9e8ea6;">${formatTime(s.created_at)}</small></td>
          <td><small style="color:#9e8ea6;">${formatTime(s.last_active_at)}</small></td>
          <td>
            ${isCurrent ? '<span class="tag">当前设备</span>' : '<span class="tag offline">活跃</span>'}
          </td>
          <td>
            ${isCurrent ? '<span style="color:#b5a6be;font-size:11px;">本机</span>' : `<button class="text-button" style="color:var(--red);" data-revoke-session="${escapeHtml(s.id)}">下线</button>`}
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--red);">加载失败</td></tr>';
    }
  }

  window.revokeSession = async (id) => {
    if (!confirm('确定注销此设备会话？该设备需重新登录。')) return;
    try {
      const res = await fetch(`/api/auth/sessions/${id}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok && data.ok) {
        showToast('该会话已注销', 'success');
        loadSessions();
      } else {
        showToast(data.error || '注销失败', 'error');
      }
    } catch {
      showToast('请求失败', 'error');
    }
  };

  document.getElementById('btn-revoke-others').addEventListener('click', async () => {
    if (!confirm('确定注销其他所有设备会话？当前设备不受影响。')) return;
    try {
      const res = await fetch('/api/auth/sessions', { method: 'GET' });
      const data = await res.json();
      if (res.ok && data.ok) {
        for (const s of data.sessions) {
          if (s.id !== data.currentSessionId) {
            await fetch(`/api/auth/sessions/${s.id}`, { method: 'DELETE' });
          }
        }
        showToast('其他设备已全部注销', 'success');
        loadSessions();
      }
    } catch {
      showToast('操作异常', 'error');
    }
  });

  // 8. OAuth Clients
  const dialogClient = document.getElementById('dialog-client');
  document.getElementById('btn-add-client').addEventListener('click', () => {
    dialogClient.showModal();
  });

  document.getElementById('form-add-client').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('new-client-name').value.trim();
    const uris = document.getElementById('new-client-uris').value.split('\n').map(u => u.trim()).filter(Boolean);
    const scopes = document.getElementById('new-client-scopes').value.trim();

    try {
      const res = await fetch('/api/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, redirect_uris: uris, scopes })
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        showToast('OAuth 客户端创建成功', 'success');
        dialogClient.close();
        document.getElementById('form-add-client').reset();
        loadClients();
      } else {
        showToast(data.error || '创建失败', 'error');
      }
    } catch {
      showToast('网络请求失败', 'error');
    }
  });

  async function loadClients() {
    const tbody = document.getElementById('clients-tbody');
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#a494ab;">加载中...</td></tr>';
    try {
      const res = await fetch('/api/clients');
      const data = await res.json();
      if (!res.ok || !data.ok) return;

      tbody.innerHTML = '';
      data.clients.forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${escapeHtml(c.name)}</strong></td>
          <td><code>${escapeHtml(c.client_id)}</code></td>
          <td><small style="color:#806f89;">${(c.redirect_uris || []).map(u => escapeHtml(u)).join('<br>')}</small></td>
          <td><code>${escapeHtml(c.scopes || 'openid')}</code></td>
          <td>
            ${c.is_system ? '<span class="tag purple">系统预置</span>' : '<span class="tag">自定义</span>'}
          </td>
          <td>
            ${c.is_system ? '<span style="color:#a899af;font-size:11px;">内置</span>' : `<button class="text-button" style="color:var(--red);" data-delete-client="${escapeHtml(c.client_id)}">删除</button>`}
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--red);">加载失败</td></tr>';
    }
  }

  window.deleteClient = async (id) => {
    if (!confirm(`确定删除客户端 ${id}？`)) return;
    try {
      const res = await fetch(`/api/clients/${id}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok && data.ok) {
        showToast('应用已删除', 'success');
        loadClients();
      } else {
        showToast(data.error || '删除失败', 'error');
      }
    } catch {
      showToast('请求异常', 'error');
    }
  };

  // 9. Audit Logs
  async function loadAuditLogs() {
    const tbody = document.getElementById('audit-tbody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#a494ab;">加载中...</td></tr>';
    try {
      const res = await fetch('/api/audit-logs');
      const data = await res.json();
      if (!res.ok || !data.ok) return;

      tbody.innerHTML = '';
      data.logs.forEach(l => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><small style="color:#9e8ea6;">${formatTime(l.created_at)}</small></td>
          <td><code>${escapeHtml(l.event)}</code></td>
          <td>${escapeHtml(l.username || '匿名')}</td>
          <td><code>${escapeHtml(l.ip || '-')}</code></td>
          <td><span style="font-size:12px;color:#786980;">${escapeHtml(l.details || '')}</span></td>
        `;
        tbody.appendChild(tr);
      });
    } catch {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--red);">加载失败</td></tr>';
    }
  }

  // 10. Ecosystem Apps Management (CRUD, Pagination, Adaptive Grid & Drag/Move Reorder)
  let cachedApps = [];
  let isManageMode = false;

  const DEFAULT_APPS_LAYOUT = {
    maxCols: 4,
    maxRows: 2,
    minWidth: 240,
    minHeight: 165,
    gap: 20
  };

  let appsLayout = { ...DEFAULT_APPS_LAYOUT };
  let currentAppsPage = 1;

  try {
    const saved = localStorage.getItem('chitanda_portal_apps_layout');
    if (saved) {
      const parsed = JSON.parse(saved);
      appsLayout = {
        maxCols: Math.max(2, Math.min(6, parseInt(parsed.maxCols, 10) || DEFAULT_APPS_LAYOUT.maxCols)),
        maxRows: Math.max(1, Math.min(6, parseInt(parsed.maxRows, 10) || DEFAULT_APPS_LAYOUT.maxRows)),
        minWidth: Math.max(180, Math.min(380, parseInt(parsed.minWidth, 10) || DEFAULT_APPS_LAYOUT.minWidth)),
        minHeight: Math.max(130, Math.min(260, parseInt(parsed.minHeight, 10) || DEFAULT_APPS_LAYOUT.minHeight)),
        gap: Math.max(10, Math.min(36, parseInt(parsed.gap, 10) || DEFAULT_APPS_LAYOUT.gap))
      };
    }
  } catch {}

  function applyAppsLayout() {
    const container = document.getElementById('apps-grid-container');
    if (container) {
      container.style.setProperty('--app-max-cols', appsLayout.maxCols);
      container.style.setProperty('--app-max-rows', appsLayout.maxRows);
      container.style.setProperty('--app-min-width', `${appsLayout.minWidth}px`);
      container.style.setProperty('--app-min-height', `${appsLayout.minHeight}px`);
      container.style.setProperty('--app-gap', `${appsLayout.gap}px`);
    }

    const selCols = document.getElementById('select-max-cols');
    const selRows = document.getElementById('select-max-rows');
    if (selCols) selCols.value = String(appsLayout.maxCols);
    if (selRows) selRows.value = String(appsLayout.maxRows);

    const inMinWidth = document.getElementById('cfg-card-min-width');
    const inMinHeight = document.getElementById('cfg-card-min-height');
    const inGap = document.getElementById('cfg-card-gap');
    const valMinWidth = document.getElementById('val-card-min-width');
    const valMinHeight = document.getElementById('val-card-min-height');
    const valGap = document.getElementById('val-card-gap');

    if (inMinWidth) inMinWidth.value = appsLayout.minWidth;
    if (inMinHeight) inMinHeight.value = appsLayout.minHeight;
    if (inGap) inGap.value = appsLayout.gap;
    if (valMinWidth) valMinWidth.textContent = `${appsLayout.minWidth}px`;
    if (valMinHeight) valMinHeight.textContent = `${appsLayout.minHeight}px`;
    if (valGap) valGap.textContent = `${appsLayout.gap}px`;
  }

  function saveAppsLayout(newCfg) {
    appsLayout = { ...appsLayout, ...newCfg };
    try {
      localStorage.setItem('chitanda_portal_apps_layout', JSON.stringify(appsLayout));
    } catch {}
    applyAppsLayout();
    renderApps();
  }

  function getPaginationMeta() {
    const totalApps = cachedApps.length;
    const maxCols = Math.max(1, parseInt(appsLayout.maxCols, 10) || 4);
    const maxRows = Math.max(1, parseInt(appsLayout.maxRows, 10) || 2);
    const pageSize = maxCols * maxRows;
    const totalPages = Math.max(1, Math.ceil(totalApps / pageSize));

    if (currentAppsPage > totalPages) {
      currentAppsPage = totalPages;
    }
    if (currentAppsPage < 1) {
      currentAppsPage = 1;
    }

    const startIndex = (currentAppsPage - 1) * pageSize;
    const endIndex = Math.min(startIndex + pageSize, totalApps);
    const pageApps = cachedApps.slice(startIndex, endIndex);

    return {
      totalApps,
      maxCols,
      maxRows,
      pageSize,
      totalPages,
      currentPage: currentAppsPage,
      startIndex,
      endIndex,
      pageApps
    };
  }

  async function loadApps() {
    const container = document.getElementById('apps-grid-container');
    if (!container) return;

    try {
      const res = await fetch('/api/apps');
      const data = await res.json();
      if (res.ok && data.ok && Array.isArray(data.apps)) {
        cachedApps = data.apps;
      }
    } catch {
      // fallback
    }

    // Update ribbon counter
    const appsEl = document.getElementById('metric-apps-count');
    if (appsEl) {
      appsEl.textContent = `${cachedApps.length} 个应用`;
    }

    renderApps();
  }

  function renderApps() {
    const container = document.getElementById('apps-grid-container');
    if (!container) return;

    applyAppsLayout();

    // Permissions check for manage buttons
    const isAdminUser = currentUser && Array.isArray(currentUser.roles) && (currentUser.roles.includes('admin') || currentUser.roles.includes('root'));
    const btnToggleManage = document.getElementById('btn-toggle-manage-apps');
    const btnOpenAddApp = document.getElementById('btn-open-add-app');
    if (!isAdminUser) {
      if (btnToggleManage) btnToggleManage.style.display = 'none';
      if (btnOpenAddApp) btnOpenAddApp.style.display = 'none';
    }

    const meta = getPaginationMeta();

    if (!cachedApps.length) {
      container.innerHTML = `
        <div style="grid-column: 1 / -1; text-align: center; color: #a494ab; padding: 48px; background: rgba(255,253,249,0.7); border-radius: 18px; border: 1.5px dashed var(--border);">
          <div style="font-size: 28px; margin-bottom: 8px;">🌸</div>
          <p style="font-size: 15px; margin-bottom: 6px; color: #645371; font-weight: 500;">暂无全域应用卡片</p>
          <small>可点击上方“＋ 添加应用”添加第一个接入的服务</small>
        </div>
      `;
      renderPagination(meta);
      return;
    }

    container.innerHTML = '';
    meta.pageApps.forEach((app, pageIdx) => {
      const globalIdx = meta.startIndex + pageIdx;
      const isGloballyFirst = globalIdx === 0;
      const isGloballyLast = globalIdx === meta.totalApps - 1;

      const card = document.createElement('div');
      card.className = `app-card ${isManageMode && isAdminUser ? 'has-manage-bar' : ''}`;
      card.setAttribute('data-id', app.id);
      card.setAttribute('draggable', (isManageMode && isAdminUser) ? 'true' : 'false');

      const manageBarStyle = (isManageMode && isAdminUser) ? 'display: flex;' : 'display: none;';

      card.innerHTML = `
        <div class="app-card-manage-bar" style="${manageBarStyle}">
          <span class="app-drag-handle" title="按住拖拽卡片调整次序">⠿ 拖拽</span>
          <div class="app-card-btns">
            <button type="button" class="btn-app-move-prev" title="前移一位" ${isGloballyFirst ? 'disabled' : ''}>← 前移</button>
            <button type="button" class="btn-app-move-next" title="后移一位" ${isGloballyLast ? 'disabled' : ''}>后移 →</button>
            <button type="button" class="btn-app-edit" title="编辑应用">✏️ 编辑</button>
            <button type="button" class="btn-app-del" title="删除应用" style="color:var(--red);">🗑️ 删除</button>
          </div>
        </div>
        <a class="app-card-link" href="${escapeHtml(app.url)}" target="_blank" rel="noopener">
          <div>
            <div class="app-card-head">
              <div class="app-icon" style="background: ${escapeHtml(app.icon_bg || '#f1e9f4')};">${escapeHtml(app.icon || '🌸')}</div>
              <span class="tag ${escapeHtml(app.tag_color || '')}">${escapeHtml(app.tag || '全域服务')}</span>
            </div>
            <h3>${escapeHtml(app.name)}</h3>
            <p title="${escapeHtml(app.description || '')}">${escapeHtml(app.description || '暂无描述信息')}</p>
          </div>
          <div class="app-card-foot">
            <span>${escapeHtml(app.footer_text || extractHost(app.url))}</span>
            <span>进入应用 &rarr;</span>
          </div>
        </a>
      `;

      // Prevent link navigation if in manage mode
      const link = card.querySelector('.app-card-link');
      link?.addEventListener('click', (e) => {
        if (isManageMode) {
          e.preventDefault();
        }
      });

      // Buttons
      const btnPrev = card.querySelector('.btn-app-move-prev');
      const btnNext = card.querySelector('.btn-app-move-next');
      const btnEdit = card.querySelector('.btn-app-edit');
      const btnDel = card.querySelector('.btn-app-del');

      btnPrev?.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (globalIdx > 0) {
          const temp = cachedApps[globalIdx - 1];
          cachedApps[globalIdx - 1] = cachedApps[globalIdx];
          cachedApps[globalIdx] = temp;
          if (pageIdx === 0 && currentAppsPage > 1) {
            currentAppsPage--;
          }
          renderApps();
          await saveNewOrder();
        }
      });

      btnNext?.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (globalIdx < meta.totalApps - 1) {
          const temp = cachedApps[globalIdx + 1];
          cachedApps[globalIdx + 1] = cachedApps[globalIdx];
          cachedApps[globalIdx] = temp;
          if (pageIdx === meta.pageApps.length - 1 && currentAppsPage < meta.totalPages) {
            currentAppsPage++;
          }
          renderApps();
          await saveNewOrder();
        }
      });

      btnEdit?.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        openAppDialog(app);
      });

      btnDel?.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!confirm(`确定删除应用“${app.name}”？`)) return;
        try {
          const res = await fetch(`/api/apps/${app.id}`, { method: 'DELETE' });
          const data = await res.json();
          if (res.ok && data.ok) {
            showToast('应用已成功删除', 'success');
            await loadApps();
          } else {
            showToast(data.error || '删除失败', 'error');
          }
        } catch {
          showToast('请求异常', 'error');
        }
      });

      // Drag and Drop
      setupCardDrag(card, app);

      container.appendChild(card);
    });

    renderPagination(meta);
  }

  let dragSrcCard = null;

  function setupCardDrag(card, app) {
    card.addEventListener('dragstart', (e) => {
      if (!isManageMode) {
        e.preventDefault();
        return;
      }
      dragSrcCard = card;
      card.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', app.id);
    });

    card.addEventListener('dragover', (e) => {
      if (!isManageMode || !dragSrcCard || dragSrcCard === card) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      card.classList.add('drag-over');
    });

    card.addEventListener('dragleave', () => {
      card.classList.remove('drag-over');
    });

    card.addEventListener('drop', async (e) => {
      if (!isManageMode || !dragSrcCard || dragSrcCard === card) return;
      e.preventDefault();
      card.classList.remove('drag-over');

      const srcId = e.dataTransfer.getData('text/plain');
      const targetId = card.getAttribute('data-id');

      const srcIdx = cachedApps.findIndex(a => a.id === srcId);
      const targetIdx = cachedApps.findIndex(a => a.id === targetId);

      if (srcIdx !== -1 && targetIdx !== -1 && srcIdx !== targetIdx) {
        const [movedItem] = cachedApps.splice(srcIdx, 1);
        cachedApps.splice(targetIdx, 0, movedItem);
        renderApps();
        await saveNewOrder();
      }
    });

    card.addEventListener('dragend', () => {
      card.classList.remove('dragging');
      document.querySelectorAll('.app-card').forEach(c => c.classList.remove('drag-over'));
    });
  }

  async function saveNewOrder() {
    const appIds = cachedApps.map(a => a.id);
    try {
      const res = await fetch('/api/apps/reorder', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app_ids: appIds })
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        showToast('应用顺序已成功保存', 'success');
      } else {
        showToast(data.error || '排序保存失败', 'error');
        await loadApps();
      }
    } catch {
      showToast('网络请求失败', 'error');
      await loadApps();
    }
  }

  function renderPagination(meta) {
    const wrapper = document.getElementById('apps-pagination-wrapper');
    const infoEl = document.getElementById('apps-pagination-info');
    const pageNumsEl = document.getElementById('apps-page-numbers');
    const btnFirst = document.getElementById('btn-page-first');
    const btnPrev = document.getElementById('btn-page-prev');
    const btnNext = document.getElementById('btn-page-next');
    const btnLast = document.getElementById('btn-page-last');
    const inputJump = document.getElementById('input-page-jump');

    if (!wrapper || !infoEl) return;

    if (meta.totalApps === 0) {
      wrapper.style.display = 'none';
      return;
    }

    wrapper.style.display = 'flex';

    const displayFrom = meta.startIndex + 1;
    const displayTo = meta.endIndex;

    infoEl.innerHTML = `
      <span>显示第 <strong>${displayFrom}</strong> - <strong>${displayTo}</strong> 项</span>
      <span class="sep-dot">·</span>
      <span>共 <strong>${meta.totalApps}</strong> 个全域应用</span>
      <span class="sep-dot">·</span>
      <span>第 <strong>${meta.currentPage}</strong> / <strong>${meta.totalPages}</strong> 页</span>
      <span class="page-capacity-tag">每页最多 ${meta.maxRows} 行 × ${meta.maxCols} 列 (${meta.pageSize} 个)</span>
    `;

    const hasPrev = meta.currentPage > 1;
    const hasNext = meta.currentPage < meta.totalPages;

    if (btnFirst) btnFirst.disabled = !hasPrev;
    if (btnPrev) btnPrev.disabled = !hasPrev;
    if (btnNext) btnNext.disabled = !hasNext;
    if (btnLast) btnLast.disabled = !hasNext;

    if (inputJump) {
      inputJump.max = meta.totalPages;
      inputJump.value = meta.currentPage;
    }

    if (pageNumsEl) {
      pageNumsEl.innerHTML = '';
      const range = getPaginationRange(meta.currentPage, meta.totalPages);
      range.forEach(item => {
        if (item === '...') {
          const span = document.createElement('span');
          span.className = 'page-ellipsis';
          span.textContent = '…';
          pageNumsEl.appendChild(span);
        } else {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = `btn-page-num ${item === meta.currentPage ? 'active' : ''}`;
          btn.textContent = String(item);
          btn.title = `第 ${item} 页`;
          btn.addEventListener('click', () => {
            if (currentAppsPage !== item) {
              currentAppsPage = item;
              renderApps();
              scrollToAppsTop();
            }
          });
          pageNumsEl.appendChild(btn);
        }
      });
    }
  }

  function getPaginationRange(current, total) {
    if (total <= 7) {
      return Array.from({ length: total }, (_, i) => i + 1);
    }
    if (current <= 4) {
      return [1, 2, 3, 4, 5, '...', total];
    }
    if (current >= total - 3) {
      return [1, '...', total - 4, total - 3, total - 2, total - 1, total];
    }
    return [1, '...', current - 1, current, current + 1, '...', total];
  }

  function scrollToAppsTop() {
    const anchor = document.querySelector('.apps-section-bar');
    if (anchor) {
      anchor.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  // Pagination navigation listeners
  document.getElementById('btn-page-first')?.addEventListener('click', () => {
    if (currentAppsPage > 1) {
      currentAppsPage = 1;
      renderApps();
      scrollToAppsTop();
    }
  });

  document.getElementById('btn-page-prev')?.addEventListener('click', () => {
    if (currentAppsPage > 1) {
      currentAppsPage--;
      renderApps();
      scrollToAppsTop();
    }
  });

  document.getElementById('btn-page-next')?.addEventListener('click', () => {
    const meta = getPaginationMeta();
    if (currentAppsPage < meta.totalPages) {
      currentAppsPage++;
      renderApps();
      scrollToAppsTop();
    }
  });

  document.getElementById('btn-page-last')?.addEventListener('click', () => {
    const meta = getPaginationMeta();
    if (currentAppsPage < meta.totalPages) {
      currentAppsPage = meta.totalPages;
      renderApps();
      scrollToAppsTop();
    }
  });

  const jumpToPage = () => {
    const input = document.getElementById('input-page-jump');
    if (!input) return;
    const meta = getPaginationMeta();
    let target = parseInt(input.value, 10);
    if (isNaN(target)) target = 1;
    target = Math.max(1, Math.min(meta.totalPages, target));
    if (currentAppsPage !== target) {
      currentAppsPage = target;
      renderApps();
      scrollToAppsTop();
    }
  };

  document.getElementById('btn-page-jump')?.addEventListener('click', jumpToPage);
  document.getElementById('input-page-jump')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      jumpToPage();
    }
  });

  // Layout Selects listeners
  document.getElementById('select-max-cols')?.addEventListener('change', (e) => {
    const val = parseInt(e.target.value, 10) || DEFAULT_APPS_LAYOUT.maxCols;
    saveAppsLayout({ maxCols: val });
  });

  document.getElementById('select-max-rows')?.addEventListener('change', (e) => {
    const val = parseInt(e.target.value, 10) || DEFAULT_APPS_LAYOUT.maxRows;
    saveAppsLayout({ maxRows: val });
  });

  // Layout Dialog & Spec Fine-Tuning
  const dialogAppLayout = document.getElementById('dialog-app-layout');
  const btnToggleLayoutModal = document.getElementById('btn-toggle-layout-modal');
  const formAppLayout = document.getElementById('form-app-layout');

  if (btnToggleLayoutModal && dialogAppLayout) {
    btnToggleLayoutModal.addEventListener('click', () => {
      applyAppsLayout();
      dialogAppLayout.showModal();
    });
  }

  const inMinWidth = document.getElementById('cfg-card-min-width');
  const inMinHeight = document.getElementById('cfg-card-min-height');
  const inGap = document.getElementById('cfg-card-gap');
  const valMinWidth = document.getElementById('val-card-min-width');
  const valMinHeight = document.getElementById('val-card-min-height');
  const valGap = document.getElementById('val-card-gap');

  inMinWidth?.addEventListener('input', (e) => {
    if (valMinWidth) valMinWidth.textContent = `${e.target.value}px`;
  });
  inMinHeight?.addEventListener('input', (e) => {
    if (valMinHeight) valMinHeight.textContent = `${e.target.value}px`;
  });
  inGap?.addEventListener('input', (e) => {
    if (valGap) valGap.textContent = `${e.target.value}px`;
  });

  if (formAppLayout) {
    formAppLayout.addEventListener('submit', (e) => {
      e.preventDefault();
      const minWidth = parseInt(inMinWidth?.value, 10) || DEFAULT_APPS_LAYOUT.minWidth;
      const minHeight = parseInt(inMinHeight?.value, 10) || DEFAULT_APPS_LAYOUT.minHeight;
      const gap = parseInt(inGap?.value, 10) || DEFAULT_APPS_LAYOUT.gap;

      saveAppsLayout({ minWidth, minHeight, gap });
      dialogAppLayout?.close();
      showToast('卡片规格与排版参数已应用', 'success');
    });
  }

  document.getElementById('btn-reset-layout')?.addEventListener('click', () => {
    saveAppsLayout(DEFAULT_APPS_LAYOUT);
    showToast('已恢复卡片默认规格排版', 'info');
  });



  // Add / Edit Dialog
  const dialogApp = document.getElementById('dialog-app');
  const btnOpenAddApp = document.getElementById('btn-open-add-app');
  const formApp = document.getElementById('form-app');

  if (btnOpenAddApp) {
    btnOpenAddApp.addEventListener('click', () => {
      openAppDialog(null);
    });
  }

  function openAppDialog(appToEdit = null) {
    if (!dialogApp || !formApp) return;
    formApp.reset();
    const title = document.getElementById('dialog-app-title');

    if (appToEdit) {
      if (title) title.textContent = '编辑全域应用';
      document.getElementById('app-form-id').value = appToEdit.id;
      document.getElementById('app-name').value = appToEdit.name || '';
      document.getElementById('app-url').value = appToEdit.url || '';
      document.getElementById('app-icon').value = appToEdit.icon || '🌸';
      document.getElementById('app-tag').value = appToEdit.tag || '全域服务';
      document.getElementById('app-tag-color').value = appToEdit.tag_color || '';
      document.getElementById('app-foot').value = appToEdit.footer_text || '';
      document.getElementById('app-desc').value = appToEdit.description || '';
    } else {
      if (title) title.textContent = '添加全域应用';
      document.getElementById('app-form-id').value = '';
      document.getElementById('app-icon').value = '🌸';
      document.getElementById('app-tag').value = '全域服务';
    }

    dialogApp.showModal();
  }

  if (formApp) {
    formApp.addEventListener('submit', async (e) => {
      e.preventDefault();
      const appId = document.getElementById('app-form-id').value;
      const name = document.getElementById('app-name').value.trim();
      const url = document.getElementById('app-url').value.trim();
      const icon = document.getElementById('app-icon').value.trim() || '🌸';
      const tag = document.getElementById('app-tag').value.trim() || '全域服务';
      const tagColor = document.getElementById('app-tag-color').value;
      const footerText = document.getElementById('app-foot').value.trim();
      const description = document.getElementById('app-desc').value.trim();

      const payload = {
        name,
        url,
        icon,
        tag,
        tag_color: tagColor,
        footer_text: footerText,
        description
      };

      try {
        let res;
        if (appId) {
          res = await fetch(`/api/apps/${appId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
        } else {
          res = await fetch('/api/apps', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
        }

        const data = await res.json();
        if (res.ok && data.ok) {
          showToast(appId ? '应用信息已更新' : '新应用已成功添加', 'success');
          dialogApp.close();
          await loadApps();
        } else {
          showToast(data.error || '保存失败', 'error');
        }
      } catch {
        showToast('请求异常，请检查网络', 'error');
      }
    });
  }

  function extractHost(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return url || '';
    }
  }

  // Dialog Close buttons
  document.querySelectorAll('.close-dialog').forEach(btn => {
    btn.addEventListener('click', () => {
      btn.closest('dialog')?.close();
    });
  });

  // Helpers
  function formatTime(isoStr) {
    if (!isoStr) return '-';
    try {
      const d = new Date(isoStr);
      return d.toLocaleString('zh-CN', { hour12: false });
    } catch {
      return isoStr;
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function showToast(msg, type = 'info') {
    const toast = document.getElementById('toast');
    toast.className = `toast ${type}`;
    toast.textContent = msg;
    toast.style.display = 'flex';
    setTimeout(() => {
      toast.style.display = 'none';
    }, 3000);
  }
});
