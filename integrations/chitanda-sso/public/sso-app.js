'use strict';

document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const clientId = urlParams.get('client_id');
  const redirectUri = urlParams.get('redirect_uri');

  const form = document.getElementById('login-form');
  const errorEl = document.getElementById('login-error');
  const submitBtn = document.getElementById('login-btn');
  const totpField = document.getElementById('totp-field');
  const totpInput = document.getElementById('input-totp');
  const oauthBanner = document.getElementById('oauth-banner');
  const oauthClientName = document.getElementById('oauth-client-name');
  const loginTitle = document.getElementById('login-title');
  const loginSubtitle = document.getElementById('login-subtitle');

  function getSafeBrowserRedirect(raw) {
    if (!raw) return '/portal';
    try {
      const trimmed = String(raw).trim();
      if (trimmed.startsWith('/') && !trimmed.startsWith('//') && !trimmed.startsWith('/\\')) {
        return trimmed;
      }
      const u = new URL(trimmed, window.location.origin);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') return '/portal';
      const host = u.hostname.toLowerCase();
      if (host === 'chitanda.net' || host.endsWith('.chitanda.net') || host === 'localhost' || host === '127.0.0.1') {
        return trimmed;
      }
    } catch {}
    return '/portal';
  }

  // 1. Check if already logged in
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      if (data.ok && data.user) {
        // Already logged in!
        if (clientId && redirectUri) {
          // Handshake OAuth authorize
          window.location.href = `/oauth/authorize${window.location.search}`;
          return;
        } else if (redirectUri) {
          window.location.href = getSafeBrowserRedirect(redirectUri);
          return;
        } else {
          window.location.href = '/portal';
          return;
        }
      }
    }
  } catch (e) {
    // ignore
  }

  // 2. Setup OAuth client banner if provided
  if (clientId) {
    oauthBanner.style.display = 'flex';
    if (clientId === 'moegallery') {
      oauthClientName.textContent = 'MoeGallery 媒体库';
    } else if (clientId === 'data-platform') {
      oauthClientName.textContent = 'Chitanda 数据中台';
    } else if (clientId === 'chitanda-home') {
      oauthClientName.textContent = 'Chitanda 主站后台';
    } else {
      oauthClientName.textContent = `第三方应用 (${clientId})`;
    }
    loginTitle.textContent = '授权登录';
    loginSubtitle.textContent = '登录以授权该应用访问你的 Chitanda 账号';
    submitBtn.querySelector('span:first-child').textContent = '登录并授权';
  }

  // 3. Handle submit
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorEl.style.display = 'none';
    submitBtn.disabled = true;

    const username = document.getElementById('input-username').value.trim();
    const password = document.getElementById('input-password').value;
    const totpCode = totpInput ? totpInput.value.trim() : '';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          totp_code: totpCode || undefined
        })
      });

      const data = await res.json();

      if (!res.ok || !data.ok) {
        if (data.require_totp) {
          totpField.style.display = 'block';
          totpInput.required = true;
          totpInput.focus();
          submitBtn.querySelector('span:first-child').textContent = '验证动态口令并登录';
          errorEl.textContent = data.message || '请输入动态口令';
          errorEl.style.display = 'block';
        } else {
          errorEl.textContent = data.error || '登录失败，请检查账号密码';
          errorEl.style.display = 'block';
        }
        submitBtn.disabled = false;
        return;
      }

      // Login success
      showToast('登录成功，正在跳转...', 'success');

      setTimeout(() => {
        if (clientId && redirectUri) {
          window.location.href = `/oauth/authorize${window.location.search}`;
        } else if (redirectUri) {
          window.location.href = getSafeBrowserRedirect(redirectUri);
        } else {
          window.location.href = '/portal';
        }
      }, 500);

    } catch (err) {
      errorEl.textContent = '网络连接异常，请重试';
      errorEl.style.display = 'block';
      submitBtn.disabled = false;
    }
  });

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
