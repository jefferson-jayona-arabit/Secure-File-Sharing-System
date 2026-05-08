/* ══════════════════════════════════════════════════════════════
   VaultShare — auth.js
   Handles login / register screen (single-page, no redirects)
   showApp() and showAuthScreen() are defined in script.js
   ══════════════════════════════════════════════════════════════ */

function switchTab(tab) {
  const isLogin = tab === 'login';
  document.querySelectorAll('.tab-btn').forEach((b, i) => {
    b.classList.toggle('active', isLogin ? i === 0 : i === 1);
  });
  document.getElementById('login-form').style.display    = isLogin ? '' : 'none';
  document.getElementById('register-form').style.display = isLogin ? 'none' : '';
  document.getElementById('auth-error').style.display    = 'none';
}

function showAuthError(msg) {
  const e = document.getElementById('auth-error');
  e.textContent   = '⚠ ' + msg;
  e.style.display = 'block';
}

async function doLogin() {
  const email = document.getElementById('login-email').value.trim();
  const pwd   = document.getElementById('login-password').value;
  if (!email || !pwd) return showAuthError('Fill all fields');

  const btn = document.querySelector('#login-form .btn-primary');
  btn.disabled  = true;
  btn.innerHTML = '<span class="spinner"></span> AUTHENTICATING...';

  try {
    const res  = await fetch('/api/auth/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ email, password: pwd })
    });
    const data = await res.json();
    if (!res.ok) {
      showAuthError(data.error || 'Login failed');
    } else {
      authToken   = data.token;
      currentUser = data.user;
      localStorage.setItem('vaultshare_token', authToken);
      localStorage.setItem('vaultshare_user',  JSON.stringify(currentUser));
      showApp();
    }
  } catch {
    showAuthError('Connection failed — is the server running?');
  }

  btn.disabled  = false;
  btn.innerHTML = 'ACCESS VAULT';
}

async function doRegister() {
  const name  = document.getElementById('reg-name').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const pwd   = document.getElementById('reg-password').value;
  if (!name || !email || !pwd) return showAuthError('Fill all fields');
  if (pwd.length < 6) return showAuthError('Password min 6 chars');

  const btn = document.querySelector('#register-form .btn-primary');
  btn.disabled  = true;
  btn.innerHTML = '<span class="spinner"></span> GENERATING RSA KEYS...';

  try {
    const res  = await fetch('/api/auth/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ name, email, password: pwd })
    });
    const data = await res.json();
    if (!res.ok) {
      showAuthError(data.error || 'Registration failed');
    } else {
      authToken   = data.token;
      currentUser = data.user;
      localStorage.setItem('vaultshare_token', authToken);
      localStorage.setItem('vaultshare_user',  JSON.stringify(currentUser));
      showApp();
    }
  } catch {
    showAuthError('Connection failed — is the server running?');
  }

  btn.disabled  = false;
  btn.innerHTML = 'CREATE ACCOUNT + GENERATE RSA KEYS';
}