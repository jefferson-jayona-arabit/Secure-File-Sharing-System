/* ══════════════════════════════════════════════════════════════
   VaultShare — script.js
   Main application logic (single-page, no redirects)
   Auth functions are in auth.js (loaded before this file)
   ══════════════════════════════════════════════════════════════ */

/* ── Shared State (also used by auth.js) ────────────────────── */
let authToken     = localStorage.getItem('vaultshare_token');
let currentUser   = JSON.parse(localStorage.getItem('vaultshare_user') || 'null');
let selectedFile    = null;
let selectedFileId  = null;
let _decryptId      = null;
let _decryptName    = null;
let decSelectedFile = null;

// In-memory decrypted files list: [{ name, size, blob, timestamp }]
let decryptedFiles = [];

/* ══════════════════════════════════════════════════════════════
   SCREEN TOGGLE
   ══════════════════════════════════════════════════════════════ */
function showApp() {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('app').style.display         = 'block';
  document.getElementById('header-user').textContent   = currentUser.email;
  loadFiles();
  renderDecryptedFiles();
  bindDragDrop();
}

function showAuthScreen() {
  document.getElementById('auth-screen').style.display = 'flex';
  document.getElementById('app').style.display         = 'none';
}

/* ── Bootstrap ──────────────────────────────────────────────── */
(function init() {
  if (authToken && currentUser) {
    showApp();
  } else {
    showAuthScreen();
  }
})();

/* ══════════════════════════════════════════════════════════════
   LOGOUT
   ══════════════════════════════════════════════════════════════ */
function doLogout() {
  localStorage.removeItem('vaultshare_token');
  localStorage.removeItem('vaultshare_user');
  authToken   = null;
  currentUser = null;
  // Reset decrypted files
  decryptedFiles.forEach(f => { if (f.url) URL.revokeObjectURL(f.url); });
  decryptedFiles = [];
  // Reset upload state
  selectedFile   = null;
  selectedFileId = null;
  document.getElementById('files-list').innerHTML        = '<div class="empty-files">No encrypted files yet.</div>';
  document.getElementById('detail-empty').style.display  = '';
  document.getElementById('detail-content').style.display = 'none';
  showAuthScreen();
}

/* ══════════════════════════════════════════════════════════════
   UPLOAD & ENCRYPT
   ══════════════════════════════════════════════════════════════ */
function onFileSelect(input) {
  if (!input.files[0]) return;
  selectedFile = input.files[0];
  document.getElementById('selected-file-text').textContent =
    `${selectedFile.name} (${formatSize(selectedFile.size)})`;
  document.getElementById('selected-file-display').style.display = 'flex';
  document.getElementById('upload-btn').style.display             = 'flex';
  document.getElementById('key-toggle-wrap').style.display        = 'block';
  document.getElementById('encrypt-log').style.display            = 'none';
}

function toggleKeySection() {
  const s   = document.getElementById('custom-key-section');
  const btn = document.getElementById('key-toggle-btn');
  const vis = s.style.display !== 'none';
  s.style.display  = vis ? 'none' : 'block';
  btn.textContent  = vis ? '⚙ USE CUSTOM KEYS (OPTIONAL)' : '✕ HIDE CUSTOM KEYS';
}

function generateCustomKey() {
  const key = Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  document.getElementById('custom-aes-key').value = key;
  validateKeyInput();
}

function generateCustomIv() {
  const iv = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  document.getElementById('custom-iv').value = iv;
  validateIvInput();
}

function validateKeyInput() {
  const val  = document.getElementById('custom-aes-key').value;
  const hint = document.getElementById('aes-key-hint');
  if (!val) { hint.textContent = ''; return; }
  const valid      = /^[0-9a-fA-F]{64}$/.test(val);
  hint.textContent = valid ? '✓ Valid 256-bit key' : `✗ Need 64 hex chars (${val.length}/64)`;
  hint.style.color = valid ? 'var(--accent)' : 'var(--danger)';
}

function validateIvInput() {
  const val  = document.getElementById('custom-iv').value;
  const hint = document.getElementById('iv-hint');
  if (!val) { hint.textContent = ''; return; }
  const valid      = /^[0-9a-fA-F]{32}$/.test(val);
  hint.textContent = valid ? '✓ Valid 128-bit IV' : `✗ Need 32 hex chars (${val.length}/32)`;
  hint.style.color = valid ? 'var(--accent)' : 'var(--danger)';
}

async function doUpload() {
  if (!selectedFile) return;

  const customAesKey = document.getElementById('custom-aes-key').value.trim();
  const customIv     = document.getElementById('custom-iv').value.trim();

  if (customAesKey && !/^[0-9a-fA-F]{64}$/.test(customAesKey)) return showToast('Invalid AES key', 'error');
  if (customIv     && !/^[0-9a-fA-F]{32}$/.test(customIv))     return showToast('Invalid IV', 'error');

  const logEl       = document.getElementById('encrypt-log');
  const progressDiv = document.getElementById('upload-progress');
  const fill        = document.getElementById('progress-fill');
  const pctSpan     = document.getElementById('progress-pct');
  const btn         = document.getElementById('upload-btn');

  btn.disabled    = true;
  btn.innerHTML   = '<span class="spinner"></span> ENCRYPTING...';
  logEl.innerHTML = '';
  logEl.style.display       = 'block';
  progressDiv.style.display = 'block';

  let pct  = 0;
  const anim = setInterval(() => {
    pct = Math.min(pct + Math.random() * 8, 85);
    fill.style.width      = pct + '%';
    pctSpan.textContent   = Math.round(pct) + '%';
  }, 150);

  try {
    const fd = new FormData();
    fd.append('file', selectedFile);
    if (customAesKey) fd.append('customAesKey', customAesKey);
    if (customIv)     fd.append('customIv', customIv);

    const res  = await fetch('/api/files/upload', {
      method:  'POST',
      headers: { Authorization: 'Bearer ' + authToken },
      body:    fd
    });
    clearInterval(anim);
    fill.style.width    = '100%';
    pctSpan.textContent = '100%';

    const data = await res.json();
    if (!res.ok) {
      showToast(data.error, 'error');
    } else {
      (data.log || []).forEach(line => {
        const d = document.createElement('div');
        d.className   = 'log-line success';
        d.textContent = line;
        logEl.appendChild(d);
      });
      setTimeout(() => {
        loadFiles();
        showToast('File encrypted & uploaded!', 'success');
        selectedFile = null;
        document.getElementById('file-input').value                   = '';
        document.getElementById('selected-file-display').style.display = 'none';
        document.getElementById('upload-btn').style.display            = 'none';
        document.getElementById('key-toggle-wrap').style.display       = 'none';
        document.getElementById('custom-key-section').style.display    = 'none';
        document.getElementById('custom-aes-key').value                = '';
        document.getElementById('custom-iv').value                     = '';
      }, 1500);
    }
  } catch {
    clearInterval(anim);
    showToast('Upload failed', 'error');
  }

  btn.disabled  = false;
  btn.innerHTML = '🔒 ENCRYPT & UPLOAD';
}

/* ══════════════════════════════════════════════════════════════
   ENCRYPTED FILE LIST
   ══════════════════════════════════════════════════════════════ */
async function loadFiles() {
  try {
    const res  = await fetch('/api/files', { headers: { Authorization: 'Bearer ' + authToken } });
    const data = await res.json();
    renderFiles(data.files || []);
  } catch {}
}

function renderFiles(files) {
  document.getElementById('file-count').textContent =
    files.length + ' file' + (files.length !== 1 ? 's' : '');
  const el = document.getElementById('files-list');

  if (!files.length) {
    el.innerHTML = '<div class="empty-files">No encrypted files yet.</div>';
    return;
  }

  el.innerHTML = files.map(f => `
    <div class="file-item ${selectedFileId === f.id ? 'selected' : ''}"
         onclick="selectFile('${f.id}', this)">
      <div class="file-icon">📁</div>
      <div style="min-width:0;flex:1">
        <div class="file-name">${escHtml(f.name)}</div>
        <div class="file-meta">${formatSize(f.size)} · ${formatDate(f.uploadedAt)}</div>
      </div>
      <div class="file-actions" onclick="event.stopPropagation()">
        <button class="btn-icon" title="Decrypt & Download"
                onclick="openDecryptModal('${f.id}','${escHtml(f.name)}')">⬇</button>
        <button class="btn-icon" title="Download Encrypted"
                onclick="downloadEncrypted('${f.id}','${escHtml(f.name)}')">🔒</button>
        <button class="btn-icon danger" title="Delete"
                onclick="deleteFile('${f.id}')">🗑</button>
      </div>
    </div>`).join('');
}

/* ══════════════════════════════════════════════════════════════
   FILE DETAIL VIEW
   ══════════════════════════════════════════════════════════════ */
async function selectFile(id, el) {
  selectedFileId = id;
  document.querySelectorAll('.file-item').forEach(i => i.classList.remove('selected'));
  if (el) el.classList.add('selected');

  try {
    const res = await fetch(`/api/files/${id}/info`, {
      headers: { Authorization: 'Bearer ' + authToken }
    });
    if (!res.ok) return;
    const f = await res.json();

    document.getElementById('detail-empty').style.display = 'none';
    const dc = document.getElementById('detail-content');
    dc.style.display = 'block';
    dc.innerHTML = `
      <div class="detail-filename">${escHtml(f.name)}</div>
      <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
        <span class="badge badge-aes">AES-256-CBC</span>
        <span class="badge badge-rsa">RSA-OAEP</span>
      </div>
      <div class="detail-section">
        <div class="detail-section-header">📋 File Info</div>
        <div class="detail-row">
          <span class="detail-key">Size</span>
          <span class="detail-val">${formatSize(f.size)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Uploaded</span>
          <span class="detail-val">${formatDate(f.uploadedAt)}</span>
        </div>
      </div>
      <div class="detail-section">
        <div class="detail-section-header">🔐 Encryption</div>
        <div class="detail-row">
          <span class="detail-key">AES IV</span>
          <span class="detail-val">${escHtml(f.iv)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">AES Key</span>
          <span class="detail-val">${escHtml(f.aesKey || '—')}</span>
        </div>
      </div>
      <div class="detail-section">
        <div class="detail-section-header">🔑 Integrity</div>
        <div class="detail-row">
          <span class="detail-key">SHA-256</span>
          <span class="detail-val">${escHtml(f.integrityHash)}</span>
        </div>
      </div>
      <div class="detail-btn-row">
        <button class="btn-download"
                onclick="openDecryptModal('${f.id}','${escHtml(f.name)}')">⬇ DECRYPT</button>
        <button class="btn-download-enc"
                onclick="downloadEncrypted('${f.id}','${escHtml(f.name)}')">🔒 ENCRYPTED</button>
      </div>`;
  } catch {}
}

/* ══════════════════════════════════════════════════════════════
   DECRYPT MODAL (for vault files)
   ══════════════════════════════════════════════════════════════ */
async function openDecryptModal(id, name) {
  _decryptId   = id;
  _decryptName = name;
  document.getElementById('decrypt-aes-key').value        = '';
  document.getElementById('decrypt-iv').value              = '';
  document.getElementById('decrypt-aes-hint').textContent  = '';
  document.getElementById('decrypt-iv-hint').textContent   = '';
  document.getElementById('decrypt-modal').classList.add('show');

  const confirmBtn  = document.querySelector('.btn-modal-confirm');
  confirmBtn.disabled  = true;
  confirmBtn.innerHTML = '<span class="spinner"></span> LOADING KEYS...';

  try {
    const res = await fetch(`/api/files/${id}/keys`, {
      headers: { Authorization: 'Bearer ' + authToken }
    });
    if (res.ok) {
      const { aesKey, iv } = await res.json();
      document.getElementById('decrypt-aes-key').value = aesKey || '';
      document.getElementById('decrypt-iv').value       = iv    || '';
      validateDecryptKey();
      validateDecryptIv();
    }
  } catch {}

  confirmBtn.disabled  = false;
  confirmBtn.innerHTML = '⬇ DECRYPT & DOWNLOAD';
}

function closeDecryptModal() {
  document.getElementById('decrypt-modal').classList.remove('show');
  _decryptId = null;
}

function validateDecryptKey() {
  const val  = document.getElementById('decrypt-aes-key').value;
  const hint = document.getElementById('decrypt-aes-hint');
  if (!val) { hint.textContent = ''; return; }
  const valid      = /^[0-9a-fA-F]{64}$/.test(val);
  hint.textContent = valid ? '✓ Valid key' : '✗ Need 64 hex chars';
  hint.style.color = valid ? 'var(--accent)' : 'var(--danger)';
}

function validateDecryptIv() {
  const val  = document.getElementById('decrypt-iv').value;
  const hint = document.getElementById('decrypt-iv-hint');
  if (!val) { hint.textContent = ''; return; }
  const valid      = /^[0-9a-fA-F]{32}$/.test(val);
  hint.textContent = valid ? '✓ Valid IV' : '✗ Need 32 hex chars';
  hint.style.color = valid ? 'var(--accent)' : 'var(--danger)';
}

async function pasteFromClipboard(inputId, hintId) {
  try {
    const text = await navigator.clipboard.readText();
    document.getElementById(inputId).value = text.trim();
    if (inputId === 'decrypt-aes-key') validateDecryptKey();
    else validateDecryptIv();
  } catch {}
}

async function confirmDecrypt() {
  if (!_decryptId) return;
  const customAesKey = document.getElementById('decrypt-aes-key').value.trim();
  const customIv     = document.getElementById('decrypt-iv').value.trim();
  if (customAesKey && !/^[0-9a-fA-F]{64}$/.test(customAesKey)) return showToast('Invalid AES key', 'error');
  if (customIv     && !/^[0-9a-fA-F]{32}$/.test(customIv))     return showToast('Invalid IV', 'error');

  const id = _decryptId, name = _decryptName;
  closeDecryptModal();
  await downloadFile(id, name, customAesKey || null, customIv || null);
}

async function downloadFile(id, name, customAesKey, customIv) {
  showToast('Decrypting...', '');
  let query = '';
  if (customAesKey) {
    query = `?customAesKey=${encodeURIComponent(customAesKey)}`;
    if (customIv) query += `&customIv=${encodeURIComponent(customIv)}`;
  }

  try {
    const res = await fetch(`/api/files/${id}/download${query}`, {
      headers: { Authorization: 'Bearer ' + authToken }
    });
    if (!res.ok) {
      const d = await res.json();
      return showToast(d.error || 'Decrypt failed', 'error');
    }
    const blob = await res.blob();
    addDecryptedFile(name, blob);
    triggerDownload(blob, name);
    showToast('Downloaded + integrity verified ✓', 'success');
  } catch {
    showToast('Download failed', 'error');
  }
}

async function downloadEncrypted(id, name) {
  try {
    const res = await fetch(`/api/files/${id}/download-encrypted`, {
      headers: { Authorization: 'Bearer ' + authToken }
    });
    if (!res.ok) return showToast('Failed', 'error');
    const blob = await res.blob();
    triggerDownload(blob, name + '.enc');
    showToast('Encrypted file downloaded', 'success');
  } catch {
    showToast('Error', 'error');
  }
}

async function deleteFile(id) {
  if (!confirm('Delete this file permanently?')) return;
  const res = await fetch(`/api/files/${id}`, {
    method:  'DELETE',
    headers: { Authorization: 'Bearer ' + authToken }
  });
  if (res.ok) {
    if (selectedFileId === id) {
      document.getElementById('detail-empty').style.display   = '';
      document.getElementById('detail-content').style.display = 'none';
      selectedFileId = null;
    }
    loadFiles();
    showToast('File deleted', 'success');
  }
}

/* ══════════════════════════════════════════════════════════════
   DECRYPT UPLOAD (.enc file from disk)
   ══════════════════════════════════════════════════════════════ */
function onDecFileSelect(input) {
  if (!input.files[0]) return;
  decSelectedFile = input.files[0];
  document.getElementById('dec-selected-text').textContent =
    `${decSelectedFile.name} (${formatSize(decSelectedFile.size)})`;
  document.getElementById('dec-selected-display').style.display = 'flex';
}

function validateDecUploadKey() {
  const val  = document.getElementById('dec-aes-key').value;
  const hint = document.getElementById('dec-aes-hint');
  if (!val) { hint.textContent = ''; return; }
  const valid      = /^[0-9a-fA-F]{64}$/.test(val);
  hint.textContent = valid ? '✓ Valid key' : '✗ Need 64 hex chars';
  hint.style.color = valid ? 'var(--accent)' : 'var(--danger)';
}

function validateDecUploadIv() {
  const val  = document.getElementById('dec-iv').value;
  const hint = document.getElementById('dec-iv-hint');
  if (!val) { hint.textContent = ''; return; }
  const valid      = /^[0-9a-fA-F]{32}$/.test(val);
  hint.textContent = valid ? '✓ Valid IV' : '✗ Need 32 hex chars';
  hint.style.color = valid ? 'var(--accent)' : 'var(--danger)';
}

async function doDecryptUpload() {
  const aesKey = document.getElementById('dec-aes-key').value.trim();
  const iv     = document.getElementById('dec-iv').value.trim();

  if (!decSelectedFile) return showToast('Please select a .enc file first', 'error');
  if (!aesKey || !iv)   return showToast('Both AES key and IV are required', 'error');
  if (!/^[0-9a-fA-F]{64}$/.test(aesKey)) return showToast('AES key must be 64 hex chars', 'error');
  if (!/^[0-9a-fA-F]{32}$/.test(iv))     return showToast('IV must be 32 hex chars', 'error');

  const btn    = document.getElementById('dec-upload-btn');
  const logDiv = document.getElementById('dec-log');
  btn.disabled  = true;
  btn.innerHTML = '<span class="spinner"></span> DECRYPTING...';
  logDiv.innerHTML     = '';
  logDiv.style.display = 'block';

  try {
    const fd = new FormData();
    fd.append('file', decSelectedFile);
    fd.append('customAesKey', aesKey);
    fd.append('customIv', iv);

    const res = await fetch('/api/files/decrypt-upload', {
      method:  'POST',
      headers: { Authorization: 'Bearer ' + authToken },
      body:    fd
    });

    if (!res.ok) {
      const err = await res.json();
      showToast(err.error || 'Decrypt failed', 'error');
      const d = document.createElement('div');
      d.className   = 'log-line error';
      d.textContent = '✗ ' + (err.error || 'Decryption failed');
      logDiv.appendChild(d);
    } else {
      let originalName = res.headers.get('X-Original-Name');
      if (!originalName) originalName = decSelectedFile.name.replace(/\.enc$/i, '');

      const blob = await res.blob();
      addDecryptedFile(originalName, blob);
      triggerDownload(blob, originalName);
      showToast('Decrypted successfully ✓', 'success');

      const d = document.createElement('div');
      d.className   = 'log-line success';
      d.textContent = `✓ Decrypted: ${originalName}`;
      logDiv.appendChild(d);

      // Reset file selection
      decSelectedFile = null;
      document.getElementById('dec-file-input').value             = '';
      document.getElementById('dec-selected-display').style.display = 'none';
    }
  } catch {
    showToast('Network error', 'error');
  }

  btn.disabled  = false;
  btn.innerHTML = '🔓 DECRYPT & DOWNLOAD';
}

/* ══════════════════════════════════════════════════════════════
   DECRYPTED FILES LIST (in-memory session store)
   ══════════════════════════════════════════════════════════════ */
function addDecryptedFile(name, blob) {
  // Revoke old blob URL if same name already exists
  const existing = decryptedFiles.find(f => f.name === name);
  if (existing && existing.url) URL.revokeObjectURL(existing.url);

  decryptedFiles.unshift({
    name,
    size:      blob.size,
    blob,
    url:       URL.createObjectURL(blob),
    timestamp: new Date()
  });
  renderDecryptedFiles();
}

function removeDecryptedFile(index) {
  const f = decryptedFiles[index];
  if (f && f.url) URL.revokeObjectURL(f.url);
  decryptedFiles.splice(index, 1);
  renderDecryptedFiles();
}

function renderDecryptedFiles() {
  const el      = document.getElementById('decrypted-files-list');
  const countEl = document.getElementById('dec-file-count');
  countEl.textContent = decryptedFiles.length + ' file' + (decryptedFiles.length !== 1 ? 's' : '');

  if (!decryptedFiles.length) {
    el.innerHTML = `<div class="dec-empty">🔓 No decrypted files yet.<br>Files appear here after decryption.</div>`;
    return;
  }

  el.innerHTML = decryptedFiles.map((f, i) => `
    <div class="decrypted-file-row">
      <div class="file-icon dec-icon">📄</div>
      <div style="min-width:0;flex:1">
        <div class="dec-file-name">${escHtml(f.name)}</div>
        <div class="file-meta">${formatSize(f.size)} · ${formatTime(f.timestamp)}</div>
      </div>
      <button class="btn-dl-dec" title="Re-download" onclick="redownloadDecrypted(${i})">⬇</button>
      <button class="btn-rm-dec" title="Remove from list" onclick="removeDecryptedFile(${i})">✕</button>
    </div>`).join('');
}

function redownloadDecrypted(index) {
  const f = decryptedFiles[index];
  if (!f) return;
  triggerDownload(f.blob, f.name);
  showToast('Downloaded: ' + f.name, 'success');
}

/* ══════════════════════════════════════════════════════════════
   DRAG & DROP  (called once from showApp)
   ══════════════════════════════════════════════════════════════ */
function bindDragDrop() {
  // Prevent double-binding
  if (window._dragDropBound) return;
  window._dragDropBound = true;

  // Encrypt drop zone
  const dropZone = document.getElementById('drop-zone');
  dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', ()  => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault(); dropZone.classList.remove('drag-over');
    const f = e.dataTransfer.files[0];
    if (!f) return;
    selectedFile = f;
    document.getElementById('selected-file-text').textContent     = `${f.name} (${formatSize(f.size)})`;
    document.getElementById('selected-file-display').style.display = 'flex';
    document.getElementById('upload-btn').style.display            = 'flex';
    document.getElementById('key-toggle-wrap').style.display       = 'block';
  });

  // Decrypt drop zone
  const decDz = document.getElementById('dec-drop-zone');
  decDz.addEventListener('dragover',  e => { e.preventDefault(); decDz.classList.add('drag-over'); });
  decDz.addEventListener('dragleave', ()  => decDz.classList.remove('drag-over'));
  decDz.addEventListener('drop', e => {
    e.preventDefault(); decDz.classList.remove('drag-over');
    const f = e.dataTransfer.files[0];
    if (!f) return;
    decSelectedFile = f;
    document.getElementById('dec-selected-text').textContent        = `${f.name} (${formatSize(f.size)})`;
    document.getElementById('dec-selected-display').style.display   = 'flex';
  });

  // Close modal on backdrop click
  document.getElementById('decrypt-modal').addEventListener('click', e => {
    if (e.target === document.getElementById('decrypt-modal')) closeDecryptModal();
  });
}

/* ══════════════════════════════════════════════════════════════
   UTILITIES
   ══════════════════════════════════════════════════════════════ */
function triggerDownload(blob, name) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

function formatSize(b) {
  if (!b) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1e6)  return (b / 1024).toFixed(1) + ' KB';
  return (b / 1e6).toFixed(1) + ' MB';
}

function formatDate(iso) {
  return new Date(iso).toLocaleDateString('en-PH', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

function formatTime(date) {
  return date.toLocaleTimeString('en-PH', {
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

function escHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[m]);
}

function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className   = 'toast show ' + type;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('show'), 3000);
}