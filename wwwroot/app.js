const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

const iconPaths = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  transfer: '<path d="M4 7h16m-4-4 4 4-4 4M20 17H4m4-4-4 4 4 4"/>',
  document: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M8 13h8M8 17h6"/>',
  connect: '<path d="m8 8-4 4 4 4m8-8 4 4-4 4m-3-11-2 14"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  logout: '<path d="M9 4H5v16h4m5-12 4 4-4 4M9 12h12"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  file: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="14 3 14 9 20 9"/>',
  server: '<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><line x1="7" y1="7" x2="7.01" y2="7"/><line x1="7" y1="17" x2="7.01" y2="17"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>'
};

function lineIcon(name) {
  return `<svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${iconPaths[name]}</svg>`;
}

for (const [selector, name] of Object.entries({
  '.nav-item[data-view="servers"]>span': 'grid',
  '.nav-item[data-view="keys"]>span': 'key',
  '.nav-item[data-view="batch"]>span': 'terminal',
  '.nav-item[data-view="files"]>span': 'transfer',
  '.nav-item[data-view="connect"]>span': 'connect',
  '.nav-item[data-view="audit"]>span': 'document',
  '.nav-item[data-view="security"]>span': 'shield',
  '#empty-servers .empty-icon': 'server',
  '#empty-keys .empty-icon': 'key',
  '#empty-files .empty-icon': 'transfer',
  '#workspace-server-icon': 'server',
  '.hint>span': 'shield'
})) {
  const el = $(selector);
  if (el) el.innerHTML = lineIcon(name);
}

$('#refresh-servers').innerHTML = lineIcon('refresh');
$('#refresh-keys').innerHTML = lineIcon('refresh');
$('#logout').innerHTML = lineIcon('logout') + '退出登录';
$$('.close').forEach(el => { el.innerHTML = lineIcon('close'); el.setAttribute('aria-label', '关闭'); });

// --- State ---
let servers = [];
let sharedKeys = [];
let snapshots = new Map();
const collectingSnapshots = new Set();
let snippets = [];
let tokens = [];
let selected = null;
let lastCreatedKey = null;
let currentSftpPath = '/';
let editorPath = '';
let textIncomplete = false;
let lastProbeFp = '';
let parsedImportHosts = [];
let auditPage = 1, auditPages = 1;

// WebSSH state
let xterm = null, fitAddon = null, termWs = null, termResizeObserver = null;
const textEncoder = new TextEncoder();

// Job polling state
let jobPollTimer = null;
let jobPollOffset = null;
let jobBufferText = '';

// --- Utilities ---
const escapeHtml = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function fmtBytes(n) {
  if (n == null || isNaN(n)) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

let toastTimer;
function toast(text) {
  const t = $('#toast');
  t.textContent = text;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3200);
}

async function copyText(text, msg = '已复制') {
  try { await navigator.clipboard.writeText(text); toast(msg); }
  catch { toast('请手动复制'); }
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = method === 'GET' ? {} : { 'X-ServerPilot': '1' };
  if (body && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, {
    method,
    headers,
    body: body instanceof FormData ? body : body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'same-origin'
  });
  if (res.status === 401 && path !== '/api/login') {
    closeTerminal();
    stopJobPoll();
    showLogin();
    throw new Error('登录已过期，请重新登录。');
  }
  if (!res.ok) {
    let msg = '操作失败，请稍后重试。';
    try { msg = (await res.json()).error || msg; } catch {}
    throw new Error(msg);
  }
  if (res.status === 204 || !res.headers.get('content-type')?.includes('json')) return null;
  return res.json();
}

// --- Auth & Navigation ---
function showAuthPanel(isSetup) {
  $('#password-form').reset();
  $('#login-form').reset();
  $('#setup-form').reset();
  $('#login-error').textContent = '';
  $('#setup-error').textContent = '';
  selected = null;
  closeTerminal();
  stopJobPoll();
  $$('dialog[open]').forEach(d => d.close());
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
  $('#login-form').classList.toggle('hidden', isSetup);
  $('#setup-form').classList.toggle('hidden', !isSetup);
  $('#auth-title').innerHTML = isSetup ? '首次使用，<br>请设置管理员密码。' : '你的服务器，<br>一个入口管理。';
  $('#auth-desc').textContent = isSetup
    ? '此密码用于登录网页后台（后续可在 MCP 接入页签发独立 AI 令牌），需 8–1024 个非空白 ASCII 字符。'
    : '登录管理后台，配置 SSH 连接并为 AI 提供安全的调用入口。';
}
const showLogin = () => showAuthPanel(false);
const showSetup = () => showAuthPanel(true);

async function showApp() {
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  renderMcpSnippets();
  await Promise.all([loadSharedKeys(), loadServers(), loadCachedSnapshots(), loadTokens(), loadSnippets()]);
  updateMetrics();
  collectMissingSnapshots();
}

$('#login-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('#login-error').textContent = '';
  const b = e.submitter;
  b.disabled = true;
  try {
    await api('/api/login', { method: 'POST', body: { password: e.target.elements.namedItem('password').value } });
    e.target.reset();
    await showApp();
  } catch (err) {
    $('#login-error').textContent = err.message === '操作失败，请稍后重试。' ? '登录失败，请检查管理员密码。' : err.message;
  } finally { b.disabled = false; }
});

$('#setup-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('#setup-error').textContent = '';
  const f = e.target;
  const newPassword = f.elements.namedItem('newPassword').value;
  const confirmPassword = f.elements.namedItem('confirmPassword').value;
  if (newPassword !== confirmPassword) {
    $('#setup-error').textContent = '两次输入的密码不一致。';
    return;
  }
  const b = e.submitter;
  b.disabled = true;
  try {
    await api('/api/setup', { method: 'POST', body: { newPassword, confirmPassword } });
    f.reset();
    await showApp();
    toast('管理员密码已设置');
  } catch (err) {
    $('#setup-error').textContent = err.message;
  } finally { b.disabled = false; }
});

$('#logout').onclick = async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch {}
  showLogin();
};

function navigateTo(view) {
  const b = $(`.nav-item[data-view="${view}"]`);
  if (!b) return;
  b.click();
}

$$('.nav-item').forEach(b => b.onclick = async () => {
  const view = b.dataset.view;
  $$('.nav-item').forEach(x => x.classList.toggle('active', x === b));
  $$('.page').forEach(x => x.classList.add('hidden'));
  $('#view-' + view).classList.remove('hidden');
  $('#page-title').textContent = b.textContent.trim().replace(/\d+$/, '').trim();
  if (view === 'keys') await loadSharedKeys();
  if (view === 'files') await loadFiles();
  if (view === 'audit') await loadAudit(1);
  if (view === 'batch') { await loadSnippets(); renderBatchTargets(); }
  if (view === 'connect') { await loadTokens(); renderMcpSnippets(); }
  if (view === 'security') await loadSettings();
});

$$('[data-close]').forEach(b => b.onclick = () => {
  const dlg = $('#' + b.dataset.close);
  if (b.dataset.close === 'operation-dialog') { closeTerminal(); stopJobPoll(); }
  dlg.close();
});
$('#operation-dialog').addEventListener('close', () => { closeTerminal(); stopJobPoll(); });

// --- Metrics & Servers ---
function barClass(pct) {
  if (pct == null) return '';
  if (pct >= 90) return 'danger';
  if (pct >= 75) return 'warn';
  return '';
}

function updateMetrics() {
  $('#metric-total').textContent = servers.length;
  $('#nav-count').textContent = servers.length;

  const snaps = servers.map(s => snapshots.get(s.id)).filter(Boolean);
  if (snaps.length === 0) {
    $('#metric-online').textContent = '—';
    $('#metric-online').className = '';
    $('#metric-online-sub').textContent = '点击“刷新主机状态”采集指标';
    $('#metric-alerts').textContent = '0';
    $('#metric-alerts').className = 'ok';
  } else {
    const online = snaps.filter(x => x.online).length;
    $('#metric-online').textContent = `${online} / ${servers.length}`;
    $('#metric-online').className = online === servers.length ? 'ok' : (online === 0 ? 'danger' : 'warn');
    $('#metric-online-sub').textContent = `已采集 ${snaps.length} 台主机状态`;
    const alerts = snaps.filter(x => !x.online || (x.memPercent ?? 0) >= 85 || (x.diskPercent ?? 0) >= 85).length;
    $('#metric-alerts').textContent = alerts;
    $('#metric-alerts').className = alerts > 0 ? 'danger' : 'ok';
  }

  const activeTokens = tokens.filter(t => !t.revoked && (!t.expiresAt || new Date(t.expiresAt) > new Date())).length;
  $('#metric-tokens').textContent = activeTokens;
}

async function loadServers() {
  try {
    servers = await api('/api/servers');
    renderServers();
    updateMetrics();
  } catch (e) { toast(e.message); }
}

async function loadCachedSnapshots() {
  try {
    const list = await api('/api/servers/snapshots');
    snapshots.clear();
    list.forEach(s => snapshots.set(s.serverId, s));
    renderServers();
    updateMetrics();
  } catch {}
}

function fmtMemMb(mb) {
  if (mb == null) return '—';
  if (mb < 1024) return `${mb}M`;
  const gb = mb / 1024;
  return `${(gb >= 100 ? Math.round(gb) : gb.toFixed(1).replace(/\.0$/, ''))}G`;
}

function fmtDiskSize(mb, gbFallback) {
  if (mb != null) {
    if (mb >= 1048576) return `${(mb / 1048576).toFixed(1).replace(/\.0$/, '')}T`;
    return fmtMemMb(mb);
  }
  return gbFallback != null ? `${gbFallback}G` : '—';
}

function renderResBars(snap, serverId) {
  const isCollecting = collectingSnapshots.has(serverId);
  if (!snap) {
    return isCollecting
      ? '<span class="badge blue">采集中…</span>'
      : '<span class="server-sub">未采集</span>';
  }
  if (!snap.online) {
    return isCollecting
      ? '<span class="badge blue">采集中…</span>'
      : `<span class="badge danger" title="${escapeHtml(snap.error || '')}">离线</span>`;
  }
  const row = (label, pct, spec) => {
    const v = pct == null ? '—' : `${Math.round(pct)}%`;
    const w = pct == null ? 0 : Math.min(100, Math.max(0, pct));
    return `<div class="res-row"><span>${label}</span><div class="res-track"><div class="res-fill ${barClass(pct)}" style="width:${w}%"></div></div><span class="res-val">${v}</span><span class="res-spec">${escapeHtml(spec)}</span></div>`;
  };
  const cpuSpec = snap.cpuCores != null ? `${snap.cpuCores}核` : '—';
  const memSpec = snap.memTotalMb ? `${fmtMemMb(snap.memUsedMb)} / ${fmtMemMb(snap.memTotalMb)}` : '—';
  const diskSpec = (snap.diskTotalMb || snap.diskTotalGb)
    ? `${fmtDiskSize(snap.diskUsedMb, snap.diskUsedGb)} / ${fmtDiskSize(snap.diskTotalMb, snap.diskTotalGb)}`
    : '—';
  const tip = `负载: ${snap.loadAverage || '—'} · 运行: ${snap.uptime || '—'} · 采集于 ${fmtDate(snap.checkedAt)}`;
  return `<div class="res-bars${isCollecting ? ' refreshing' : ''}" title="${escapeHtml(tip)}">${row('CPU', snap.cpuPercent, cpuSpec)}${row('内存', snap.memPercent, memSpec)}${row('磁盘', snap.diskPercent, diskSpec)}</div>`;
}

async function collectSnapshots(ids, { silent = false } = {}) {
  const queue = [...new Set(ids)].filter(id => id && !collectingSnapshots.has(id));
  if (!queue.length) return;
  queue.forEach(id => collectingSnapshots.add(id));
  renderServers();
  let done = 0;
  const worker = async () => {
    while (queue.length) {
      const id = queue.shift();
      try {
        const s = await api(`/api/servers/${id}/snapshot`, { method: 'POST' });
        snapshots.set(s.serverId, s);
        done++;
      } catch {
      } finally {
        collectingSnapshots.delete(id);
        renderServers();
        updateMetrics();
        if (selected?.id === id) renderSnapshotTab();
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(4, Math.max(1, ids.length)) }, worker));
  if (!silent) toast(`已刷新 ${done} 台主机状态`);
}

function collectMissingSnapshots() {
  const missing = servers.filter(s => !snapshots.has(s.id)).map(s => s.id);
  if (missing.length) collectSnapshots(missing, { silent: true });
}

function renderServers() {
  const q = $('#search').value.trim().toLowerCase();
  const byId = new Map(servers.map(s => [s.id, s.name]));
  const keyById = new Map(sharedKeys.map(k => [k.id, k.name]));
  const filtered = servers.filter(s => [s.name, s.host, s.tags, s.notes].some(v => (v || '').toLowerCase().includes(q)));
  $('#empty-servers').classList.toggle('hidden', servers.length > 0);
  $('#server-rows').innerHTML = filtered.map(s => {
    const snap = snapshots.get(s.id);
    const dotCls = snap ? (snap.online ? 'online' : 'offline') : '';
    const jumpName = s.jumpServerId ? byId.get(s.jumpServerId) : null;
    const sharedKeyName = s.sharedKeyId ? keyById.get(s.sharedKeyId) : null;
    const latency = snap?.online ? `<span class="badge blue">${snap.latencyMs}ms</span>` : '';
    return `<tr>
      <td>
        <div class="server-cell">
          <div class="server-icon">${lineIcon('server')}<span class="status-dot ${dotCls}"></span></div>
          <div>
            <div class="server-name">${escapeHtml(s.name)}${jumpName ? `<span class="badge blue">跳板: ${escapeHtml(jumpName)}</span>` : ''}</div>
            <div class="server-sub">${escapeHtml(s.notes || (snap?.osName || 'SSH 主机'))}</div>
          </div>
        </div>
      </td>
      <td>
        <div class="mono" style="font-size:12.5px">${escapeHtml(s.username)}@${escapeHtml(s.host)}:${s.port}</div>
        <div class="server-sub">
          ${sharedKeyName ? `<span class="badge blue">密钥: ${escapeHtml(sharedKeyName)}</span>` : `<span class="badge key">${s.authType === 'password' ? '密码' : '独立私钥'}</span>`}
          ${s.useServiceKey ? '<span class="badge">服务端密钥</span>' : ''}
          ${s.proxy ? '<span class="badge">代理</span>' : ''}
          ${latency}
        </div>
      </td>
      <td>${renderResBars(snap, s.id)}</td>
      <td>${(s.tags || '').split(',').filter(Boolean).map(t => `<span class="badge">${escapeHtml(t.trim())}</span>`).join('') || '<span class="server-sub">—</span>'}</td>
      <td>
        <div class="row-actions">
          <button class="link-button pill-primary" data-action="terminal" data-id="${s.id}">终端</button>
          <button class="link-button" data-action="sftp" data-id="${s.id}">文件</button>
          <button class="link-button secondary-action" data-action="operate" data-id="${s.id}">工作台</button>
          <button class="link-button secondary-action" data-action="test" data-id="${s.id}">测试</button>
          <button class="link-button secondary-action" data-action="edit" data-id="${s.id}">编辑</button>
          <button class="link-button danger" data-action="delete" data-id="${s.id}">删除</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

$('#search').oninput = renderServers;
$('#refresh-servers').onclick = async () => {
  await Promise.all([loadServers(), loadCachedSnapshots()]);
  collectMissingSnapshots();
};
$('#refresh-all-snapshots').onclick = async e => {
  if (!servers.length) return toast('暂无可采集的服务器');
  const b = e.target;
  b.disabled = true;
  toast('正在并发采集全部主机状态…');
  try {
    await collectSnapshots(servers.map(s => s.id));
  } finally { b.disabled = false; }
};

// --- Add / Edit Server Modal & Standalone SSH Key Management ---
function authFields() {
  const f = $('#server-form').elements;
  const isKey = f.namedItem('authType').value === 'privateKey';
  $('#key-fields').classList.toggle('hidden', !isKey);
  $('#password-fields').classList.toggle('hidden', isKey);
  const usingShared = isKey && !!$('#shared-key-select').value;
  $('#manual-key-fields').classList.toggle('hidden', usingShared);
}
$('#server-form').elements.namedItem('authType').onchange = authFields;
$('#shared-key-select').onchange = authFields;
$('#goto-keys-page').onclick = () => {
  $('#server-dialog').close();
  navigateTo('keys');
};

async function loadSharedKeys(selectedId = null) {
  try {
    sharedKeys = await api('/api/keys');
    $('#nav-keys-count').textContent = sharedKeys.length;
    $('#metric-keys-total').textContent = sharedKeys.length;
    const boundCount = sharedKeys.reduce((acc, k) => acc + (k.serverNames?.length || 0), 0);
    $('#metric-keys-bound').textContent = boundCount;
    const select = $('#shared-key-select');
    const prevVal = selectedId !== null ? selectedId : select.value;
    select.innerHTML = '<option value="">不使用密钥库（手动填写本机专用私钥）</option>' +
      sharedKeys.map(k => `<option value="${escapeHtml(k.id)}">${escapeHtml(k.name)} [${escapeHtml(k.algorithm || 'KEY')}]</option>`).join('');
    select.value = prevVal || '';
    authFields();
    renderSharedKeys();
    if (servers.length) renderServers();
  } catch (err) { toast(err.message); }
}

function renderSharedKeys() {
  const q = ($('#key-search')?.value || '').trim().toLowerCase();
  const filtered = sharedKeys.filter(k => [k.name, k.algorithm, k.fingerprint, k.notes, ...(k.serverNames || [])].some(v => (v || '').toLowerCase().includes(q)));
  $('#empty-keys').classList.toggle('hidden', sharedKeys.length > 0);
  $('#key-rows').innerHTML = filtered.map(k => {
    const names = k.serverNames || [];
    const boundHtml = names.length
      ? names.slice(0, 3).map(n => `<span class="badge blue">${escapeHtml(n)}</span>`).join('') + (names.length > 3 ? `<span class="badge">+${names.length - 3}</span>` : '')
      : '<span class="server-sub">暂未绑定</span>';
    return `<tr>
      <td>
        <div class="server-name">${escapeHtml(k.name)}${k.hasPassphrase ? '<span class="badge warn">带口令</span>' : ''}</div>
        <div class="server-sub">${escapeHtml(k.notes || '无备注')}</div>
      </td>
      <td>
        <div><span class="badge blue">${escapeHtml(k.algorithm || 'SSH')}</span></div>
        <div class="mono server-sub" title="${escapeHtml(k.fingerprint)}">${escapeHtml(k.fingerprint || '—')}</div>
      </td>
      <td>${boundHtml}</td>
      <td style="font-size:12px;white-space:nowrap">${fmtDate(k.updatedAt || k.createdAt)}</td>
      <td>
        <div class="row-actions">
          <button type="button" class="link-button pill-primary" data-key-copy="${k.id}">复制公钥</button>
          <button type="button" class="link-button" data-key-deploy="${k.id}">下发公钥</button>
          <button type="button" class="link-button secondary-action" data-key-edit="${k.id}">编辑 / 轮换</button>
          <button type="button" class="link-button danger" data-key-del="${k.id}">删除</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

$('#key-search').oninput = renderSharedKeys;
$('#refresh-keys').onclick = () => loadSharedKeys();

function showNewKeyBanner(k) {
  lastCreatedKey = k;
  $('#new-key-banner-title').textContent = `密钥「${k.name}」已保存（${k.algorithm} · ${k.fingerprint}）`;
  $('#new-key-pub').textContent = k.publicKey || '';
  $('#new-key-banner').classList.remove('hidden');
}

$('#copy-new-key-pub').onclick = () => { if (lastCreatedKey?.publicKey) copyText(lastCreatedKey.publicKey, '公钥已复制'); };
$('#deploy-new-key-btn').onclick = () => { if (lastCreatedKey) openDeployKeyDialog(lastCreatedKey); };

function openGenerateKeyDialog() {
  $('#key-generate-form').reset();
  $('#key-gen-error').textContent = '';
  $('#key-generate-dialog').showModal();
}
$('#open-generate-key').onclick = openGenerateKeyDialog;
$('#empty-gen-key').onclick = openGenerateKeyDialog;

$('#key-generate-form').onsubmit = async e => {
  e.preventDefault();
  const f = e.target, b = e.submitter;
  b.disabled = true;
  $('#key-gen-error').textContent = '';
  try {
    const data = Object.fromEntries(new FormData(f));
    const created = await api('/api/keys/generate', { method: 'POST', body: data });
    $('#key-generate-dialog').close();
    showNewKeyBanner(created);
    await loadSharedKeys();
    toast('密钥对已生成并加密保存');
  } catch (err) { $('#key-gen-error').textContent = err.message; }
  finally { b.disabled = false; }
};

function openEditKeyDialog(k = null) {
  const f = $('#key-edit-form');
  f.reset();
  $('#key-edit-error').textContent = '';
  f.elements.namedItem('id').value = k?.id || '';
  f.elements.namedItem('name').value = k?.name || '';
  f.elements.namedItem('notes').value = k?.notes || '';
  $('#key-edit-title').textContent = k ? `编辑 / 轮换密钥：${k.name}` : '导入已有私钥';
  $('#key-edit-desc').textContent = k
    ? '可修改名称和备注；如填写新私钥将立即轮换，所有已绑定服务器自动生效。'
    : '上传私钥文件或粘贴私钥内容，服务端将自动提取算法、公钥与 SHA-256 指纹。';
  $('#key-edit-req').classList.toggle('hidden', !!k);
  f.elements.namedItem('privateKey').placeholder = k ? '留空表示保留当前私钥；填写新私钥将轮换覆盖' : '粘贴 -----BEGIN OPENSSH PRIVATE KEY----- 或 PEM 私钥内容';
  $('#key-edit-dialog').showModal();
}
$('#open-import-key').onclick = () => openEditKeyDialog();
$('#empty-imp-key').onclick = () => openEditKeyDialog();

$('#key-edit-file').onchange = async e => {
  const file = e.target.files[0];
  if (!file) return;
  if (file.size > 65536) { toast('私钥文件不能超过 64 KiB'); e.target.value = ''; return; }
  $('#key-edit-form').elements.namedItem('privateKey').value = await file.text();
  if (!$('#key-edit-form').elements.namedItem('name').value.trim()) {
    $('#key-edit-form').elements.namedItem('name').value = file.name.replace(/\.[^.]+$/, '');
  }
};

$('#key-edit-form').onsubmit = async e => {
  e.preventDefault();
  const f = e.target, id = f.elements.namedItem('id').value, b = e.submitter;
  b.disabled = true;
  $('#key-edit-error').textContent = '';
  try {
    const data = Object.fromEntries(new FormData(f));
    delete data.id;
    const saved = await api('/api/keys' + (id ? '/' + encodeURIComponent(id) : ''), { method: id ? 'PUT' : 'POST', body: data });
    $('#key-edit-dialog').close();
    if (!id || data.privateKey?.trim()) showNewKeyBanner(saved);
    await loadSharedKeys();
    toast(id ? (data.privateKey?.trim() ? '密钥已轮换，已绑定服务器自动生效' : '密钥信息已更新') : '私钥已导入并加密保存');
  } catch (err) { $('#key-edit-error').textContent = err.message; }
  finally { b.disabled = false; }
};

function openDeployKeyDialog(k) {
  $('#deploy-key-id').value = k.id;
  $('#key-deploy-subtitle').textContent = `密钥「${k.name}」(${k.algorithm} · ${k.fingerprint})`;
  $('#deploy-key-pub').textContent = k.publicKey || '';
  $('#deploy-bind-after').checked = false;
  $('#deploy-results').innerHTML = '';
  $('#deploy-targets').innerHTML = servers.length
    ? servers.map(s => `<label class="target-chip"><input type="checkbox" name="deployServer" value="${s.id}" ${s.sharedKeyId === k.id ? '' : ''}>${escapeHtml(s.name)} <small style="display:inline;margin:0;color:var(--muted)">(${escapeHtml(s.username)}@${escapeHtml(s.host)})</small></label>`).join('')
    : '<span class="footnote">暂无可用服务器，请先添加服务器。</span>';
  $('#key-deploy-dialog').showModal();
}

$('#copy-deploy-pub').onclick = () => copyText($('#deploy-key-pub').textContent, '公钥已复制');
$('#deploy-select-all').onclick = () => $$('input[name="deployServer"]').forEach(c => c.checked = true);
$('#deploy-select-none').onclick = () => $$('input[name="deployServer"]').forEach(c => c.checked = false);

$('#key-deploy-form').onsubmit = async e => {
  e.preventDefault();
  const keyId = $('#deploy-key-id').value;
  const serverIds = $$('input[name="deployServer"]:checked').map(c => c.value);
  if (!serverIds.length) return toast('请至少选择一台目标服务器');
  const bindAfterDeploy = $('#deploy-bind-after').checked;
  const b = e.submitter;
  b.disabled = true;
  $('#deploy-results').innerHTML = '<p class="footnote">正在向所选主机下发公钥…</p>';
  try {
    const r = await api(`/api/keys/${encodeURIComponent(keyId)}/deploy`, { method: 'POST', body: { serverIds, bindAfterDeploy } });
    $('#deploy-results').innerHTML = r.results.map(item => `<div class="batch-card">
      <div class="batch-card-head">
        <strong>${escapeHtml(item.serverName)}</strong>
        <span class="badge ${item.success ? 'ok' : 'danger'}">${item.success ? (item.alreadyInstalled ? '已存在' : '下发成功') : '失败'}</span>
      </div>
      <div style="padding:10px 14px;font-size:12.5px;color:var(--ink-secondary)">${escapeHtml(item.message)}</div>
    </div>`).join('');
    if (bindAfterDeploy) await Promise.all([loadServers(), loadSharedKeys()]);
    toast(`公钥下发完成：成功 ${r.succeeded} / ${r.total}`);
  } catch (err) {
    $('#deploy-results').innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  } finally { b.disabled = false; }
};

$('#key-rows').onclick = async e => {
  const copyBtn = e.target.closest('[data-key-copy]');
  if (copyBtn) {
    const k = sharedKeys.find(x => x.id === copyBtn.dataset.keyCopy);
    if (k?.publicKey) copyText(k.publicKey, `已复制「${k.name}」的公钥`);
    return;
  }
  const depBtn = e.target.closest('[data-key-deploy]');
  if (depBtn) {
    const k = sharedKeys.find(x => x.id === depBtn.dataset.keyDeploy);
    if (k) openDeployKeyDialog(k);
    return;
  }
  const editBtn = e.target.closest('[data-key-edit]');
  if (editBtn) {
    const k = sharedKeys.find(x => x.id === editBtn.dataset.keyEdit);
    if (k) openEditKeyDialog(k);
    return;
  }
  const delBtn = e.target.closest('[data-key-del]');
  if (delBtn) {
    const k = sharedKeys.find(x => x.id === delBtn.dataset.keyDel);
    if (!k) return;
    if (!confirm(`确认永久删除共享密钥「${k.name}」？`)) return;
    try {
      await api('/api/keys/' + encodeURIComponent(k.id), { method: 'DELETE' });
      await loadSharedKeys();
      toast('共享密钥已删除');
    } catch (err) { toast(err.message); }
  }
};

$('#probe-host').onclick = async e => {
  const x = $('#server-form').elements;
  e.target.disabled = true;
  lastProbeFp = '';
  $('#apply-probe-fp').classList.add('hidden');
  $('#probe-result').textContent = '正在获取候选指纹…';
  try {
    const r = await api('/api/servers/probe', { method: 'POST', body: { host: x.namedItem('host').value, port: Number(x.namedItem('port').value) } });
    lastProbeFp = r.fingerprint;
    $('#probe-result').textContent = `${r.algorithm}  ${r.fingerprint}。请通过可信渠道核对无误后再使用。`;
    $('#apply-probe-fp').classList.remove('hidden');
  } catch (err) {
    $('#probe-result').textContent = err.message;
  } finally { e.target.disabled = false; }
};

$('#apply-probe-fp').onclick = () => {
  if (lastProbeFp) $('#server-form').elements.namedItem('hostFingerprint').value = lastProbeFp;
};

function populateJumpSelect(currentServerId = '', selectedJumpId = '') {
  const sel = $('#jump-server-select');
  sel.innerHTML = '<option value="">直连（不使用跳板机）</option>' +
    servers.filter(s => s.id !== currentServerId)
      .map(s => `<option value="${escapeHtml(s.id)}">${escapeHtml(s.name)} (${escapeHtml(s.host)}:${s.port})</option>`).join('');
  sel.value = selectedJumpId || '';
}

function editServer(s, prefill = null) {
  const f = $('#server-form'), x = f.elements;
  f.reset();
  lastProbeFp = '';
  $('#apply-probe-fp').classList.add('hidden');
  $('#probe-result').textContent = '';
  const src = s || prefill || {};
  for (const [name, value] of Object.entries({
    id: s?.id || '',
    name: src.name || '',
    host: src.host || '',
    port: src.port || 22,
    username: src.username || '',
    authType: src.authType || 'privateKey',
    hostFingerprint: src.hostFingerprint || '',
    tags: src.tags || '',
    notes: src.notes || '',
    proxy: src.proxy || '',
    allowedRemotePaths: src.allowedRemotePaths || ''
  })) x.namedItem(name).value = value;
  x.namedItem('tryKeyboard').checked = !!s?.tryKeyboard;
  x.namedItem('useServiceKey').checked = !!s?.useServiceKey;
  $('#server-dialog-title').textContent = s ? '编辑服务器' : '添加服务器';
  $('#server-error').textContent = '';
  x.namedItem('privateKey').placeholder = s ? '留空以保留原私钥' : '粘贴私钥内容，仅在服务器端加密保存';
  x.namedItem('password').placeholder = s ? '留空以保留原密码' : '仅在服务器端加密保存';
  populateJumpSelect(s?.id || '', src.jumpServerId || '');
  loadSharedKeys(s?.sharedKeyId || '').then(() => authFields()).catch(err => toast(err.message));
  authFields();
  $('#server-dialog').showModal();
}

$('#add-server').onclick = () => editServer();
$('#empty-add').onclick = () => editServer();

$('#server-form').onsubmit = async e => {
  e.preventDefault();
  const f = e.target, id = f.elements.namedItem('id').value, b = e.submitter;
  b.disabled = true;
  $('#server-error').textContent = '';
  try {
    const data = Object.fromEntries(new FormData(f));
    data.port = Number(data.port);
    data.tryKeyboard = data.tryKeyboard === 'on';
    data.useServiceKey = data.useServiceKey === 'on';
    delete data.id;
    const saved = await api('/api/servers' + (id ? '/' + id : ''), { method: id ? 'PUT' : 'POST', body: data });
    f.reset();
    $('#server-dialog').close();
    await Promise.all([loadServers(), loadSharedKeys()]);
    toast('服务器已保存');
    if (saved?.id) collectSnapshots([saved.id], { silent: true });
  } catch (err) {
    $('#server-error').textContent = err.message;
  } finally { b.disabled = false; }
};

// --- Import ~/.ssh/config ---
$('#open-import-ssh').onclick = () => {
  $('#ssh-config-file').value = '';
  $('#ssh-config-text').value = '';
  $('#import-preview').classList.add('hidden');
  $('#import-rows').innerHTML = '';
  $('#import-dialog').showModal();
};

$('#ssh-config-file').onchange = async e => {
  const file = e.target.files[0];
  if (!file) return;
  $('#ssh-config-text').value = await file.text();
};

$('#parse-ssh-config').onclick = async e => {
  const configText = $('#ssh-config-text').value;
  if (!configText.trim()) return toast('请先粘贴或选择 SSH 配置文件');
  e.target.disabled = true;
  try {
    const res = await api('/api/servers/import-ssh-config', { method: 'POST', body: { configText } });
    parsedImportHosts = res.hosts || [];
    if (!parsedImportHosts.length) return toast('未解析到有效 Host 条目');
    $('#import-preview').classList.remove('hidden');
    $('#import-rows').innerHTML = parsedImportHosts.map((h, i) => `<tr>
      <td><strong>${escapeHtml(h.name)}</strong>${h.alreadyExists ? ' <span class="badge warn">已存在</span>' : ''}</td>
      <td class="mono">${escapeHtml(h.host)}:${h.port}</td>
      <td>${escapeHtml(h.username)}</td>
      <td>${escapeHtml(h.proxyJump || '—')}</td>
      <td><button type="button" class="link-button" data-import-idx="${i}">填入表单</button></td>
    </tr>`).join('');
  } catch (err) { toast(err.message); }
  finally { e.target.disabled = false; }
};

$('#import-rows').onclick = e => {
  const btn = e.target.closest('button[data-import-idx]');
  if (!btn) return;
  const h = parsedImportHosts[Number(btn.dataset.importIdx)];
  if (!h) return;
  const jumpMatch = h.proxyJump ? servers.find(s => s.name.toLowerCase() === h.proxyJump.toLowerCase()) : null;
  $('#import-dialog').close();
  editServer(null, {
    name: h.name,
    host: h.host,
    port: h.port,
    username: h.username,
    jumpServerId: jumpMatch?.id || '',
    notes: h.identityFile ? `IdentityFile: ${h.identityFile}` : ''
  });
};

// --- Server Row Actions & Workspace Modal ---
function openWorkspace(s, initialTab = 'terminal') {
  selected = s;
  $('#operation-form').reset();
  $('#operation-dialog').classList.remove('fullscreen');
  $('#toggle-workspace-fullscreen').textContent = '全屏';
  $('#operation-title').textContent = s.name;
  $('#operation-subtitle').textContent = `${s.username}@${s.host}:${s.port}`;
  $('#command-result').textContent = '执行结果将显示在这里。';
  $('#transfer-result').textContent = '';
  $('#job-result').textContent = '';
  $('#job-output').textContent = '选中任务的状态和输出将显示在这里。';
  $('#sftp-editor').classList.add('hidden');
  populateSnippetDropdowns();
  loadStagingDatalist();
  $('#operation-dialog').showModal();
  switchWorkspaceTab(initialTab);
}

function switchWorkspaceTab(tab) {
  if (tab !== 'jobs') stopJobPoll();
  $$('[data-tab]').forEach(x => x.classList.toggle('active', x.dataset.tab === tab));
  ['terminal', 'sftp', 'command', 'jobs', 'snapshot', 'transfer'].forEach(t =>
    $('#tab-' + t).classList.toggle('hidden', t !== tab));

  if (tab === 'terminal') {
    if (!termWs || termWs.readyState > 1) connectTerminal();
    else fitTerminal();
  }
  if (tab === 'sftp') loadSftpDir(currentSftpPath || '/');
  if (tab === 'jobs') loadJobs();
  if (tab === 'snapshot') renderSnapshotTab();
}

$$('[data-tab]').forEach(b => b.onclick = () => switchWorkspaceTab(b.dataset.tab));

$('#toggle-workspace-fullscreen').onclick = e => {
  const dlg = $('#operation-dialog');
  const full = dlg.classList.toggle('fullscreen');
  e.target.textContent = full ? '退出全屏' : '全屏';
  setTimeout(fitTerminal, 80);
};

$('#server-rows').onclick = async e => {
  const b = e.target.closest('button');
  if (!b) return;
  const s = servers.find(x => x.id === b.dataset.id);
  if (!s) return;
  try {
    if (b.dataset.action === 'edit') editServer(s);
    if (b.dataset.action === 'terminal') openWorkspace(s, 'terminal');
    if (b.dataset.action === 'sftp') { currentSftpPath = s.allowedRemotePaths.split('\n').filter(Boolean)[0] || '/'; openWorkspace(s, 'sftp'); }
    if (b.dataset.action === 'operate') openWorkspace(s, 'command');
    if (b.dataset.action === 'test') {
      b.disabled = true;
      const r = await api(`/api/servers/${s.id}/test`, { method: 'POST' });
      toast(`连接成功，延迟 ${r.latencyMs}ms，主机指纹匹配`);
    }
    if (b.dataset.action === 'delete' && confirm(`确认删除服务器「${s.name}」？此操作不会影响远端主机。`)) {
      await api(`/api/servers/${s.id}`, { method: 'DELETE' });
      snapshots.delete(s.id);
      await Promise.all([loadServers(), loadSharedKeys()]);
      toast('服务器已删除');
    }
  } catch (err) { toast(err.message); }
  finally { b.disabled = false; }
};

// --- WebSSH Terminal (xterm.js + WebSocket) ---
let termFontSize = 14;

function setTermStatus(text, cls = '') {
  const el = $('#term-status');
  if (!el) return;
  el.innerHTML = `<i></i>${escapeHtml(text)}`;
  el.className = 'term-pill' + (cls ? ' ' + cls : '');
}

function sendTermResize() {
  if (!termWs || termWs.readyState !== WebSocket.OPEN || !xterm) return;
  termWs.send(JSON.stringify({ type: 'resize', cols: xterm.cols, rows: xterm.rows }));
}

function fitTerminal() {
  if (!fitAddon || !xterm || $('#tab-terminal').classList.contains('hidden')) return;
  requestAnimationFrame(() => {
    try {
      fitAddon.fit();
      sendTermResize();
    } catch {}
  });
}

function closeTerminal() {
  if (termResizeObserver) { termResizeObserver.disconnect(); termResizeObserver = null; }
  if (termWs) { try { termWs.close(); } catch {} termWs = null; }
  if (xterm) { try { xterm.dispose(); } catch {} xterm = null; fitAddon = null; }
  setTermStatus('未连接', '');
}

function connectTerminal() {
  if (!selected) return;
  closeTerminal();
  const container = $('#xterm-container');
  container.innerHTML = '';

  if (typeof Terminal === 'undefined') {
    container.textContent = '终端组件加载失败，请刷新页面重试。';
    return;
  }

  xterm = new Terminal({
    cursorBlink: true,
    cursorStyle: 'bar',
    fontSize: termFontSize,
    lineHeight: 1.28,
    scrollback: 5000,
    fontFamily: '"Cascadia Code", Consolas, "JetBrains Mono", ui-monospace, monospace',
    theme: {
      background: '#0f172a',
      foreground: '#e2ecfb',
      cursor: '#60a5fa',
      cursorAccent: '#0f172a',
      selectionBackground: 'rgba(59, 130, 246, 0.35)',
      black: '#1e293b', red: '#f87171', green: '#34d399', yellow: '#fbbf24',
      blue: '#60a5fa', magenta: '#c084fc', cyan: '#22d3ee', white: '#e2e8f0',
      brightBlack: '#475569', brightRed: '#fca5a5', brightGreen: '#6ee7b7', brightYellow: '#fde68a',
      brightBlue: '#93c5fd', brightMagenta: '#d8b4fe', brightCyan: '#67e8f9', brightWhite: '#f8fafc'
    }
  });
  fitAddon = new FitAddon.FitAddon();
  xterm.loadAddon(fitAddon);
  xterm.open(container);
  try { fitAddon.fit(); } catch {}

  const cols = xterm.cols || 120;
  const rows = xterm.rows || 32;
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${location.host}/api/servers/${encodeURIComponent(selected.id)}/terminal?cols=${cols}&rows=${rows}`;
  setTermStatus('连接中…', 'blue');

  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';
  termWs = ws;

  ws.onopen = () => {
    setTermStatus('已连接', 'ok');
    fitTerminal();
    setTimeout(fitTerminal, 150);
    xterm.focus();
  };
  ws.onmessage = ev => {
    if (ev.data instanceof ArrayBuffer) xterm?.write(new Uint8Array(ev.data));
    else if (typeof ev.data === 'string') xterm?.write(ev.data);
  };
  ws.onerror = () => setTermStatus('连接异常', 'danger');
  ws.onclose = () => {
    if (termWs === ws) setTermStatus('已断开', 'warn');
  };

  xterm.onData(data => {
    if (ws.readyState === WebSocket.OPEN) ws.send(textEncoder.encode(data));
  });
  xterm.onResize(() => sendTermResize());

  termResizeObserver = new ResizeObserver(() => fitTerminal());
  termResizeObserver.observe(container);
  setTimeout(fitTerminal, 80);
}

$('#term-reconnect').onclick = connectTerminal;
$('#term-clear').onclick = () => xterm?.clear();
$('#term-font-dec').onclick = () => {
  termFontSize = Math.max(11, termFontSize - 1);
  if (xterm) { xterm.options.fontSize = termFontSize; fitTerminal(); }
};
$('#term-font-inc').onclick = () => {
  termFontSize = Math.min(20, termFontSize + 1);
  if (xterm) { xterm.options.fontSize = termFontSize; fitTerminal(); }
};
$('#term-send-snippet').onclick = () => {
  const cmd = $('#term-snippet-select').value;
  if (!cmd) return toast('请先选择命令片段');
  if (!termWs || termWs.readyState !== WebSocket.OPEN) return toast('终端尚未连接');
  termWs.send(textEncoder.encode(cmd + '\n'));
  xterm?.focus();
};

// --- Visual SFTP File Browser ---
function renderBreadcrumbs(path) {
  const parts = path.split('/').filter(Boolean);
  let html = `<button type="button" data-crumb="/">/</button>`;
  let acc = '';
  for (const p of parts) {
    acc += '/' + p;
    html += `<span>/</span><button type="button" data-crumb="${escapeHtml(acc)}">${escapeHtml(p)}</button>`;
  }
  $('#sftp-breadcrumbs').innerHTML = html;
}

async function loadSftpDir(path) {
  if (!selected) return;
  const target = (path || '/').trim() || '/';
  $('#sftp-status').textContent = '加载目录中…';
  try {
    const r = await api(`/api/servers/${selected.id}/sftp/list`, { method: 'POST', body: { remotePath: target } });
    currentSftpPath = r.path;
    $('#sftp-path').value = r.path;
    $('#sftp-up').disabled = !r.parentPath;
    $('#sftp-up').dataset.parent = r.parentPath || '';
    renderBreadcrumbs(r.path);
    $('#sftp-rows').innerHTML = r.entries.length
      ? r.entries.map(e => `<tr>
          <td>
            <button type="button" class="link-button" style="display:inline-flex;align-items:center;gap:7px;padding:2px 4px" data-sftp-open="${escapeHtml(e.fullPath)}" data-is-dir="${e.isDirectory}">
              ${lineIcon(e.isDirectory ? 'folder' : 'file')}
              <span>${escapeHtml(e.name)}${e.isSymlink ? ' →' : ''}</span>
            </button>
          </td>
          <td>${e.isDirectory ? '—' : fmtBytes(e.size)}</td>
          <td class="mono" style="font-size:12px">${escapeHtml(e.permissions)}</td>
          <td style="font-size:12px">${fmtDate(e.modifiedAt)}</td>
          <td>
            <div class="row-actions">
              ${!e.isDirectory ? `<button type="button" class="link-button" data-sftp-edit="${escapeHtml(e.fullPath)}">编辑</button><a class="link-button secondary-action" href="/api/servers/${selected.id}/sftp/download?path=${encodeURIComponent(e.fullPath)}">下载</a>` : ''}
              <button type="button" class="link-button secondary-action" data-sftp-rename="${escapeHtml(e.fullPath)}" data-name="${escapeHtml(e.name)}">重命名</button>
              <button type="button" class="link-button danger" data-sftp-del="${escapeHtml(e.fullPath)}" data-is-dir="${e.isDirectory}">删除</button>
            </div>
          </td>
        </tr>`).join('')
      : '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:26px">目录为空</td></tr>';
    $('#sftp-status').textContent = `共 ${r.entries.length} 项。支持拖拽文件到此区域直接上传。`;
  } catch (err) {
    $('#sftp-status').textContent = err.message;
    toast(err.message);
  }
}

$('#sftp-go').onclick = () => loadSftpDir($('#sftp-path').value);
$('#sftp-path').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); loadSftpDir($('#sftp-path').value); } });
$('#sftp-refresh').onclick = () => loadSftpDir(currentSftpPath);
$('#sftp-up').onclick = () => { if ($('#sftp-up').dataset.parent) loadSftpDir($('#sftp-up').dataset.parent); };
$('#sftp-breadcrumbs').onclick = e => {
  const b = e.target.closest('button[data-crumb]');
  if (b) loadSftpDir(b.dataset.crumb);
};

$('#sftp-mkdir').onclick = async () => {
  if (!selected) return;
  const name = prompt('输入新文件夹名称：');
  if (!name || !name.trim()) return;
  const full = currentSftpPath === '/' ? '/' + name.trim() : currentSftpPath + '/' + name.trim();
  try {
    await api(`/api/servers/${selected.id}/sftp/mkdir`, { method: 'POST', body: { remotePath: full } });
    toast('目录已创建');
    await loadSftpDir(currentSftpPath);
  } catch (err) { toast(err.message); }
};

async function directUploadFile(file) {
  if (!selected || !file) return;
  const form = new FormData();
  form.append('file', file);
  form.append('directory', currentSftpPath);
  form.append('overwrite', 'true');
  $('#sftp-status').textContent = `正在上传 ${file.name}…`;
  try {
    const r = await api(`/api/servers/${selected.id}/sftp/upload`, { method: 'POST', body: form });
    toast(`已上传 ${file.name} (${fmtBytes(r.bytes)})`);
    await loadSftpDir(currentSftpPath);
  } catch (err) {
    $('#sftp-status').textContent = err.message;
    toast(err.message);
  }
}

$('#sftp-direct-file').onchange = async e => {
  const f = e.target.files[0];
  e.target.value = '';
  if (f) await directUploadFile(f);
};

const dropzone = $('#sftp-dropzone');
dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', async e => {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  for (const f of [...(e.dataTransfer?.files || [])]) await directUploadFile(f);
});

async function openInlineEditor(remotePath) {
  if (!selected) return;
  editorPath = remotePath;
  textIncomplete = true;
  $('#editor-file-path').textContent = remotePath;
  $('#editor-meta').textContent = '读取中…';
  $('#text-result').textContent = '';
  $('#text-append').checked = false;
  $('#sftp-editor').classList.remove('hidden');
  try {
    const r = await api(`/api/servers/${selected.id}/read-file`, { method: 'POST', body: { remotePath, offset: 0, length: 524288 } });
    textIncomplete = r.isBinary || r.nextOffset != null;
    if (r.isBinary) {
      $('#text-content').value = '';
      $('#editor-meta').textContent = '二进制文件，请直接下载。';
    } else {
      $('#text-content').value = r.content;
      $('#editor-meta').textContent = `${fmtBytes(r.size)}${textIncomplete ? '（未完整读取，仅支持追加写入）' : ''}`;
    }
  } catch (err) {
    $('#editor-meta').textContent = err.message;
  }
}

$('#close-editor').onclick = () => $('#sftp-editor').classList.add('hidden');
$('#write-text').onclick = async e => {
  if (!selected || !editorPath) return;
  const append = $('#text-append').checked;
  if (textIncomplete && !append) return toast('文件未完整读取，不能覆盖写入');
  if (!confirm(`确认${append ? '追加到' : '覆盖保存'} ${editorPath}？`)) return;
  e.target.disabled = true;
  try {
    const r = await api(`/api/servers/${selected.id}/write-file`, { method: 'POST', body: { remotePath: editorPath, content: $('#text-content').value, append } });
    $('#text-result').textContent = `已写入 ${fmtBytes(r.bytes)}${r.appended ? '（追加）' : ''}。`;
    toast('文件已保存');
    await loadSftpDir(currentSftpPath);
  } catch (err) {
    $('#text-result').textContent = err.message;
  } finally { e.target.disabled = false; }
};

$('#sftp-rows').onclick = async e => {
  const openBtn = e.target.closest('[data-sftp-open]');
  if (openBtn) {
    const path = openBtn.dataset.sftpOpen;
    if (openBtn.dataset.isDir === 'true') await loadSftpDir(path);
    else await openInlineEditor(path);
    return;
  }
  const editBtn = e.target.closest('[data-sftp-edit]');
  if (editBtn) { await openInlineEditor(editBtn.dataset.sftpEdit); return; }

  const renBtn = e.target.closest('[data-sftp-rename]');
  if (renBtn) {
    const oldPath = renBtn.dataset.sftpRename;
    const nextName = prompt('输入新名称：', renBtn.dataset.name);
    if (!nextName || !nextName.trim() || nextName.trim() === renBtn.dataset.name) return;
    const parent = oldPath.slice(0, oldPath.lastIndexOf('/')) || '/';
    const newPath = parent === '/' ? '/' + nextName.trim() : parent + '/' + nextName.trim();
    try {
      await api(`/api/servers/${selected.id}/sftp/rename`, { method: 'POST', body: { oldPath, newPath } });
      toast('已重命名');
      await loadSftpDir(currentSftpPath);
    } catch (err) { toast(err.message); }
    return;
  }

  const delBtn = e.target.closest('[data-sftp-del]');
  if (delBtn) {
    const path = delBtn.dataset.sftpDel;
    const kind = delBtn.dataset.isDir === 'true' ? '空目录' : '文件';
    if (!confirm(`确认删除远端${kind}「${path}」？`)) return;
    try {
      await api(`/api/servers/${selected.id}/sftp/delete`, { method: 'POST', body: { remotePath: path } });
      toast('已删除');
      await loadSftpDir(currentSftpPath);
    } catch (err) { toast(err.message); }
  }
};

// --- Command Execution ---
$('#cmd-snippet-select').onchange = e => {
  if (e.target.value) $('#command-input').value = e.target.value;
};

$('#copy-command-result').onclick = () => copyText($('#command-result').textContent, '输出已复制');

$('#run-command').onclick = async e => {
  if (!selected) return;
  const command = $('#command-input').value;
  if (!command.trim()) return toast('请输入命令');
  e.target.disabled = true;
  $('#command-result').textContent = '正在执行，请稍候…';
  try {
    const r = await api(`/api/servers/${selected.id}/execute`, { method: 'POST', body: { command, timeoutSeconds: Number($('#command-timeout').value) } });
    $('#command-result').textContent = `退出码: ${r.exitCode ?? '未知'}${r.exitSignal ? '  信号: ' + r.exitSignal : ''}${r.outputTruncated ? '  [输出已截断]' : ''}\n\n${r.stdout}${r.stderr ? '\n[stderr]\n' + r.stderr : ''}`;
  } catch (err) {
    $('#command-result').textContent = err.message;
  } finally { e.target.disabled = false; }
};

// --- Background Jobs (Kill + Auto Poll + Cleanup) ---
function stopJobPoll() {
  if (jobPollTimer) { clearInterval(jobPollTimer); jobPollTimer = null; }
  $('#job-auto-poll').checked = false;
}

async function fetchJobStatus(incremental = false) {
  if (!selected) return;
  const jobId = $('#job-id').value.trim();
  if (!jobId) return;
  try {
    const qs = incremental && jobPollOffset != null ? `?offset=${jobPollOffset}` : '';
    const r = await api(`/api/servers/${selected.id}/jobs/${encodeURIComponent(jobId)}${qs}`);
    if (!incremental || jobPollOffset == null) {
      jobBufferText = r.output || '';
    } else if (r.output) {
      jobBufferText += r.output;
    }
    jobPollOffset = r.offset + new TextEncoder().encode(r.output || '').length;
    $('#job-output').textContent = `状态: ${r.status}   退出码: ${r.exitCode ?? '—'}   开始: ${r.startedAt ?? '—'}   总字节: ${r.totalBytes}\n\n${jobBufferText}`;
    $('#job-output').scrollTop = $('#job-output').scrollHeight;
    if (r.status !== 'running' && jobPollTimer) {
      stopJobPoll();
      await loadJobs();
    }
  } catch (err) {
    $('#job-output').textContent = err.message;
    stopJobPoll();
  }
}

$('#show-job').onclick = () => {
  jobPollOffset = null;
  jobBufferText = '';
  fetchJobStatus(false);
};

$('#job-auto-poll').onchange = e => {
  if (e.target.checked) {
    if (!$('#job-id').value.trim()) { e.target.checked = false; return toast('请先选择或输入任务 ID'); }
    jobPollOffset = null;
    fetchJobStatus(false);
    jobPollTimer = setInterval(() => fetchJobStatus(true), 2000);
  } else {
    stopJobPoll();
  }
};

$('#start-job').onclick = async e => {
  if (!selected) return;
  const command = $('#job-command').value;
  if (!command.trim()) return toast('请输入后台命令');
  e.target.disabled = true;
  $('#job-result').textContent = '正在启动…';
  try {
    const r = await api(`/api/servers/${selected.id}/jobs`, { method: 'POST', body: { command, timeoutSeconds: Number($('#job-timeout').value) } });
    $('#job-id').value = r.jobId;
    $('#job-result').textContent = `已启动 jobId=${r.jobId}`;
    toast('后台任务已启动');
    await loadJobs();
    $('#job-auto-poll').checked = true;
    $('#job-auto-poll').dispatchEvent(new Event('change'));
  } catch (err) { $('#job-result').textContent = err.message; }
  finally { e.target.disabled = false; }
};

$('#kill-job').onclick = async e => {
  if (!selected) return;
  const jobId = $('#job-id').value.trim();
  if (!jobId) return toast('请先选择任务 ID');
  if (!confirm(`确认终止后台任务 ${jobId}？`)) return;
  e.target.disabled = true;
  try {
    const r = await api(`/api/servers/${selected.id}/jobs/${encodeURIComponent(jobId)}/kill`, { method: 'POST' });
    $('#job-result').textContent = r.message;
    toast(r.message);
    await loadJobs();
    await fetchJobStatus(false);
  } catch (err) { toast(err.message); }
  finally { e.target.disabled = false; }
};

$('#cleanup-jobs').onclick = async e => {
  if (!selected) return;
  if (!confirm('清理该主机上所有已结束的后台任务日志目录？')) return;
  e.target.disabled = true;
  try {
    const r = await api(`/api/servers/${selected.id}/jobs/cleanup`, { method: 'POST', body: { olderThanHours: 0 } });
    toast(r.message);
    await loadJobs();
  } catch (err) { toast(err.message); }
  finally { e.target.disabled = false; }
};

$('#refresh-jobs').onclick = loadJobs;

async function loadJobs() {
  if (!selected) return;
  try {
    const r = await api(`/api/servers/${selected.id}/jobs`);
    $('#job-table-rows').innerHTML = r.jobs.length
      ? r.jobs.map(j => {
          const cls = j.state === 'running' ? 'blue' : (j.state === 'killed' ? 'warn' : (j.exitCode === 0 ? 'ok' : 'danger'));
          return `<tr>
            <td class="mono" style="font-size:11.5px">${escapeHtml(j.jobId.slice(0, 12))}…</td>
            <td><span class="badge ${cls}">${escapeHtml(j.state)}</span></td>
            <td>${j.exitCode ?? '—'}</td>
            <td class="audit-detail-cell" title="${escapeHtml(j.command)}">${escapeHtml(j.command)}</td>
            <td>
              <div class="row-actions">
                <button type="button" class="link-button" data-job-pick="${j.jobId}">查看</button>
                ${j.state !== 'running' ? `<button type="button" class="link-button danger" data-job-del="${j.jobId}">删除</button>` : ''}
              </div>
            </td>
          </tr>`;
        }).join('')
      : '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:18px">暂无后台任务</td></tr>';
  } catch (err) {
    $('#job-table-rows').innerHTML = `<tr><td colspan="5" class="error">${escapeHtml(err.message)}</td></tr>`;
  }
}

$('#job-table-rows').onclick = async e => {
  const pick = e.target.closest('[data-job-pick]');
  if (pick) {
    $('#job-id').value = pick.dataset.jobPick;
    jobPollOffset = null;
    await fetchJobStatus(false);
    return;
  }
  const del = e.target.closest('[data-job-del]');
  if (del) {
    try {
      await api(`/api/servers/${selected.id}/jobs/${encodeURIComponent(del.dataset.jobDel)}`, { method: 'DELETE' });
      toast('已删除任务记录');
      await loadJobs();
    } catch (err) { toast(err.message); }
  }
};

// --- Server Snapshot Tab ---
function renderSnapshotTab() {
  if (!selected) return;
  const s = snapshots.get(selected.id);
  if (!s) {
    $('#snap-checked-at').textContent = '尚未采集该主机状态';
    $('#snap-content').innerHTML = '<div class="empty"><p>点击右上角“立即采集状态”获取 CPU、内存、磁盘、监听端口与服务信息。</p></div>';
    return;
  }
  $('#snap-checked-at').textContent = `采集时间：${fmtDate(s.checkedAt)} · 延迟 ${s.latencyMs}ms`;
  if (!s.online) {
    $('#snap-content').innerHTML = `<div class="empty"><strong style="color:var(--danger)">主机离线或连接失败</strong><p>${escapeHtml(s.error || '')}</p></div>`;
    return;
  }
  const gauge = (title, pct, sub) => {
    const w = pct == null ? 0 : Math.min(100, Math.max(0, pct));
    return `<div class="snap-card">
      <small>${title}</small>
      <strong>${pct == null ? '—' : pct.toFixed(1) + '%'}</strong>
      <div class="res-track" style="height:7px;margin-bottom:8px"><div class="res-fill ${barClass(pct)}" style="width:${w}%"></div></div>
      <div class="footnote" style="margin:0">${escapeHtml(sub)}</div>
    </div>`;
  };
  $('#snap-content').innerHTML = `
    <div class="snap-grid">
      ${gauge('CPU 使用率', s.cpuPercent, `${s.cpuCores ?? '?'} 核心 · 负载 ${s.loadAverage || '—'}`)}
      ${gauge('内存使用率', s.memPercent, s.memTotalMb ? `${fmtMemMb(s.memUsedMb)} / ${fmtMemMb(s.memTotalMb)} (${s.memUsedMb} / ${s.memTotalMb} MB)` : '—')}
      ${gauge('根分区磁盘', s.diskPercent, (s.diskTotalMb || s.diskTotalGb) ? `${fmtDiskSize(s.diskUsedMb, s.diskUsedGb)} / ${fmtDiskSize(s.diskTotalMb, s.diskTotalGb)}` : '—')}
    </div>
    <div class="snap-meta">
      <div><span>主机名</span><strong>${escapeHtml(s.hostname || '—')}</strong></div>
      <div><span>系统</span><strong>${escapeHtml(s.osName || '—')} (${escapeHtml(s.kernel || '—')})</strong></div>
      <div><span>运行时间</span><strong>${escapeHtml(s.uptime || '—')}</strong></div>
      <div><span>Docker 容器</span><strong>${s.dockerTotal != null ? `运行中 ${s.dockerRunning} / 共 ${s.dockerTotal}` : '未安装或无权限'}</strong></div>
      <div><span>失败 Systemd 服务</span><strong>${s.failedServices != null ? s.failedServices : '—'}</strong></div>
      <div><span>TCP 监听端口 (${s.listeningPortsCount ?? 0})</span><strong class="mono">${escapeHtml(s.listeningPorts || '—')}</strong></div>
    </div>`;
}

$('#refresh-one-snapshot').onclick = async e => {
  if (!selected) return;
  e.target.disabled = true;
  try {
    const s = await api(`/api/servers/${selected.id}/snapshot`, { method: 'POST' });
    snapshots.set(s.serverId, s);
    renderSnapshotTab();
    renderServers();
    updateMetrics();
    toast('状态采集完成');
  } catch (err) { toast(err.message); }
  finally { e.target.disabled = false; }
};

// --- Staging Transfer Tab ---
async function loadStagingDatalist() {
  try {
    const rows = await api('/api/files');
    $('#staging-datalist').innerHTML = rows.map(f => `<option value="${escapeHtml(f.name)}"></option>`).join('');
  } catch {}
}

async function transfer(direction, b) {
  if (!selected) return;
  const stagingFile = $('#transfer-file').value, remotePath = $('#transfer-path').value;
  b.disabled = true;
  $('#transfer-result').textContent = '传输中…';
  try {
    await api(`/api/servers/${selected.id}/${direction}`, { method: 'POST', body: { stagingFile, remotePath } });
    $('#transfer-result').textContent = '传输完成。';
    toast('文件传输完成');
  } catch (e) { $('#transfer-result').textContent = e.message; }
  finally { b.disabled = false; }
}
$('#transfer-upload').onclick = e => transfer('upload', e.target);
$('#transfer-download').onclick = e => transfer('download', e.target);

// --- Snippets & Batch Execution ---
async function loadSnippets() {
  try {
    snippets = await api('/api/snippets');
    renderSnippets();
    populateSnippetDropdowns();
  } catch (err) { toast(err.message); }
}

function populateSnippetDropdowns() {
  const opts = '<option value="">选择命令片段…</option>' +
    snippets.map(s => `<option value="${escapeHtml(s.command)}">[${escapeHtml(s.category)}] ${escapeHtml(s.name)}</option>`).join('');
  $('#cmd-snippet-select').innerHTML = opts;
  $('#term-snippet-select').innerHTML = opts;
}

function renderSnippets() {
  const q = ($('#snippet-search').value || '').trim().toLowerCase();
  const filtered = snippets.filter(s => [s.name, s.category, s.command, s.description].some(v => (v || '').toLowerCase().includes(q)));
  $('#empty-snippets').classList.toggle('hidden', filtered.length > 0);
  $('#snippet-list').innerHTML = filtered.map(s => `<div class="snippet-item">
    <div class="snippet-item-head">
      <div><strong>${escapeHtml(s.name)}</strong> <span class="badge blue">${escapeHtml(s.category)}</span></div>
      <div class="row-actions">
        <button type="button" class="link-button" data-snip-use="${s.id}">填入批量</button>
        <button type="button" class="link-button secondary-action" data-snip-edit="${s.id}">编辑</button>
        <button type="button" class="link-button danger" data-snip-del="${s.id}">删除</button>
      </div>
    </div>
    <code>${escapeHtml(s.command)}</code>
    ${s.description ? `<div class="footnote" style="margin:0">${escapeHtml(s.description)}</div>` : ''}
  </div>`).join('');
}

$('#snippet-search').oninput = renderSnippets;

function editSnippet(s = null) {
  const f = $('#snippet-form');
  f.reset();
  $('#snippet-error').textContent = '';
  $('#snippet-dialog-title').textContent = s ? '编辑命令片段' : '新建命令片段';
  f.elements.namedItem('id').value = s?.id || '';
  f.elements.namedItem('name').value = s?.name || '';
  f.elements.namedItem('category').value = s?.category || '通用';
  f.elements.namedItem('command').value = s?.command || '';
  f.elements.namedItem('description').value = s?.description || '';
  $('#snippet-dialog').showModal();
}

$('#add-snippet').onclick = () => editSnippet();

$('#snippet-form').onsubmit = async e => {
  e.preventDefault();
  const f = e.target, id = f.elements.namedItem('id').value, b = e.submitter;
  b.disabled = true;
  $('#snippet-error').textContent = '';
  try {
    const data = Object.fromEntries(new FormData(f));
    delete data.id;
    await api('/api/snippets' + (id ? '/' + id : ''), { method: id ? 'PUT' : 'POST', body: data });
    $('#snippet-dialog').close();
    await loadSnippets();
    toast('命令片段已保存');
  } catch (err) { $('#snippet-error').textContent = err.message; }
  finally { b.disabled = false; }
};

$('#snippet-list').onclick = async e => {
  const useBtn = e.target.closest('[data-snip-use]');
  if (useBtn) {
    const s = snippets.find(x => x.id === useBtn.dataset.snipUse);
    if (s) { $('#batch-command').value = s.command; toast(`已填入「${s.name}」`); }
    return;
  }
  const editBtn = e.target.closest('[data-snip-edit]');
  if (editBtn) {
    const s = snippets.find(x => x.id === editBtn.dataset.snipEdit);
    if (s) editSnippet(s);
    return;
  }
  const delBtn = e.target.closest('[data-snip-del]');
  if (delBtn && confirm('确认删除该命令片段？')) {
    try {
      await api('/api/snippets/' + encodeURIComponent(delBtn.dataset.snipDel), { method: 'DELETE' });
      await loadSnippets();
      toast('已删除');
    } catch (err) { toast(err.message); }
  }
};

function renderBatchTargets() {
  const tags = [...new Set(servers.flatMap(s => (s.tags || '').split(',').map(t => t.trim()).filter(Boolean)))];
  $('#batch-tag-buttons').innerHTML = tags.map(t => `<button type="button" class="button secondary sm" data-pick-tag="${escapeHtml(t)}">标签: ${escapeHtml(t)}</button>`).join('');
  $('#batch-targets').innerHTML = servers.length
    ? servers.map(s => `<label class="target-chip"><input type="checkbox" name="batchServer" value="${s.id}" data-tags="${escapeHtml(s.tags || '')}">${escapeHtml(s.name)}</label>`).join('')
    : '<span class="footnote">暂无可选服务器</span>';
}

$('#batch-select-all').onclick = () => $$('input[name="batchServer"]').forEach(c => c.checked = true);
$('#batch-select-none').onclick = () => $$('input[name="batchServer"]').forEach(c => c.checked = false);
$('#batch-tag-buttons').onclick = e => {
  const b = e.target.closest('[data-pick-tag]');
  if (!b) return;
  const tag = b.dataset.pickTag.toLowerCase();
  $$('input[name="batchServer"]').forEach(c => {
    const st = (c.dataset.tags || '').split(',').map(x => x.trim().toLowerCase());
    c.checked = st.includes(tag);
  });
};

$('#run-batch').onclick = async e => {
  const ids = $$('input[name="batchServer"]:checked').map(c => c.value);
  const command = $('#batch-command').value;
  if (!ids.length) return toast('请至少选择一台服务器');
  if (!command.trim()) return toast('请输入要执行的命令');
  e.target.disabled = true;
  $('#batch-summary').textContent = `正在 ${ids.length} 台服务器上并行执行…`;
  $('#batch-results').innerHTML = '';
  try {
    const r = await api('/api/servers/batch-execute', { method: 'POST', body: { serverIds: ids, command, timeoutSeconds: Number($('#batch-timeout').value) } });
    $('#batch-summary').textContent = `完成：共 ${r.total} 台，成功 ${r.succeeded} 台，失败 ${r.failed} 台。`;
    $('#batch-results').innerHTML = r.results.map(item => `<div class="batch-card">
      <div class="batch-card-head">
        <strong>${escapeHtml(item.serverName)}</strong>
        <div>
          <span class="badge ${item.success ? 'ok' : 'danger'}">${item.success ? '成功' : '失败'}${item.exitCode != null ? ' · 退出码 ' + item.exitCode : ''}</span>
          <span class="badge">${item.durationMs}ms</span>
        </div>
      </div>
      <pre class="terminal" style="margin:0;border-radius:0;max-height:220px">${escapeHtml(item.error ? '[错误] ' + item.error : (item.stdout || '') + (item.stderr ? '\n[stderr]\n' + item.stderr : '')) || '(无输出)'}</pre>
    </div>`).join('');
  } catch (err) {
    $('#batch-summary').textContent = err.message;
  } finally { e.target.disabled = false; }
};

// --- Staging Files ---
async function loadFiles() {
  try {
    const rows = await api('/api/files');
    $('#empty-files').classList.toggle('hidden', rows.length > 0);
    $('#file-rows').innerHTML = rows.map(f => `<tr>
      <td><strong>${escapeHtml(f.name)}</strong></td>
      <td>${fmtBytes(f.size)}</td>
      <td>${fmtDate(f.updatedAt)}</td>
      <td><div class="row-actions"><a class="link-button" href="/api/files/${encodeURIComponent(f.name)}">下载</a><button class="link-button danger" data-file="${escapeHtml(f.name)}">删除</button></div></td>
    </tr>`).join('');
  } catch (e) { toast(e.message); }
}

$('#stage-file').onchange = async e => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const form = new FormData();
    form.append('file', file);
    await api('/api/files', { method: 'POST', body: form });
    await loadFiles();
    toast('文件已上传到暂存区');
  } catch (err) { toast(err.message); }
  finally { e.target.value = ''; }
};

$('#file-rows').onclick = async e => {
  const name = e.target.dataset.file;
  if (name && confirm(`删除暂存文件「${name}」？`)) {
    try { await api('/api/files/' + encodeURIComponent(name), { method: 'DELETE' }); await loadFiles(); }
    catch (err) { toast(err.message); }
  }
};

// --- MCP Access & Tokens ---
function renderMcpSnippets(sampleToken = '<你的独立MCP令牌>') {
  const url = location.origin + '/mcp';
  $('#mcp-url').textContent = url;
  $('#mcp-snippet-codex').textContent = `[mcp_servers.serverpilot]\nurl = "${url}"\nbearer_token_env_var = "SERVERPILOT_MCP_TOKEN"\n\n# 启动 Codex 前设置环境变量：\n# export SERVERPILOT_MCP_TOKEN="${sampleToken}"`;
  $('#mcp-snippet-claude').textContent = `claude mcp add --transport http serverpilot ${url} \\\n  --header "Authorization: Bearer ${sampleToken}"`;
}

$$('[data-mcp-tab]').forEach(b => b.onclick = () => {
  $$('[data-mcp-tab]').forEach(x => x.classList.toggle('active', x === b));
  $('#mcp-snippet-codex').classList.toggle('hidden', b.dataset.mcpTab !== 'codex');
  $('#mcp-snippet-claude').classList.toggle('hidden', b.dataset.mcpTab !== 'claude');
});

$('#copy-url').onclick = () => copyText($('#mcp-url').textContent, 'MCP 地址已复制');
$('#copy-new-token').onclick = () => copyText($('#new-token-value').textContent, 'MCP 令牌已复制');

async function loadTokens() {
  try {
    tokens = await api('/api/tokens');
    updateMetrics();
    $('#empty-tokens').classList.toggle('hidden', tokens.length > 0);
    $('#token-rows').innerHTML = tokens.map(t => {
      const expired = t.expiresAt && new Date(t.expiresAt) < new Date();
      const statusBadge = t.revoked ? '<span class="badge danger">已吊销</span>' : expired ? '<span class="badge warn">已过期</span>' : '<span class="badge ok">有效</span>';
      const scope = t.allowedTags ? `标签: ${escapeHtml(t.allowedTags)}` : '全部服务器';
      return `<tr>
        <td><strong>${escapeHtml(t.name)}</strong></td>
        <td class="mono">${escapeHtml(t.prefix)}</td>
        <td><span class="badge ${t.readOnly ? 'blue' : 'ok'}">${t.readOnly ? '只读' : '读写'}</span></td>
        <td>${scope}</td>
        <td style="font-size:12px"><div>过期：${t.expiresAt ? fmtDate(t.expiresAt) : '永不过期'}</div><div class="server-sub">最后使用：${t.lastUsedAt ? fmtDate(t.lastUsedAt) : '从未使用'}</div></td>
        <td>${statusBadge}</td>
        <td>
          <div class="row-actions">
            ${!t.revoked ? `<button type="button" class="link-button secondary-action" data-tok-revoke="${t.id}">吊销</button>` : ''}
            <button type="button" class="link-button danger" data-tok-del="${t.id}">删除</button>
          </div>
        </td>
      </tr>`;
    }).join('');
  } catch (err) { toast(err.message); }
}

$('#open-create-token').onclick = () => {
  $('#token-form').reset();
  $('#token-error').textContent = '';
  $('#token-dialog').showModal();
};

$('#token-form').onsubmit = async e => {
  e.preventDefault();
  const f = e.target, b = e.submitter;
  b.disabled = true;
  $('#token-error').textContent = '';
  try {
    const fd = new FormData(f);
    const days = fd.get('expiresInDays');
    const res = await api('/api/tokens', {
      method: 'POST',
      body: {
        name: fd.get('name'),
        allowedTags: fd.get('allowedTags') || '',
        readOnly: fd.get('readOnly') === 'on',
        expiresInDays: days ? Number(days) : null
      }
    });
    $('#token-dialog').close();
    $('#new-token-value').textContent = res.plainToken;
    $('#new-token-banner').classList.remove('hidden');
    renderMcpSnippets(res.plainToken);
    await loadTokens();
    toast('独立 MCP 令牌已创建');
  } catch (err) { $('#token-error').textContent = err.message; }
  finally { b.disabled = false; }
};

$('#token-rows').onclick = async e => {
  const rev = e.target.closest('[data-tok-revoke]');
  if (rev && confirm('吊销该 MCP 令牌？使用它的 AI 客户端将立即失效。')) {
    try { await api(`/api/tokens/${rev.dataset.tokRevoke}/revoke`, { method: 'POST' }); await loadTokens(); toast('令牌已吊销'); }
    catch (err) { toast(err.message); }
    return;
  }
  const del = e.target.closest('[data-tok-del]');
  if (del && confirm('永久删除该 MCP 令牌记录？')) {
    try { await api(`/api/tokens/${del.dataset.tokDel}`, { method: 'DELETE' }); await loadTokens(); toast('令牌已删除'); }
    catch (err) { toast(err.message); }
  }
};

// --- Enhanced Audit Log ---
function auditFilterParams() {
  const params = new URLSearchParams();
  const q = $('#audit-q').value.trim();
  const result = $('#audit-result').value;
  if (q) params.set('q', q);
  if (result) params.set('result', result);
  return params;
}

async function loadAudit(page = auditPage) {
  try {
    const params = auditFilterParams();
    params.set('page', String(page));
    params.set('pageSize', '50');
    const expParams = auditFilterParams().toString();
    $('#export-audit-csv').href = '/api/audit/export?format=csv' + (expParams ? '&' + expParams : '');
    $('#export-audit-json').href = '/api/audit/export?format=json' + (expParams ? '&' + expParams : '');

    const res = await api('/api/audit?' + params.toString());
    auditPage = res.page;
    auditPages = res.totalPages;
    $('#empty-audit').classList.toggle('hidden', res.total > 0);
    $('#audit-rows').innerHTML = res.items.map(r => `<tr>
      <td style="white-space:nowrap;font-size:12px">${fmtDate(r.at)}</td>
      <td><span class="badge ${r.actor.startsWith('mcp') ? 'blue' : ''}">${escapeHtml(r.actor)}</span></td>
      <td>${escapeHtml(r.server)}</td>
      <td class="mono" style="font-size:12px">${escapeHtml(r.action)}</td>
      <td style="white-space:nowrap;font-size:12px">${r.durationMs != null ? r.durationMs + 'ms' : '—'}${r.exitCode != null ? ' · rc=' + r.exitCode : ''}</td>
      <td class="audit-detail-cell" title="${escapeHtml(r.detail || '')}">${escapeHtml(r.detail || '—')}</td>
      <td><span class="badge ${r.result === 'success' ? 'ok' : 'danger'}">${r.result === 'success' ? '成功' : '失败'}</span></td>
    </tr>`).join('');
    $('#audit-page-info').textContent = `共 ${res.total} 条 · 第 ${auditPage} / ${auditPages} 页`;
    $('#audit-prev').disabled = auditPage <= 1;
    $('#audit-next').disabled = auditPage >= auditPages;
  } catch (e) { toast(e.message); }
}

$('#audit-prev').onclick = () => loadAudit(auditPage - 1);
$('#audit-next').onclick = () => loadAudit(auditPage + 1);
$('#refresh-audit').onclick = () => loadAudit(auditPage);
$('#audit-filter-btn').onclick = () => loadAudit(1);
$('#audit-q').addEventListener('keydown', e => { if (e.key === 'Enter') loadAudit(1); });

// --- Security, Settings, Notifications & Backup ---
$('#password-form').onsubmit = async e => {
  e.preventDefault();
  const b = e.submitter;
  b.disabled = true;
  $('#password-result').textContent = '';
  try {
    const data = Object.fromEntries(new FormData(e.target));
    await api('/api/password', { method: 'POST', body: data });
    showLogin();
    $('#login-error').textContent = '密码已修改，请使用新密码登录。';
  } catch (err) { $('#password-result').textContent = err.message; }
  finally { b.disabled = false; }
};

function syncNotifyChannelFields() {
  const isTg = $('#set-notify-channel').value === 'telegram';
  $('#notify-url-wrap').classList.toggle('hidden', isTg);
  $('#notify-tg-wrap').classList.toggle('hidden', !isTg);
}
$('#set-notify-channel').onchange = syncNotifyChannelFields;

async function loadSettings() {
  try {
    const s = await api('/api/settings');
    $('#set-audit-details').checked = s.auditRecordDetails;
    $('#set-admin-mcp').checked = s.allowAdminPasswordForMcp;
    const n = s.notifications;
    $('#set-notify-enabled').checked = n.enabled;
    $('#set-notify-channel').value = n.channel || 'generic';
    $('#set-notify-url').value = n.webhookUrlMasked || '';
    $('#set-tg-token').value = '';
    $('#set-tg-token').placeholder = n.hasTelegramToken ? '已保存（留空保留原 Token）' : '输入 Telegram Bot Token';
    $('#set-tg-chatid').value = n.telegramChatId || '';
    $('#set-notify-login').checked = n.notifyOnLogin;
    $('#set-notify-pwd').checked = n.notifyOnPasswordChange;
    $('#set-notify-alert').checked = n.notifyOnServerAlert;
    $('#set-notify-job').checked = n.notifyOnJobEvent;
    syncNotifyChannelFields();
  } catch (err) { toast(err.message); }
}

$('#settings-form').onsubmit = async e => {
  e.preventDefault();
  const b = e.submitter;
  b.disabled = true;
  try {
    await api('/api/settings', {
      method: 'PUT',
      body: {
        auditRecordDetails: $('#set-audit-details').checked,
        allowAdminPasswordForMcp: $('#set-admin-mcp').checked,
        notifications: {
          enabled: $('#set-notify-enabled').checked,
          channel: $('#set-notify-channel').value,
          webhookUrl: $('#set-notify-url').value,
          telegramBotToken: $('#set-tg-token').value || null,
          telegramChatId: $('#set-tg-chatid').value,
          notifyOnLogin: $('#set-notify-login').checked,
          notifyOnPasswordChange: $('#set-notify-pwd').checked,
          notifyOnServerAlert: $('#set-notify-alert').checked,
          notifyOnJobEvent: $('#set-notify-job').checked
        }
      }
    });
    await loadSettings();
    toast('系统设置已保存');
  } catch (err) { toast(err.message); }
  finally { b.disabled = false; }
};

$('#test-notify-btn').onclick = async e => {
  e.target.disabled = true;
  try {
    const r = await api('/api/notifications/test', { method: 'POST' });
    toast(r.message);
  } catch (err) { toast(err.message); }
  finally { e.target.disabled = false; }
};

$('#backup-export-form').onsubmit = async e => {
  e.preventDefault();
  const b = e.submitter;
  b.disabled = true;
  try {
    const env = await api('/api/backup/export', { method: 'POST', body: { passphrase: $('#backup-export-pass').value } });
    const blob = new Blob([JSON.stringify(env, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `serverpilot-backup-${new Date().toISOString().slice(0, 10)}.spbak.json`;
    a.click();
    URL.revokeObjectURL(url);
    $('#backup-export-pass').value = '';
    toast('加密备份已导出');
  } catch (err) { toast(err.message); }
  finally { b.disabled = false; }
};

$('#backup-import-form').onsubmit = async e => {
  e.preventDefault();
  const file = $('#backup-import-file').files[0];
  if (!file) return toast('请选择备份文件');
  const b = e.submitter;
  b.disabled = true;
  $('#backup-import-result').textContent = '正在解密并恢复…';
  try {
    const payload = await file.text();
    const r = await api('/api/backup/import', {
      method: 'POST',
      body: { passphrase: $('#backup-import-pass').value, payload, overwriteExisting: $('#backup-import-overwrite').checked }
    });
    $('#backup-import-result').textContent = `导入完成：服务器 ${r.serversImported} 台（跳过 ${r.serversSkipped} 台）、共享私钥 ${r.sharedKeysImported} 个、命令片段 ${r.snippetsImported} 条。`;
    $('#backup-import-form').reset();
    await Promise.all([loadSharedKeys(), loadServers(), loadSnippets(), loadSettings()]);
    toast('备份已恢复');
  } catch (err) {
    $('#backup-import-result').textContent = err.message;
    toast(err.message);
  } finally { b.disabled = false; }
};

// --- Bootstrap ---
(async () => {
  try {
    const session = await api('/api/session');
    if (session.authenticated) await showApp();
    else if (session.needsSetup) showSetup();
    else showLogin();
  } catch {
    showLogin();
  }
})();
