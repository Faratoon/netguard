/* NetGuard dashboard - vanilla JS client */
const state = { devices: [], policies: [], curfews: [], blocklist: [] };

const $ = (sel) => document.querySelector(sel);
const api = async (path, options = {}) => {
  const token = localStorage.getItem('netguard_token');
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers['X-NetGuard-Token'] = token;
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    // API token required - ask once and retry
    const entered = window.prompt('This NetGuard instance is protected.\nEnter the API token:');
    if (entered) {
      localStorage.setItem('netguard_token', entered.trim());
      headers['X-NetGuard-Token'] = entered.trim();
      const retry = await fetch(path, { ...options, headers });
      if (retry.ok) return retry.status === 204 ? null : retry.json();
    }
  }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) {}
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
};
const fmtBytes = (b) => {
  if (!b) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), units.length - 1);
  return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + units[i];
};
const fmtUptime = (s) => {
  if (!s) return '-';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
};

/* ---------------------------------------------------------------- tabs */
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    $('#' + tab.dataset.tab).classList.add('active');
    if (tab.dataset.tab === 'admin') loadAdmin();
  });
});

/* ------------------------------------------------------------ dashboard */
async function loadDashboard() {
  try {
    const info = await api('/api/admin/info');
    const r = info.router || {};
    $('#router-line').textContent = `${r.model || 'router'} - ${r.firmware || ''} - WAN ${r.wan_ip || 'n/a'}`;
    $('#card-router').innerHTML = kv([
      ['Model', r.model], ['Firmware', r.firmware], ['WAN IP', r.wan_ip],
      ['LAN IP', r.lan_ip], ['DNS', (r.dns_servers || []).join(', ')], ['Uptime', fmtUptime(r.uptime_seconds)],
      ['CPU %', r.cpu_percent], ['Memory %', r.mem_percent], ['Load', (r.load_avg || []).join(' / ')],
      ['WiFi', (r.wireless || []).map((w) => w.ssid).join(', ')],
    ]);
    $('#card-counts').innerHTML = kv(Object.entries(info.counts || {}).map(([k, v]) => [k.replace(/_/g, ' '), v]));
  } catch (e) { $('#router-line').textContent = 'router unreachable: ' + e.message; }

  try {
    const summary = await api('/api/network/summary?hours=24');
    $('#card-traffic').innerHTML = kv([
      ['Downloaded', fmtBytes(summary.total_rx_bytes)],
      ['Uploaded', fmtBytes(summary.total_tx_bytes)],
    ]);
    $('#card-top').innerHTML = (summary.per_device || []).length
      ? summary.per_device.slice(0, 6).map((d) => `<div><span>${d.name || d.device_id}</span><span>${fmtBytes(d.rx_bytes + d.tx_bytes)}</span></div>`).join('')
      : '<div><span>no traffic samples yet</span><span>-</span></div>';
  } catch (e) { /* ignore */ }

  try {
    const series = await api('/api/network/traffic?hours=24');
    drawChart(series.samples || []);
  } catch (e) { /* ignore */ }
}

function kv(pairs) {
  return pairs.map(([k, v]) => `<div><span>${k}</span><span>${v === null || v === undefined ? '-' : v}</span></div>`).join('');
}

function drawChart(samples) {
  const canvas = $('#traffic-chart');
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!samples.length) return;
  const max = Math.max(...samples.map((s) => s.rx_bytes + s.tx_bytes), 1);
  const bw = canvas.width / samples.length;
  samples.forEach((s, i) => {
    const h = ((s.rx_bytes + s.tx_bytes) / max) * (canvas.height - 20);
    ctx.fillStyle = '#1f6feb';
    ctx.fillRect(i * bw, canvas.height - h, Math.max(bw - 1, 1), h);
    ctx.fillStyle = '#56d364';
    ctx.fillRect(i * bw, canvas.height - ((s.tx_bytes / max) * (canvas.height - 20)), Math.max(bw - 1, 1), ((s.tx_bytes / max) * (canvas.height - 20)));
  });
}

/* -------------------------------------------------------------- devices */
async function loadDevices() {
  const data = await api('/api/devices');
  state.devices = data.devices || [];
  $('#device-count').textContent = `${data.count} device(s) found`;
  $('#device-list').innerHTML = state.devices.map((d) => `
    <div class="device">
      <div class="name">${d.friendly_name || d.hostname || d.mac}</div>
      <div class="meta">${d.mac} &middot; ${d.ip || 'no ip'} &middot; ${d.vendor || 'unknown vendor'} &middot; ${d.device_type}</div>
      ${d.is_blocked ? '<span class="badge on">blocked</span>' : ''}
      ${d.is_quarantined ? '<span class="badge on">no internet</span>' : ''}
      ${d.is_safe_mode ? '<span class="badge safe">safe mode</span>' : ''}
      ${!d.is_blocked && !d.is_safe_mode ? '<span class="badge ok">normal</span>' : ''}
      <div style="margin-top:10px">
        <button class="tiny" onclick="toggleDevice(${d.id},'is_blocked',${!d.is_blocked})">${d.is_blocked ? 'Unblock' : 'Block'}</button>
        <button class="tiny" onclick="toggleDevice(${d.id},'is_safe_mode',${!d.is_safe_mode})">${d.is_safe_mode ? 'Disable safe mode' : 'Safe mode'}</button>
        <button class="tiny" onclick="toggleDevice(${d.id},'is_quarantined',${!d.is_quarantined})">${d.is_quarantined ? 'Restore internet' : 'Cut internet'}</button>
      </div>
    </div>`).join('');

  const opts = state.devices.map((d) => `<option value="${d.id}">${d.friendly_name || d.hostname || d.mac}</option>`).join('');
  $('#pol-device').innerHTML = '<option value="">all devices</option>' + opts;
  $('#cur-device').innerHTML = opts;
  $('#chk-device').innerHTML = '<option value="">global</option>' + opts;
}

window.toggleDevice = async (id, field, value) => {
  await api(`/api/devices/${id}`, { method: 'PATCH', body: JSON.stringify({ [field]: value }) });
  loadDevices();
};

/* ------------------------------------------------------------- controls */
async function loadControls() {
  const bl = await api('/api/controls/blocklist');
  state.blocklist = bl.entries || [];
  $('#blocklist').innerHTML = state.blocklist.length
    ? state.blocklist.map((e) => `<div class="item"><span>${e.domain}<small>${e.category} - hits: ${e.hits}</small></span>
        <button class="tiny ghost" onclick="delBlock(${e.id})">x</button></div>`).join('')
    : '<div class="hint">blocklist is empty</div>';

  const pol = await api('/api/controls/policies');
  state.policies = pol.policies || [];
  $('#policies').innerHTML = state.policies.length
    ? state.policies.map((p) => `<div class="item"><span>${p.kind}: ${p.value}<small>${p.action}${p.device_id ? ' - device ' + p.device_id : ' - global'}</small></span>
        <button class="tiny ghost" onclick="delPolicy(${p.id})">x</button></div>`).join('')
    : '<div class="hint">no rules</div>';

  const cur = await api('/api/controls/curfews');
  state.curfews = cur.curfews || [];
  $('#curfews').innerHTML = state.curfews.length
    ? state.curfews.map((c) => `<div class="item"><span>${c.device_name || c.device_id}<small>${c.start_time}-${c.end_time} days ${c.days} (${c.action})${c.active_now ? ' - ACTIVE' : ''}</small></span>
        <button class="tiny ghost" onclick="delCurfew(${c.id})">x</button></div>`).join('')
    : '<div class="hint">no curfews</div>';
}

window.delBlock = async (id) => { await api(`/api/controls/blocklist/${id}`, { method: 'DELETE' }); loadControls(); };
window.delPolicy = async (id) => { await api(`/api/controls/policies/${id}`, { method: 'DELETE' }); loadControls(); };
window.delCurfew = async (id) => { await api(`/api/controls/curfews/${id}`, { method: 'DELETE' }); loadControls(); };

$('#btn-add-block').onclick = async () => {
  await api('/api/controls/blocklist', { method: 'POST', body: JSON.stringify({ domain: $('#bl-domain').value, category: $('#bl-category').value }) });
  $('#bl-domain').value = ''; loadControls();
};
$('#btn-import-presets').onclick = async () => {
  const res = await api('/api/controls/presets/adult/import', { method: 'POST' });
  alert(`added ${res.added} domains`);
  loadControls();
};
$('#btn-add-policy').onclick = async () => {
  const device_id = $('#pol-device').value ? Number($('#pol-device').value) : null;
  await api('/api/controls/policies', { method: 'POST', body: JSON.stringify({
    device_id, kind: $('#pol-kind').value, value: $('#pol-value').value, action: $('#pol-action').value }) });
  $('#pol-value').value = ''; loadControls();
};
$('#btn-add-curfew').onclick = async () => {
  await api('/api/controls/curfews', { method: 'POST', body: JSON.stringify({
    device_id: Number($('#cur-device').value), days: $('#cur-days').value,
    start_time: $('#cur-start').value, end_time: $('#cur-end').value, action: $('#cur-action').value }) });
  loadControls();
};
$('#btn-check').onclick = async () => {
  const device_id = $('#chk-device').value ? Number($('#chk-device').value) : null;
  const res = await api('/api/controls/check', { method: 'POST', body: JSON.stringify({ device_id, domain: $('#chk-domain').value }) });
  const box = $('#check-result');
  box.textContent = res.blocked ? 'BLOCKED - ' + res.reason : 'ALLOWED - ' + res.reason;
  box.className = 'result ' + (res.blocked ? 'blocked' : 'allowed');
};
$('#btn-apply').onclick = async () => {
  const res = await api('/api/controls/apply', { method: 'POST', body: JSON.stringify({ apply: false }) });
  $('#apply-output').textContent = (res.commands || []).join('\n') + (res.dry_run ? '\n\n[dry run - nothing was sent to the router]' : '');
};
$('#btn-apply-live').onclick = async () => {
  if (!confirm('Push these rules to the router now?')) return;
  const res = await api('/api/controls/apply', { method: 'POST', body: JSON.stringify({ apply: true }) });
  $('#apply-output').textContent = (res.commands || []).join('\n') + `\n\napplied=${res.applied} error=${res.error || 'none'}`;
};

/* -------------------------------------------------------------- network */
$('#btn-speed').onclick = async () => { $('#speed-out').textContent = 'testing...'; const r = await api('/api/network/speedtest', { method: 'POST' }); $('#speed-out').textContent = r.output; };
$('#btn-ping').onclick = async () => { $('#ping-out').textContent = 'pinging...'; const r = await api('/api/network/ping', { method: 'POST', body: JSON.stringify({ host: $('#ping-host').value }) }); $('#ping-out').textContent = r.output; };
$('#btn-trace').onclick = async () => { $('#trace-out').textContent = 'tracing...'; const r = await api('/api/network/traceroute', { method: 'POST', body: JSON.stringify({ host: $('#trace-host').value }) }); $('#trace-out').textContent = r.output; };
$('#btn-scan-net').onclick = async () => { $('#scan-out').textContent = 'scanning...'; const r = await api('/api/network/scan', { method: 'POST', body: JSON.stringify({ cidr: $('#scan-cidr').value }) }); $('#scan-out').textContent = JSON.stringify(r.detail, null, 2); };
$('#btn-status').onclick = async () => { const r = await api('/api/network/status'); $('#status-out').textContent = JSON.stringify(r, null, 2); };
$('#btn-scan').onclick = async () => { await api('/api/devices/scan', { method: 'POST' }); loadDevices(); };

/* --------------------------------------------------------------- images */
$('#btn-upload').onclick = async () => {
  const file = $('#img-file').files[0];
  if (!file) return alert('pick a file first');
  const fd = new FormData();
  fd.append('file', file);
  fd.append('title', $('#img-title').value || file.name);
  const token = localStorage.getItem('netguard_token');
  const res = await fetch('/api/media/upload', { method: 'POST', body: fd, headers: token ? { 'X-NetGuard-Token': token } : {} });
  if (!res.ok) alert('upload failed');
  loadGallery();
};

async function loadGallery() {
  const data = await api('/api/media/list');
  $('#gallery').innerHTML = (data.assets || []).map((a) => `
    <figure><a href="${a.url}" target="_blank"><img src="${a.url}" alt="${a.title || ''}" loading="lazy"></a>
    <figcaption>${a.kind}<br>${a.title || ''}</figcaption></figure>`).join('');
}

/* ---------------------------------------------------------------- admin */
async function loadAdmin() {
  const info = await api('/api/admin/info');
  $('#admin-out').textContent = JSON.stringify(info, null, 2);
  const s = await api('/api/admin/settings');
  $('#settings-form').innerHTML = `
    <label>Router host<input id="set-host" value="${s.router.host}"></label>
    <label>Router user<input id="set-user" value="${s.router.user}"></label>
    <label>Router vendor<input id="set-vendor" value="${s.router.vendor}"></label>
    <label>Dry run (no live changes)<input type="checkbox" id="set-dry" ${s.router.dry_run ? 'checked' : ''}></label>
    <label>API token<input id="set-token" type="password" placeholder="${s.api_token_set ? 'set' : 'not set'}"></label>`;
  const tools = await api('/api/admin/tools');
  $('#tools-out').textContent = JSON.stringify(tools, null, 2);
}

$('#btn-admin-info').onclick = loadAdmin;
$('#btn-save-settings').onclick = async () => {
  const payload = {
    router_host: $('#set-host').value,
    router_user: $('#set-user').value,
    router_vendor: $('#set-vendor').value,
    dry_run: $('#set-dry').checked,
  };
  if ($('#set-token').value) payload.api_token = $('#set-token').value;
  await api('/api/admin/settings', { method: 'PUT', body: JSON.stringify(payload) });
  if ($('#set-token').value) localStorage.setItem('netguard_token', $('#set-token').value);
  alert('settings saved');
};

/* ------------------------------------------------------------------ dns */
async function loadDns() {
  try {
    const s = await api('/api/dns/status');
    const stats = s.stats || {};
    $('#dns-status').innerHTML = kv([
      ['Running', s.running ? 'yes' : 'no'],
      ['Listening', `${s.host}:${s.port}`],
      ['This machine', (s.listen || []).join(', ') || '-'],
      ['Upstream DNS', (s.upstream || []).join(', ')],
      ['Queries', stats.queries ?? '-'],
      ['Blocked', stats.blocked ?? '-'],
      ['Forwarded', stats.forwarded ?? '-'],
      ['Error', s.error || '-'],
    ]);
    const recent = stats.recent || [];
    $('#dns-recent').innerHTML = recent.length
      ? recent.slice(0, 12).map((r) => `<div class="item"><span>${r.domain}<small>${r.client} - ${r.reason || ''}</small></span></div>`).join('')
      : '<div class="hint">no blocked lookups yet</div>';
  } catch (e) { /* ignore */ }
  try {
    const ins = await api('/api/dns/instructions');
    $('#dns-instructions').innerHTML =
      `<div class="item"><span>Use this DNS server<small>${ins.dns_server}</small></span></div>` +
      ins.steps.map((s) => `<div class="item"><span>${s}</span></div>`).join('');
  } catch (e) { /* ignore */ }
}

$('#btn-dns-start').onclick = async () => { await api('/api/dns/start', { method: 'POST' }); loadDns(); };
$('#btn-dns-stop').onclick = async () => { await api('/api/dns/stop', { method: 'POST' }); loadDns(); };
$('#btn-dns-lookup').onclick = async () => {
  const res = await api('/api/dns/lookup', { method: 'POST', body: JSON.stringify({
    domain: $('#dns-domain').value, client_ip: $('#dns-client').value || '192.168.1.50' }) });
  const box = $('#dns-result');
  box.textContent = `${res.domain} -> ${res.resolved_to} ${res.blocked ? '(' + res.reason + ')' : ''}`;
  box.className = 'result ' + (res.blocked ? 'blocked' : 'allowed');
};

/* --------------------------------------------------------------- startup */
(async function init() {
  await loadDashboard();
  await loadDevices();
  await loadControls();
  await loadDns();
  await loadGallery();
  setInterval(loadDashboard, 30000);
  setInterval(loadDns, 15000);
})();
