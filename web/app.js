const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

const STATE_LABEL = { up: 'OK', degraded: 'Degraded', down: 'Down', unknown: 'Unknown' };
const CAT_LABEL = { security: 'Security', disruption: 'Disruption', system: 'System', presence: 'Presence' };
const SERIES_COLORS = ['--s1', '--s2', '--s3', '--s4', '--s5', '--s6', '--s7'];
const NOTIFY_SEVERITIES = new Set(['warning', 'critical']);

const state = {
  status: null,
  range: 60,
  evFilter: '',
  events: [],
  logs: [],
  logsLoaded: false,
  hidden: new Set(),
  chartData: null,
  devices: new Map(),
  devFilter: 'all',
  editing: null,
  push: { supported: 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window, sub: null },
};

// ---------- helpers ----------
const LOCALE = window.i18n?.locale || 'en-GB';
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtMs = (v) => (v == null ? '–' : v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`);
function fmtTime(ts) {
  const d = new Date(ts * 1000);
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay
    ? d.toLocaleTimeString(LOCALE, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : d.toLocaleString(LOCALE, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function fmtAgo(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
  return `${Math.floor(s / 86400)} d`;
}
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
async function api(path, method = 'GET', body) {
  const opts = { method, cache: 'no-store' };
  if (body !== undefined) { opts.body = JSON.stringify(body); opts.headers = { 'content-type': 'application/json' }; }
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = `${path}: ${r.status}`;
    try { const j = await r.json(); if (typeof j.detail === 'string') msg = j.detail; } catch { /* not JSON */ }
    if (r.status === 401 && !path.startsWith('/api/auth')) showLogin();
    throw new Error(msg);
  }
  return r.json();
}
const worst = (states) => states.reduce((a, b) => (rank(b) > rank(a) ? b : a), 'up');
const rank = (s) => ({ up: 0, unknown: 1, degraded: 2, down: 3 }[s] ?? 1);

// ---------- flikar ----------
function showTab(name) {
  $$('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
  $$('.tab').forEach((t) => (t.hidden = t.id !== `tab-${name}`));
  if (name === 'logs' && !state.logsLoaded) loadLogs();
  if (name === 'overview') { loadChart(); setTimeout(() => { state.map?.invalidateSize(); renderMap(); }, 50); }
  if (name === 'devices') loadDevices();
  if (name === 'settings') renderSettings();
  if (name === 'security') renderSecurity();
  try { localStorage.setItem('nm-tab', name); } catch {}
}
$$('.tabs button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
$$('[data-goto]').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.goto)));

// ---------- statuskort ----------
function renderStatus(s) {
  state.status = s;
  const gw = s.targets.find((t) => t.kind === 'gateway');
  const inet = s.targets.filter((t) => t.kind === 'internet');
  const devices = s.targets.filter((t) => t.kind === 'device');
  const dns = s.dns.targets;
  const bestInet = inet.filter((t) => t.median_ms != null).sort((a, b) => a.median_ms - b.median_ms)[0];
  const sl = s.syslog;
  const lastLog = sl.sources.reduce((m, x) => Math.max(m, x.last_seen || 0), 0);

  const up = s.uplink;
  const upT = up && s.targets.find((t) => t.host === up.host);
  const cards = [];
  if (up) {
    cards.push({
      label: 'Server uplink', state: up.state,
      value: STATE_LABEL[up.state],
      sub: `${esc(up.name)} · ${fmtMs(upT?.median_ms)} · loss ${upT?.loss_pct ?? 0} %`,
    });
  }
  cards.push(
    {
      label: 'Main router', state: s.lan.state,
      value: STATE_LABEL[s.lan.state],
      sub: gw ? `${esc(gw.name)} · ${fmtMs(gw.median_ms)} · loss ${gw.loss_pct} %` : 'No gateway found',
    },
    {
      label: 'Internet', state: s.wan.state,
      value: STATE_LABEL[s.wan.state],
      sub: bestInet ? `${fmtMs(bestInet.median_ms)} to ${esc(bestInet.name)} · for ${fmtAgo(s.wan.since)}` : 'Waiting for measurements',
    },
    {
      label: 'DNS', state: dns.length ? worst(dns.map((d) => d.state)) : 'unknown',
      value: dns.length ? STATE_LABEL[worst(dns.map((d) => d.state))] : '–',
      sub: dns.map((d) => `${esc(d.name)} ${fmtMs(d.median_ms)}`).join(' · ') || 'No DNS targets',
    },
  );
  const aps = devices.filter((d) => !up || d.host !== up.host);
  if (aps.length) {
    const st = worst(aps.map((d) => d.state));
    const downN = aps.filter((d) => d.state === 'down').length;
    cards.push({
      label: 'Access points', state: st,
      value: downN ? `${downN} down` : `${aps.length} responding`,
      sub: aps.map((d) => esc(d.name)).join(' · '),
    });
  }
  const sec = s.security;
  if (sec) {
    const inv = sec.inventory;
    const alarms = [];
    if (!inv.arp_ok) alarms.push('ARP');
    if (sec.dhcp.rogue.length) alarms.push('DHCP');
    if (sec.dns.problems.length) alarms.push('DNS');
    const st = alarms.length ? 'down' : inv.untrusted ? 'degraded' : 'up';
    const checks = [`ARP ${inv.arp_ok ? '✓' : '✗'}`, sec.dhcp.enabled ? `DHCP ${sec.dhcp.rogue.length ? '✗' : '✓'}` : 'DHCP –',
      `DNS ${sec.dns.ok === false ? '✗' : sec.dns.ok ? '✓' : '…'}`];
    cards.push({
      label: 'Security', state: st,
      value: alarms.length ? `Alert: ${alarms.join(', ')}` : inv.untrusted ? `${inv.untrusted} new device${inv.untrusted > 1 ? 's' : ''}` : 'OK',
      sub: `${checks.join(' · ')} · ${inv.online} devices online`,
      goto: alarms.length ? 'security' : inv.untrusted ? 'devices' : null,
    });
  }
  // Logs come mainly from modules that log in to the routers; syslog sources only appear once a line arrives.
  const ra = s.router;
  const raOk = ra?.enabled && ra.last_ok && Date.now() / 1000 - ra.last_ok < 300;
  cards.push({
    label: 'Router logs',
    state: ra?.enabled ? (raOk ? 'up' : 'down') : sl.error ? 'down' : sl.sources.length ? 'up' : 'unknown',
    value: ra?.enabled ? (raOk ? 'Reading' : 'Not reachable') : sl.error ? 'Error' : sl.sources.length ? `${sl.sources.length} source${sl.sources.length > 1 ? 's' : ''}` : 'None yet',
    sub: ra?.enabled
      ? (raOk ? `${esc(ra.model || 'Router')} · checked ${fmtAgo(ra.last_ok)} ago` : esc(ra.last_error || 'No answer from the router'))
      : sl.error ? esc(sl.error) : sl.sources.length ? `Last ${fmtAgo(lastLog)} ago` : `Listening on udp/${sl.port}`,
  });

  for (const sv of s.services || []) {
    cards.push({
      label: esc(sv.name), state: sv.state,
      value: sv.state === 'up' ? 'Up' : sv.state === 'down' ? 'Down' : 'Checking…',
      sub: sv.state === 'down' ? `${esc(sv.error || '')} · since ${fmtTime(sv.since)}` : sv.ms != null ? `${Math.round(sv.ms)} ms` : '',
    });
  }
  // Cards that only say OK become small chips; only problems get big cards.
  const ok = cards.filter((c) => c.state === 'up');
  const bad = cards.filter((c) => c.state !== 'up');
  $('#okbar').innerHTML = ok.map((c) => `<span class="chip" title="${c.sub.replace(/"/g, '&quot;')}">✓ ${c.label}</span>`).join('');
  $('#cards').innerHTML = bad.map((c) => `
    <div class="card ${c.state}"${c.goto ? ` data-goto="${c.goto}" role="button" tabindex="0" style="cursor:pointer"` : ''}>
      <span class="label">${c.label}</span>
      <span class="value">${c.value}</span>
      <span class="sub">${c.sub}</span>
    </div>`).join('');
  $$('#cards [data-goto]').forEach((el) => el.addEventListener('click', () => showTab(el.dataset.goto)));
  if (!$('#tab-security').hidden) renderSecurity();
  if (!$('#tab-settings').hidden) renderPushPanel();
  if (!$('#tab-devices').hidden) renderDevices();

  const rows = [...s.targets, ...dns];
  const badN = rows.filter((t) => t.state !== 'up').length;
  $('#targets-sum').textContent = badN ? `· ${badN} with problems` : `· all ${rows.length} OK`;
  if (badN) $('#targets-panel').open = true;
  renderTop();
  renderUsage();
  renderHostFlows();
  renderMap();
  $('#targets').innerHTML = rows.map((t) => `
    <tr>
      <td>${esc(t.name)}</td>
      <td>${esc(t.host)}</td>
      <td class="num">${fmtMs(t.last_ms)}</td>
      <td class="num">${fmtMs(t.median_ms)}</td>
      <td class="num">${t.loss_pct} %</td>
      <td><span class="pill ${t.state}">${STATE_LABEL[t.state]}</span></td>
    </tr>`).join('');

  renderLogHelp();
}

// ---------- top devices (speed from the router) ----------
function renderTop() {
  const tr = state.status?.router?.traffic || {};
  const list = Object.entries(tr).map(([mac, t]) => ({ mac, t, sum: (t.down || 0) + (t.up || 0) }))
    .filter((x) => x.sum * 8 >= 200_000).sort((a, b) => b.sum - a.sum).slice(0, 8);
  const max = list[0]?.sum || 1;
  const total = Object.values(tr).reduce((a, t) => a + (t.down || 0) + (t.up || 0), 0);
  const upd = state.status?.router?.last_ok;
  $('#top-total').innerHTML = `<span class="live-dot"></span>Live${upd ? ` · <span id="top-age"></span>` : ''}${total ? ` · ${fmtMbps(total)} total` : ''}`;
  tickTopAge();
  $('#top-devs').innerHTML = list.length ? list.map(({ mac, t, sum }) => {
    const name = esc(devName(mac));
    return `<li><div class="td-row"><span>${name}</span><span><b>↓ ${fmtMbps(t.down || 0)}</b> <span class="muted">↑ ${fmtMbps(t.up || 0)}</span></span></div>
      <div class="bar"><i style="width:${Math.max(3, (sum / max) * 100)}%"></i></div></li>`;
  }).join('') : `<li class="muted">${state.status?.router?.enabled ? 'No device above 200 kbit/s right now.' : 'Router API not active.'}</li>`;
}

// "x s ago" counts up every second between updates.
function tickTopAge() {
  const el = $('#top-age'), upd = state.status?.router?.last_ok;
  if (el && upd) el.textContent = `${Math.max(0, Math.round(Date.now() / 1000 - upd))} s ago`;
}
setInterval(tickTopAge, 1000);

// ---------- insikter ----------
const fmtMbit = (v) => (v == null ? '–' : v >= 100 ? String(Math.round(v)) : v.toFixed(1));
const fmtMbps = (bps) => `${fmtMbit((bps * 8) / 1e6)} Mbit/s`;
// Names for lists without an IP column. If several devices share a name, the end of the IP is added, e.g. "Google-Nest-Mini · .45".
const devName = (mac) => {
  const d = state.devices?.get(mac);
  if (!d) return mac;
  const label = deviceLabel(d);
  let n = 0;
  for (const x of state.devices.values()) if (deviceLabel(x) === label && ++n > 1) break;
  return n > 1 && d.ip ? `${label} · .${d.ip.split('.').pop()}` : label;
};

// Small line chart with y axis (unit), time axis, legend and values under the finger/pointer.
// series: [{ name, cls, pts: [[ts, value], ...] }], fmt: value -> text with unit.
const fmtRateBits = (bps) => (bps == null ? '–' : bps * 8 >= 1e6 ? `${fmtMbit((bps * 8) / 1e6)} Mbit/s` : `${Math.round((bps * 8) / 1e3)} kbit/s`);
const hhmm = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const SPARK_FMT = {
  mbit: (v) => `${fmtMbit(v)} Mbit/s`,
  ms: (v) => (v == null ? '–' : `${Math.round(v)} ms`),
  dbm: (v) => (v == null ? '–' : `${Math.round(v - 100)} dBm`),
};
function spark(series, fmt, note = '', fmtKey = '') {
  const pts = series.flatMap((s) => s.pts).filter((p) => p[1] != null);
  const xs = pts.map((p) => p[0]);
  if (new Set(xs).size < 2) return '<div class="muted small">Not enough data yet. The graph fills in minute by minute.</div>';
  const x0 = Math.min(...xs), dx = Math.max(...xs) - x0 || 1;
  const y1 = niceMax(Math.max(...pts.map((p) => p[1])) * 1.05 || 1);
  const W = 300, H = 90;
  const X = (x) => ((x - x0) / dx) * W, Y = (y) => H - (y / y1) * (H - 2) - 1;
  const line = (s) => s.pts.filter((p) => p[1] != null).map(([x, y]) => `${X(x).toFixed(1)},${Y(y).toFixed(1)}`).join(' ');
  const grid = [0.25, 0.5, 0.75].map((f) => `<line x1="0" x2="${W}" y1="${Y(y1 * f).toFixed(1)}" y2="${Y(y1 * f).toFixed(1)}"/>`).join('');
  const data = esc(JSON.stringify({ x0, dx, s: series.map((s) => ({ n: s.name, c: s.cls, p: s.pts })) }));
  const legend = series.map((s) => {
    const vals = s.pts.map((p) => p[1]).filter((v) => v != null);
    return `<span class="lg ${s.cls}"><i></i>${esc(s.name)}: now <b>${fmt(vals[vals.length - 1])}</b> · max ${fmt(Math.max(...vals))}</span>`;
  }).join('');
  return `<div class="sparkbox" data-spark="${data}" data-fmt="${fmtKey}">
    <div class="sp-y"><span>${fmt(y1)}</span><span>${fmt(y1 / 2)}</span><span>${fmtKey === "dbm" ? fmt(0) : 0}</span></div>
    <div class="sp-plot"><svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><g class="sp-grid">${grid}</g>${
      series.map((s) => `<polyline class="${s.cls}" points="${line(s)}"/>`).join('')}</svg><div class="sp-tip" hidden></div><div class="sp-cursor" hidden></div></div>
    <div class="sp-x"><span>${hhmm(x0)}</span><span>${hhmm(x0 + dx / 2)}</span><span>${hhmm(x0 + dx)}</span></div>
    <div class="sp-legend">${legend}${note ? `<span class="muted">${esc(note)}</span>` : ''}</div>
  </div>`;
}
// Show exact values where you point/tap in the chart.
function sparkHover(e) {
  const plot = e.target.closest?.('.sp-plot');
  $$('.sp-tip, .sp-cursor').forEach((el) => { if (!plot || !plot.contains(el)) el.hidden = true; });
  if (!plot) return;
  const box = plot.closest('.sparkbox'), d = JSON.parse(box.dataset.spark), fmt = SPARK_FMT[box.dataset.fmt] || (box.closest('#speed') ? SPARK_FMT.mbit : fmtRateBits);
  const r = plot.getBoundingClientRect(), cx = (e.touches?.[0] || e).clientX;
  const f = Math.min(1, Math.max(0, (cx - r.left) / r.width)), ts = d.x0 + f * d.dx;
  const near = (p) => p.reduce((a, b) => (Math.abs(b[0] - ts) < Math.abs(a[0] - ts) ? b : a));
  const rows = d.s.map((s) => { const q = near(s.p); return `<div class="lg ${s.c}"><i></i>${esc(s.n)}: <b>${fmt(q[1])}</b></div>`; });
  const tip = plot.querySelector('.sp-tip'), cur = plot.querySelector('.sp-cursor');
  tip.innerHTML = `<div class="muted">${hhmm(near(d.s[0].p)[0])}</div>${rows.join('')}`;
  tip.hidden = cur.hidden = false;
  cur.style.left = `${f * 100}%`;
  tip.style.left = f > 0.6 ? '' : `${f * 100 + 2}%`;
  tip.style.right = f > 0.6 ? `${(1 - f) * 100 + 2}%` : '';
}
document.addEventListener('mousemove', sparkHover);
document.addEventListener('touchstart', sparkHover, { passive: true });

async function loadSpeed() {
  try { state.speedHist = await api('/api/speedtests?hours=24'); } catch { state.speedHist = []; }
  renderSpeed();
}
function renderSpeed() {
  const st = state.status?.speedtest, h = state.speedHist || [];
  const last = h[h.length - 1] || st?.last;
  $('#speed').innerHTML = `
    <div class="speed-nums">
      <div><b>${fmtMbit(last?.down_mbps)}</b><span>Mbit/s down</span></div>
      <div><b>${fmtMbit(last?.up_mbps)}</b><span>Mbit/s up</span></div>
      <div><b>${last?.ping_ms != null ? Math.round(last.ping_ms) : '–'}</b><span>ms ping</span></div>
    </div>
    ${spark([{ name: 'Download', cls: 's-down', pts: h.map((r) => [r.ts, r.down_mbps]) }, { name: 'Upload', cls: 's-up', pts: h.map((r) => [r.ts, r.up_mbps]) }],
      (v) => `${fmtMbit(v)} Mbit/s`, 'measured internet speed, last 24 h')}
    ${last?.others_down_mbps != null ? `<div class="muted small">Includes what other devices used during the test: ${fmtMbit(last.others_down_mbps)} down · ${fmtMbit(last.others_up_mbps)} up Mbit/s (the test itself got ${fmtMbit(last.test_down_mbps)} · ${fmtMbit(last.test_up_mbps)}).</div>` : ''}
    <div class="muted small">${st?.error ? `Last test failed: ${esc(st.error)}`
      : last ? `Quick test every ${st?.interval_min} min · last ${fmtAgo(last.ts)} ago · graph: 24 h` : 'First test runs shortly.'}</div>`;
}
$('#speed-now').addEventListener('click', async (e) => {
  const b = e.currentTarget; b.disabled = true; b.textContent = 'Testing…';
  try { await api('/api/speedtest', 'POST'); await loadSpeed(); } catch (err) { alert(err.message); }
  b.disabled = false; b.textContent = 'Test now';
});

// ---------- overview: choose and order panels (saved in the browser) ----------
const OV_KEY = 'netmaster.overview';
function ovLayout() {
  const all = $$('#ov-grid > .ov-item').map((el) => el.dataset.ov);
  let saved = [];
  try { saved = JSON.parse(localStorage.getItem(OV_KEY)) || []; } catch { /* no storage */ }
  saved = saved.filter((x) => all.includes(x.id));
  // new panels land in their default place
  all.forEach((id, i) => { if (!saved.some((x) => x.id === id)) saved.splice(Math.min(i, saved.length), 0, { id, on: true }); });
  return saved;
}
function ovApply(lay = ovLayout()) {
  const g = $('#ov-grid');
  lay.forEach(({ id, on }) => { const el = g.querySelector(`[data-ov="${id}"]`); el.classList.toggle('ov-off', !on); g.appendChild(el); });
}
function ovSave(lay) {
  try { if (lay) localStorage.setItem(OV_KEY, JSON.stringify(lay)); else localStorage.setItem(OV_KEY, '[]'); } catch { /* no storage */ }
  ovApply(lay || undefined);
  ovEditor(lay || undefined);
}
function ovEditor(lay = ovLayout()) {
  const label = (id) => $(`#ov-grid [data-ov="${id}"]`).dataset.label;
  $('#ov-editor').innerHTML = `<div class="panel-head"><h2>Customize overview</h2><button class="ghost small" id="ov-done">Done</button></div>
    <div class="muted small">Tick the panels you want to see. Move them with the arrows. Saved on this device.</div>
    <ul class="ov-list">${lay.map((x, i) => `<li data-i="${i}">
      <label><input type="checkbox" ${x.on ? 'checked' : ''}> ${esc(label(x.id))}</label>
      <span><button class="ghost small" data-mv="-1" ${i ? '' : 'disabled'} aria-label="Move up">↑</button><button class="ghost small" data-mv="1" ${i < lay.length - 1 ? '' : 'disabled'} aria-label="Move down">↓</button></span></li>`).join('')}</ul>
    <button class="link small" id="ov-reset">Reset to default</button>`;
}
$('#ov-edit').addEventListener('click', () => { const e = $('#ov-editor'); e.hidden = !e.hidden; if (!e.hidden) ovEditor(); });
$('#ov-editor').addEventListener('click', (e) => {
  if (e.target.id === 'ov-done') { $('#ov-editor').hidden = true; return; }
  if (e.target.id === 'ov-reset') {
    const def = $$('#ov-grid > .ov-item').map((el) => el.dataset.ov).sort((a, b) => OV_DEFAULT.indexOf(a) - OV_DEFAULT.indexOf(b));
    ovSave(def.map((id) => ({ id, on: true })));
    return;
  }
  const b = e.target.closest('[data-mv]');
  if (!b) return;
  const lay = ovLayout(), i = +b.closest('li').dataset.i, j = i + +b.dataset.mv;
  [lay[i], lay[j]] = [lay[j], lay[i]];
  ovSave(lay);
});
$('#ov-editor').addEventListener('change', (e) => {
  const li = e.target.closest('li'), lay = ovLayout();
  lay[+li.dataset.i].on = e.target.checked;
  ovSave(lay);
});
const OV_DEFAULT = $$('#ov-grid > .ov-item').map((el) => el.dataset.ov);
ovApply();

// ---------- samtalskvalitet ----------
const GRADE = { good: ['ok', 'Good'], fair: ['warn', 'Fair'], poor: ['bad', 'Poor'] };
async function loadCalls() {
  try { state.calls = await api('/api/calls?hours=24'); } catch { state.calls = []; }
  renderCalls();
}
function renderCalls() {
  const c = state.status?.calls, n = c?.now, h = state.calls || [];
  if (!c) return;
  const [cls, word] = GRADE[n?.grade] || ['', '–'];
  const bad = h.filter((m) => m.grade === 'poor'), busy = bad.filter((m) => (m.load || 0) >= 20).length;
  $('#calls-sub').textContent = n ? `last minute · ${fmtAgo(n.ts + 60)} ago` : 'measuring…';
  $('#calls').innerHTML = `
    <div class="speed-nums">
      <div><b class="${cls}-text">${word}</b><span>for video calls</span></div>
      <div><b>${n?.ms != null ? Math.round(n.ms) : '–'}</b><span>ms delay</span></div>
      <div><b>${n ? Math.round(n.jitter) : '–'}</b><span>ms jitter</span></div>
      <div><b>${n ? n.loss : '–'}</b><span>% lost</span></div>
    </div>
    ${spark([{ name: 'Delay', cls: 's-down', pts: h.map((m) => [m.ts, m.ms]) }, { name: 'Jitter', cls: 's-up', pts: h.map((m) => [m.ts, m.jitter]) }],
      SPARK_FMT.ms, '', 'ms').replace('class="sparkbox"', 'class="sparkbox short"')}
    <div class="muted small" title="Good: under 100 ms delay, 20 ms jitter and 1 % loss">Last hour: ${c.hour.good} good · ${c.hour.fair} fair · ${c.hour.poor} poor min.${
      bad.length ? ` ${busy} of ${bad.length} poor min today while the network was busy${busy ? ' (QoS in the router helps)' : ''}.` : ''}</div>`;
}
setInterval(() => { if (!$('#tab-overview').hidden) loadCalls(); }, 60000);

async function loadUsage() {
  try {
    const [day, recent] = await Promise.all([api('/api/usage?hours=24'), api('/api/usage?hours=0.0834')]);
    state.usage24 = day.slice(0, 8);
    state.usage5 = new Map(recent.map((u) => [u.mac, u.down + u.up]));
  } catch { return; }
  renderUsage();
}
// Top list per day, with speed right now (from the router) and usage over the last 5 minutes.
function renderUsage() {
  const list = state.usage24;
  if (!list) return;
  const tr = state.status?.router?.traffic || {};
  const max = (list[0]?.down || 0) + (list[0]?.up || 0) || 1;
  $('#usage').innerHTML = list.length ? list.map((u) => {
    const sum = u.down + u.up, t = tr[u.mac], now = (t?.down || 0) + (t?.up || 0);
    const live = now * 8 >= 200_000 ? `<b>↓ ${fmtMbps(t.down || 0)}</b> ↑ ${fmtMbps(t.up || 0)}` : '<span class="muted">idle</span>';
    return `<li><div class="td-row"><span>${esc(devName(u.mac))}</span><span>${live}</span></div>
      <div class="bar"><i style="width:${Math.max(3, (sum / max) * 100)}%"></i></div>
      <div class="td-row small muted"><span>5 min: ${fmtBytes(state.usage5?.get(u.mac) || 0)}</span><span>24 h: ${fmtBytes(sum)} (↓${fmtBytes(u.down)} ↑${fmtBytes(u.up)})</span></div></li>`;
  }).join('') : '<li class="muted">Collecting data…</li>';
}
setInterval(loadUsage, 60 * 1000);

// Programs on the server that use the internet. A click shows where they talk to.
function renderHostFlows() {
  const hf = state.status?.host_flows;
  if (!hf) return;
  $('#hf-sub').textContent = hf.error ? hf.error : `${hf.ip || ''} · last hour${hf.learning ? ' · learning' : ''}`;
  const list = hf.procs.filter((p) => p.down + p.up > 100_000 || p.now[0] + p.now[1] > 1000);
  const max = Math.max(1, ...list.map((p) => p.down + p.up));
  $('#hostflows').innerHTML = list.length ? list.map((p) => {
    const open = state.openProc === p.name;
    const live = p.now[0] + p.now[1] > 1000 ? `↓${fmtBytes(p.now[0])}/s ↑${fmtBytes(p.now[1])}/s · ` : '';
    return `<li class="clickable" data-proc="${esc(p.name)}" title="${esc(p.exe || p.name)}">
      <div class="td-row"><span>${esc(p.name)}</span><span class="muted">${live}${fmtBytes(p.down + p.up)}</span></div>
      <div class="bar"><i style="width:${Math.max(3, ((p.down + p.up) / max) * 100)}%"></i></div>
      ${open ? `<div class="remotes">${p.exe ? `<div class="mono small muted">${esc(p.exe)}</div>` : ''}${p.remotes.map((r) =>
        `<div class="td-row small"><span><span class="mono">${esc(r.ip)}</span> <span class="badge">${esc(r.port || '')}</span>${r.host ? ` <span class="muted">${esc(r.host)}</span>` : ''}${r.geo ? `<br><span class="muted">${esc(geoText(r.geo))}</span>` : ''}</span>
         <span class="muted">↓${fmtBytes(r.down)} ↑${fmtBytes(r.up)} <button class="link small" data-trace="${esc(r.ip)}">Trace</button></span></div>`).join('')}</div>` : ''}
    </li>`;
  }).join('') : `<li class="muted">${hf.enabled ? 'No program has used the internet noticeably in the last hour.' : 'Not active.'}</li>`;
}
$('#hostflows').addEventListener('click', (e) => {
  const tr = e.target.closest('[data-trace]');
  if (tr) return traceRoute(tr.dataset.trace);
  const li = e.target.closest('[data-proc]');
  if (!li) return;
  state.openProc = state.openProc === li.dataset.proc ? null : li.dataset.proc;
  renderHostFlows();
  renderMap();
});

// ---------- map of where the server connects ----------
const flag = (cc) => (cc ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0))) : '');
const geoText = (g) => (g ? `${flag(g.cc)} ${[g.city, g.country].filter(Boolean).join(', ')}${g.org ? ` · ${g.org}` : ''}` : '');
function ensureMap() {
  if (state.map || !window.L) return state.map;
  state.map = L.map('map', { worldCopyJump: true }).setView([50, 10], 3);
  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18, attribution: '© OpenStreetMap' }).addTo(state.map);
  state.mapLayer = L.layerGroup().addTo(state.map);
  state.traceLayer = L.layerGroup().addTo(state.map);
  return state.map;
}
function renderMap() {
  const hf = state.status?.host_flows;
  // The map only shows the program selected in the list above, otherwise it gets too cluttered.
  // If the program is not in the last hour's traffic, the address from the event is shown instead.
  const x = state.mapExtra;
  const sel = hf?.procs.find((p) => p.name === state.openProc)
    || (x && x.name === state.openProc ? { name: x.name, remotes: [x] } : null);
  $('#map-panel').hidden = !sel;
  if (!sel || $('#tab-overview').hidden || !ensureMap()) return;
  $('#map-title').textContent = `Where ${sel.name} connects`;
  if (state.mapProc !== sel.name) {
    state.mapProc = sel.name;
    state.mapFitted = false;
    state.traceLayer.clearLayers();
    $('#hops').innerHTML = '';
    $('#trace-info').textContent = '';
    setTimeout(() => state.map.invalidateSize(), 0);
  }
  const pts = new Map();
  for (const p of [sel]) {
    for (const r of p.remotes) {
      if (r.geo?.lat == null) continue;
      const k = `${r.geo.lat},${r.geo.lon}`;
      const e = pts.get(k) || { g: r.geo, items: new Set() };
      e.items.add(`${esc(p.name)} → ${esc(r.host || r.ip)}`);
      pts.set(k, e);
    }
  }
  const sig = JSON.stringify([...pts].map(([k, e]) => [k, [...e.items]]));
  if (sig === state.mapSig) return;
  state.mapSig = sig;
  state.mapLayer.clearLayers();
  const home = hf.home?.lat != null ? [hf.home.lat, hf.home.lon] : null;
  const css = getComputedStyle(document.documentElement);
  const accent = css.getPropertyValue('--accent').trim(), info = css.getPropertyValue('--info').trim();
  if (home) L.circleMarker(home, { radius: 7, color: info, fillOpacity: 0.9 }).bindPopup('<b>Home</b>').addTo(state.mapLayer);
  for (const { g, items } of pts.values()) {
    const ll = [g.lat, g.lon];
    if (home) L.polyline([home, ll], { color: accent, weight: 1, opacity: 0.35 }).addTo(state.mapLayer);
    L.circleMarker(ll, { radius: 6, color: accent, fillOpacity: 0.8 })
      .bindPopup(`<b>${esc(geoText(g))}</b><br>${[...items].join('<br>')}`).addTo(state.mapLayer);
  }
  if (!state.mapFitted && pts.size) {
    state.mapFitted = true;
    state.map.fitBounds(L.latLngBounds([...pts.values()].map(({ g }) => [g.lat, g.lon]).concat(home ? [home] : [])), { padding: [20, 20], maxZoom: 6 });
  }
}
async function traceRoute(ip) {
  if (!ensureMap()) return;
  $('#trace-info').textContent = `Tracing ${ip}… (up to 30 s)`;
  $('#map').scrollIntoView({ behavior: 'smooth', block: 'center' });
  let hops;
  try { hops = await api(`/api/trace/${ip}`, 'POST'); } catch (err) { $('#trace-info').textContent = `Trace failed: ${err.message}`; return; }
  state.traceLayer.clearLayers();
  const bad = getComputedStyle(document.documentElement).getPropertyValue('--warn').trim();
  const geoHops = hops.filter((h) => h.geo?.lat != null);
  const home = state.status?.host_flows?.home;
  const line = (home?.lat != null ? [[home.lat, home.lon]] : []).concat(geoHops.map((h) => [h.geo.lat, h.geo.lon]));
  if (line.length > 1) L.polyline(line, { color: bad, weight: 3 }).addTo(state.traceLayer);
  geoHops.forEach((h) => L.circleMarker([h.geo.lat, h.geo.lon], { radius: 5, color: bad, fillOpacity: 1 })
    .bindPopup(`<b>Hop ${h.n}</b> ${esc(h.ip)}${h.ms != null ? ` · ${h.ms} ms` : ''}<br>${esc(geoText(h.geo))}`).addTo(state.traceLayer));
  if (line.length) state.map.fitBounds(L.latLngBounds(line), { padding: [30, 30], maxZoom: 7 });
  $('#trace-info').textContent = `Route to ${ip}: ${hops.length} hops`;
  $('#hops').innerHTML = hops.map((h) => `<li><span class="mono">${esc(h.ip)}</span>${h.ms != null ? ` · ${h.ms} ms` : ''}${h.geo ? ` · ${esc(geoText(h.geo))}` : ' · <span class="muted">private / unknown</span>'}</li>`).join('');
}

setInterval(() => $$('.inv-elapsed').forEach((el) => { el.textContent = `${Math.round((Date.now() - Number(el.dataset.t0)) / 1000)} s`; }), 1000);
// Result of "Investigate": what the device probably is, plus everything that could be found out.
function invHtml(r) {
  if (!r) return '';
  if (r.running) {
    const done = r.steps.filter((s) => s.summary != null).length;
    return `<div class="inv"><div class="inv-guess"><span class="spinner"></span> Investigating ${r.steps.length ? `${done}/${r.steps.length}` : '…'} · <span class="inv-elapsed" data-t0="${r.t0}">${Math.round((Date.now() - r.t0) / 1000)} s</span></div>
      <ul class="inv-steps">${r.steps.map((s) => `<li class="${s.summary != null ? 'done' : ''}"><span class="ic">${s.summary != null ? '✓' : '<span class="spinner"></span>'}</span>${esc(s.label)}${s.summary != null ? ` <span class="muted">: ${esc(s.summary)}</span>` : ''}</li>`).join('')}</ul></div>`;
  }
  const close = '<button class="ghost small inv-close" data-act="inv-close" title="Close">✕ Close</button>';
  if (r.error) return `<div class="inv danger-text small">${close}${esc(r.error)}</div>`;
  return `<div class="inv">${close}
    <div class="inv-guess">${r.guess.length ? `Probably: ${r.guess.map((g) => `<span class="badge">${esc(g)}</span>`).join(' ')}` : '<span class="muted">No clear match. See the details below.</span>'}</div>
    <dl>${r.facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}
      <dt>Open ports</dt><dd>${r.ports.length ? r.ports.map((p) => `<div><span class="badge">${p.port} ${esc(p.name)}</span>${p.banner ? ` <span class="muted small">${esc(p.banner)}</span>` : ''}</div>`).join('') : 'none of the common ports'}</dd>
    </dl></div>`;
}

// Detail row under a device: traffic over the last day, signal and open ports.
// Wi-Fi signal over the day. Values are drawn as dBm + 100 so the graph goes up for better signal.
function wifiHtml(w) {
  if (!w) return '';
  if (!w.points.length) return `<div class="muted small">Wi-Fi: ${w.conn ? `${esc(w.conn)} (no signal data, e.g. cable or an access point that does not report it)` : 'no data yet'}${w.switches ? ` · switched connection ${w.switches} times in 24 h` : ''}</div>`;
  return `${spark([{ name: 'Wi-Fi signal', cls: 's-up', pts: w.points.map(([ts, s]) => [ts, s + 100]) }], SPARK_FMT.dbm,
    `${w.conn ? `now ${w.conn} · ` : ''}switched connection ${w.switches} times in 24 h · above -60 dBm great, below -75 dBm weak`, 'dbm')}`;
}
// Filter form: choose the level (the whole site or one subdomain), who it applies to, and block/allow.
function domainLevels(domain) {
  const p = domain.split('.'), out = [];
  const minLen = p.length >= 3 && ['co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'or', 'ne', 'go'].includes(p[p.length - 2]) && p[p.length - 1].length === 2 ? 3 : 2;
  for (let i = 0; i <= p.length - minLen; i++) out.push(p.slice(i).join('.'));
  return out;
}
function fltHtml(domain) {
  const lv = domainLevels(domain), f = state.flt, d = state.devices.get(f.mac);
  return `<div class="flt">
    <div class="flt-head">Choose what to filter. It applies to that name and everything under it:</div>
    ${lv.map((x, i) => `<label><input type="radio" name="flt-lv" value="${esc(x)}" ${i === lv.length - 1 ? 'checked' : ''}> <span class="mono">${esc(x)}</span>${
      i === lv.length - 1 ? ' <span class="muted">(whole site)</span>' : i === 0 && lv.length > 1 ? ' <span class="muted">(only this exact name)</span>' : ''}</label>`).join('')}
    <label class="flt-for">For <select name="flt-scope"><option value="">all devices</option><option value="${f.mac}">only ${esc(d ? deviceLabel(d) : f.mac)}</option></select></label>
    <div class="flt-btns"><button class="ghost bad-text" data-act="flt-do" data-action="block">Block</button><button class="ghost ok-text" data-act="flt-do" data-action="allow">Allow</button><button class="ghost" data-act="flt-cancel">Cancel</button></div>
  </div>`;
}

// Which domains the device looked up through the DNS filter in the last day. Blocked ones are red.
function dnsHtml(x) {
  if (!x) return '';
  if (!x.enabled) return '<div class="muted small">Contacts: install a DNS filter module (e.g. AdGuard Home) under Settings → Modules to see which sites this device looks up.</div>';
  if (!x.total) return '<div class="muted small">Contacts (DNS filter, 24 h): no lookups. The device may use another DNS, or has been quiet.</div>';
  const show = state.dnsAll ? x.domains : x.domains.slice(0, 12);
  return `<details class="dns-box"${state.dnsOpen ? ' open' : ''}><summary class="small">Contacts (DNS filter, 24 h): <b>${x.distinct}</b> sites · ${x.total} lookups${x.blocked ? ` · <span class="bad-text">${x.blocked} blocked</span>` : ''}</summary>
    <ul class="dns-list">${show.map((r) => `<li class="${r.blocked >= r.n ? 'bad-text' : ''}"><span class="mono">${esc(r.domain)}</span><span class="muted">${r.n}${r.blocked ? ` · ${r.blocked} blocked` : ''}<button class="link small" data-act="flt" data-domain="${esc(r.domain)}" title="Block or allow this site in AdGuard">filter</button></span></li>${
      state.flt?.domain === r.domain ? `<li class="flt-row">${fltHtml(r.domain)}</li>` : ''}`).join('')}</ul>
    ${!state.dnsAll && x.domains.length > 12 ? `<button class="link small" data-act="dns-all">Show ${x.domains.length - 12} more</button>` : ''}</details>`;
}
// The name of an enabled smart-home module (e.g. "Home Assistant"), if any: devices can be shown there.
function smartHome() {
  const m = (state.status?.modules || []).find((x) => x.enabled && x.provides.includes('smart_home'));
  return m ? (m.label || m.name) : '';
}
function histRow(d) {
  const h = state.hist?.[d.mac], pr = state.status?.ports, t = state.status?.router?.traffic?.[d.mac];
  const ports = pr?.open?.[d.mac];
  const pts = h?.points || [];
  const total = pts.reduce((a, p) => a + p.down + p.up, 0);
  const portHtml = ports == null ? 'not scanned yet' : ports.length
    ? ports.map((p) => `<span class="badge${pr.risky.includes(p) ? ' bad' : ''}">${p} ${esc(pr.names[p] || '')}</span>`).join(' ') : 'none';
  return `<tr class="hist-row" data-mac="${d.mac}"><td colspan="${state.devColCount || 7}">
    ${h ? spark([{ name: 'Download', cls: 's-down', pts: pts.map((p) => [p.ts, p.down / h.bucket_s]) }, { name: 'Upload', cls: 's-up', pts: pts.map((p) => [p.ts, p.up / h.bucket_s]) }],
      fmtRateBits, `this device's average speed per ${Math.round(h.bucket_s / 60)} min, last 24 h`)
      : '<div class="muted small">Loading…</div>'}
    ${wifiHtml(state.wifiHist?.[d.mac])}
    ${dnsHtml(state.dnsHist?.[d.mac])}
    <div class="hist-actions">
      <button class="ghost small" data-act="watch">${d.watch ? '🔔 Notifying when it comes/goes · turn off' : '🔔 Notify me when it comes online or goes offline'}</button>
      ${smartHome() ? `<button class="ghost small" data-act="share" title="Adds this device to ${esc(smartHome())} (presence, IP/MAC, top sites and an Internet switch)">${d.share ? `🏠 Shown in ${esc(smartHome())} · remove` : `🏠 Show in ${esc(smartHome())}`}</button>` : ''}
      <button class="ghost small" data-act="wake" title="Wake-on-LAN: turns on a sleeping computer, if it has Wake-on-LAN enabled">⏻ Wake (Wake-on-LAN)</button>
    </div>
    <div class="hist-meta">
      <span>Last 24 h: <b>${fmtBytes(total)}</b></span>
      ${t?.conn ? `<span>Connection: <b>${esc(t.conn)}</b>${t.ssid ? ` · ${esc(t.ssid)}` : ''}${t.signal != null ? ` · signal ${esc(String(t.signal))}` : ''}</span>` : ''}
      <span>Open ports: ${portHtml}</span>
    </div>${invHtml(state.inv?.[d.mac])}</td></tr>`;
}

// ---------- swipe between tabs (mobile) ----------
{
  let x0 = null, y0 = 0;
  const main = document.querySelector('main');
  main.addEventListener('touchstart', (e) => {
    const el = e.target;
    // Let tables, charts and fields scroll sideways on their own.
    if (e.touches.length !== 1 || el.closest('input, textarea, .chart, .seg') ||
        [...$$('.table-wrap, .logs')].some((w) => w.contains(el) && w.scrollWidth > w.clientWidth)) { x0 = null; return; }
    x0 = e.touches[0].clientX; y0 = e.touches[0].clientY;
  }, { passive: true });
  main.addEventListener('touchend', (e) => {
    if (x0 == null) return;
    const dx = e.changedTouches[0].clientX - x0, dy = e.changedTouches[0].clientY - y0;
    x0 = null;
    if (Math.abs(dx) < 60 || Math.abs(dx) < Math.abs(dy) * 1.5) return;
    const o = $$('.tabs button').map((b) => b.dataset.tab);
    const cur = $('.tabs button[aria-selected="true"]')?.dataset.tab;
    const next = o[o.indexOf(cur) + (dx < 0 ? 1 : -1)];
    if (next) {
      showTab(next);
      $(`.tabs button[data-tab="${next}"]`)?.scrollIntoView({ inline: 'center', block: 'nearest' });
      window.scrollTo({ top: 0 });
    }
  }, { passive: true });
}

// ---------- diagram ----------
async function loadChart() {
  try {
    state.chartData = await api(`/api/samples?minutes=${state.range}`);
    renderChart();
  } catch (e) { console.warn(e); }
}

function seriesMeta() {
  const s = state.status;
  const all = s ? [...s.targets, ...s.dns.targets] : [];
  return all.map((t, i) => ({ key: t.key, name: t.name, color: cssVar(SERIES_COLORS[i % SERIES_COLORS.length]) }));
}

function renderChart() {
  const el = $('#chart');
  const data = state.chartData;
  const meta = seriesMeta();
  const W = el.clientWidth || 600, H = el.clientHeight || 240;
  const pad = { l: 44, r: 10, t: 10, b: 22 };
  const now = Date.now() / 1000, x0 = now - state.range * 60;
  const x = (ts) => pad.l + ((ts - x0) / (now - x0)) * (W - pad.l - pad.r);

  const visible = meta.filter((m) => !state.hidden.has(m.key) && data?.series[m.key]?.length);
  const vals = visible.flatMap((m) => data.series[m.key].map((p) => p[1]).filter((v) => v != null)).sort((a, b) => a - b);
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Response times over time">`;

  if (!vals.length) {
    svg += `<text class="empty" x="${W / 2}" y="${H / 2}" text-anchor="middle">No measurements yet</text></svg>`;
    el.innerHTML = svg;
    renderLegend(meta);
    return;
  }
  // The scale follows the highest value so peaks are never cut off.
  const yMax = niceMax(Math.max(vals[vals.length - 1] * 1.05, 5));
  const y = (v) => pad.t + (1 - Math.min(v, yMax) / yMax) * (H - pad.t - pad.b);

  for (let i = 0; i <= 4; i++) {
    const v = (yMax / 4) * i, yy = y(v);
    svg += `<line class="gridline" x1="${pad.l}" x2="${W - pad.r}" y1="${yy}" y2="${yy}"/>`;
    svg += `<text class="axis" x="${pad.l - 6}" y="${yy + 4}" text-anchor="end">${Math.round(v)} ms</text>`;
  }
  const ticks = 5;
  for (let i = 0; i <= ticks; i++) {
    const ts = x0 + ((now - x0) / ticks) * i;
    const d = new Date(ts * 1000);
    const lbl = state.range > 1440 ? d.toLocaleDateString(LOCALE, { weekday: 'short', day: 'numeric' }) : d.toLocaleTimeString(LOCALE, { hour: '2-digit', minute: '2-digit' });
    svg += `<text class="axis" x="${x(ts)}" y="${H - 6}" text-anchor="${i === 0 ? 'start' : i === ticks ? 'end' : 'middle'}">${lbl}</text>`;
  }

  const gapLimit = data.bucket_s * 3;
  for (const m of visible) {
    const pts = data.series[m.key];
    let d = '', prev = null;
    const lossMarks = [];
    for (const [ts, v, loss] of pts) {
      if (loss > 0) lossMarks.push([ts, loss]);
      if (v == null) { prev = null; continue; }
      d += `${prev == null || ts - prev > gapLimit ? 'M' : 'L'}${x(ts).toFixed(1)},${y(v).toFixed(1)}`;
      prev = ts;
    }
    svg += `<path d="${d}" fill="none" stroke="${m.color}" stroke-width="1.6" stroke-linejoin="round"/>`;
    // Number at the series' highest peak.
    const peak = pts.reduce((a, p) => (p[1] != null && (!a || p[1] > a[1]) ? p : a), null);
    if (peak) {
      const px = x(peak[0]), py = y(peak[1]);
      const anchor = px > W - 60 ? 'end' : px < pad.l + 30 ? 'start' : 'middle';
      svg += `<circle cx="${px}" cy="${py}" r="3" fill="${m.color}"/>`;
      svg += `<text class="peak" x="${px}" y="${Math.max(pad.t + 9, py - 6)}" text-anchor="${anchor}" fill="${m.color}">${Math.round(peak[1])} ms</text>`;
    }
    for (const [ts, loss] of lossMarks) {
      svg += `<rect x="${x(ts) - 1}" y="${pad.t}" width="2" height="${(H - pad.t - pad.b) * Math.min(1, 0.15 + loss)}" fill="${cssVar('--bad')}" opacity="${0.25 + 0.6 * loss}"><title>${m.name}: ${Math.round(loss * 100)} % loss ${fmtTime(ts)}</title></rect>`;
    }
  }
  svg += '</svg>';
  el.innerHTML = svg;
  renderLegend(meta);
}

function niceMax(v) {
  const p = 10 ** Math.floor(Math.log10(v));
  // Tight steps so the highest peak lands near the top (54 ms -> 60, not 100).
  for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function renderLegend(meta) {
  $('#legend').innerHTML = meta.map((m) => `
    <button data-key="${esc(m.key)}" aria-pressed="${!state.hidden.has(m.key)}"><i style="background:${m.color}"></i>${esc(m.name)}</button>`).join('');
  $$('#legend button').forEach((b) => b.addEventListener('click', () => {
    const k = b.dataset.key;
    state.hidden.has(k) ? state.hidden.delete(k) : state.hidden.add(k);
    renderChart();
  }));
}

$$('#range button').forEach((b) => b.addEventListener('click', () => {
  $$('#range button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  state.range = Number(b.dataset.min);
  loadChart();
}));
window.addEventListener('resize', () => renderChart());

// ---------- events ----------
const NEW_PROG = 'New program on the server is using the internet: ';
const progIp = (detail) => (detail || '').match(/Talking to (\d+\.\d+\.\d+\.\d+)/)?.[1] || '';
function eventHtml(e) {
  const prog = e.title.startsWith(NEW_PROG) ? e.title.slice(NEW_PROG.length) : null;
  const ip = prog ? progIp(e.detail) : '';
  return `<li class="${e.severity}${prog ? ' clickable' : ''}"${prog ? ` data-proc="${esc(prog)}" data-ip="${esc(ip)}" title="Show on map"` : ''}>
    <span class="dot"></span>
    <span class="title">${esc(e.title)}<span class="tag">${CAT_LABEL[e.category] || esc(e.category)}</span>${prog ? '<span class="tag">Map →</span>' : ''}</span>
    <span class="meta">${fmtTime(e.ts)}${e.severity !== 'info' ? muteMark(e) : ''}</span>
    ${e.detail ? `<span class="detail">${esc(e.detail)}</span>` : ''}
  </li>`;
}
// The Events tab shows EV_STEP events; "Show more" adds more and fetches older ones from the server when needed.
const EV_STEP = 20;
state.evShown = EV_STEP;
function renderEvents() {
  const all = state.events.filter((e) => !state.evFilter || e.category === state.evFilter);
  const list = all.slice(0, state.evShown);
  $('#events').innerHTML = list.map(eventHtml).join('') || '<li><span class="none">No events</span></li>';
  const more = all.length > list.length || !state.evEnd;
  const box = $('#ev-more');
  box.hidden = !list.length || !more && state.evShown <= EV_STEP;
  box.innerHTML = `<span class="muted">Showing ${list.length}</span>
    ${more ? `<button type="button" class="link" data-ev-more="${EV_STEP}">Show ${EV_STEP} more</button>
      <button type="button" class="link" data-ev-more="100">Show 100 more</button>` : ''}
    ${state.evShown > EV_STEP ? `<button type="button" class="link" data-ev-more="0">Show fewer</button>` : ''}`;
  const recent = state.events.filter((e) => e.severity !== 'info' || e.category !== 'system').slice(0, 8);
  $('#recent-events').innerHTML = recent.map(eventHtml).join('') || '<li><span class="none">Nothing to report</span></li>';
}
$$('#ev-filter button').forEach((b) => b.addEventListener('click', () => {
  $$('#ev-filter button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  state.evFilter = b.dataset.cat;
  state.evShown = EV_STEP;
  renderEvents();
}));
$('#ev-more').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-ev-more]');
  if (!b) return;
  const n = Number(b.dataset.evMore);
  if (!n) { state.evShown = EV_STEP; renderEvents(); return; }
  state.evShown += n;
  b.disabled = true;
  // fetch older events until there are enough of the chosen category, or there are no more
  const have = () => state.events.filter((x) => !state.evFilter || x.category === state.evFilter).length;
  try {
    while (!state.evEnd && have() < state.evShown) {
      const last = state.events.at(-1);
      const older = await api(`/api/events?limit=200${last ? `&before_id=${last.id}` : ''}`);
      state.events.push(...older);
      if (older.length < 200) state.evEnd = true;
    }
  } catch (err) { console.warn(err); }
  renderEvents();
});

// ---------- routerloggar ----------
async function loadLogs() {
  try {
    state.logs = await api('/api/syslog?limit=500');
    state.logsLoaded = true;
    renderLogs();
  } catch (e) { console.warn(e); }
}
// Tidy router log lines: "date time LEVEL TYPE: text" -> "Type: text". Full line on hover.
const LOG_TYPES = {
  NAT: 'Port forwarding', UPNP: 'UPnP', QOS: 'QoS', FIREWALL: 'Firewall', BASIC_SECURITY: 'Basic security',
  ACCESS_CONTROL: 'Access control', PARENTAL_CONTROL: 'Parental control', TRAFFIC_STATS: 'Traffic stats',
  REMOTE_MANAGEMENT: 'Remote management', LOCAL_MANAGEMENT: 'Local management', TIME_SETTINGS: 'Time',
  FACTORY_RESET: 'Factory reset', LED_CONTROLLER: 'LEDs', MODEM: 'Modem', DHCPS: 'DHCP server',
  DHCPC: 'DHCP client', WAN: 'WAN', WIRELESS: 'Wi-Fi', WIFI: 'Wi-Fi', SYSTEM: 'System', IMB: 'IP/MAC binding',
  DDNS: 'Dynamic DNS', VPN: 'VPN', OPENVPN: 'OpenVPN', PPTP: 'PPTP', HOMECARE: 'HomeShield', SECURITY: 'Security',
};
const LOG_PHRASES = [
  [/Virtual server created succeeded\[ex-port:(\S+) ip:(\S+) in-port:(\S+) protocol:(\S+)\]/i,
    'Port $1 opened to the internet → $2:$3 ($4)'],
  [/backup: switch network to (\S+?)\.?$/i, 'Internet connection switched to $1'],
  [/Start to run NIGHT/i, 'LED night mode'],
];
function translateLog(msg) {
  const m = msg.match(/^(?:\S+ \S+ )?(?:[A-Z]+ )?([A-Z_]+): (.*)$/);  // "date time LEVEL TYPE: text"
  if (!m) return null;
  let text = m[2];
  for (const [re, out] of LOG_PHRASES) if (re.test(text)) { text = text.replace(re, out); break; }
  const type = LOG_TYPES[m[1]] || m[1];
  return `${type}: ${text}`;
}
function logHtml(l) {
  const st = state.status || {};
  const name = st.syslog?.sources.find((s) => s.host === l.host)?.name
    || (st.router?.host === l.host && (st.router.model || 'Main router'))
    || st.modules?.find((m) => m.host === l.host)?.label || l.host;
  const nice = translateLog(l.message);
  return `<div class="sev${l.severity}"><span class="t">${fmtTime(l.ts)}</span><span class="h">${esc(name)}</span><span class="m" title="${esc(l.message)}">${esc(nice || l.message)}</span></div>`;
}
function renderLogs() {
  const q = $('#log-search').value.trim().toLowerCase();
  const list = q ? state.logs.filter((l) => l.message.toLowerCase().includes(q) || l.host.includes(q)) : state.logs;
  $('#logs').innerHTML = list.map(logHtml).join('');
}
// Where the logs come from: modules read them from the routers; syslog is an optional extra.
function logSources() {
  const st = state.status || {}, sl = st.syslog, out = [];
  const src = (name, ok, text) => out.push({ name, ok, text });
  (st.modules || []).filter((m) => m.enabled && m.provides.includes('logs')).forEach((m) => src(m.label || m.name,
    !m.last_error && !!m.last_ok, m.last_error ? esc(m.last_error) : m.last_ok ? `read directly · ${fmtAgo(m.last_ok)} ago` : 'connecting…'));
  (sl?.sources || []).forEach((s) => src(s.name || s.host, true, 'sends syslog'));
  return out;
}
function renderLogHelp() {
  const srcs = logSources(), sl = state.status?.syslog;
  if (!state.status) return;
  $('#log-help').innerHTML = srcs.length
    ? `<div class="log-srcs">${srcs.map((s) => `<span class="${s.ok ? 'ok-text' : 'warn-text'}">${s.ok ? '✓' : '!'} <b>${esc(s.name)}</b> <span class="muted">${s.text}</span></span>`).join('')}</div>`
    : `No log source is connected. Install a router module under Settings → Modules, or set the router to send its system log to this computer, port <code>${sl?.port}</code> (UDP).`;
}
$('#log-search').addEventListener('input', renderLogs);

// ---------- devices ----------
const ONLINE_S = 600;
async function loadDnsTop() {
  try { state.dnsTop = await api('/api/dns-top?hours=24'); renderDevices(); } catch { /* no DNS filter module */ }
}
setInterval(() => { if (!$('#tab-devices').hidden) loadDnsTop(); }, 300000);
async function loadDevices() {
  try {
    const list = await api('/api/devices');
    const first = !state.devices?.size;
    state.devices = new Map(list.map((d) => [d.mac, d]));
    renderDevices();
    if (first) renderEvents();  // device names in the 🔕 texts
    loadDnsTop();
  } catch (e) { console.warn(e); }
}
function fmtBytes(n) {
  if (n == null) return '–';
  const u = ['B', 'kB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}
function trafficHtml(t) {
  if (!t) return '<span class="host">–</span>';
  // Rounded in the list; exact values and a graph appear when you click the device.
  const r = (bps) => { const b = (bps || 0) * 8; if (!b) return "0"; return b >= 1e6 ? `${b >= 1e7 ? Math.round(b / 1e6) : (b / 1e6).toFixed(1)} Mbit/s` : `${Math.max(1, Math.round(b / 1e3))} kbit/s`; };
  const speed = (t.down || 0) + (t.up || 0) >= 125 ? `↓${r(t.down)} · ↑${r(t.up)}` : 'idle';
  const tot = t.usage == null ? '–' : fmtBytes(t.usage).replace(/(\d+)\.\d+/, '$1');
  return `${speed}<span class="host">${tot} total</span>`;
}
function deviceLabel(d) { return d.name || d.hostname || d.vendor || (d.randomized ? 'Unknown (random MAC)' : 'Unknown device'); }
// Icon buttons. The text shows as a tooltip and is read out by screen readers.
const ICONS = {
  approve: '<path d="M20 6 9 17l-5-5"/>',
  approved: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  investigate: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  forget: '<path d="M4 7h16M10 7V4h4v3M6 7l1 13h10l1-13"/>',
  locked: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  pause: '<circle cx="12" cy="12" r="9"/><path d="M10 9v6M14 9v6"/>',
  paused: '<circle cx="12" cy="12" r="9"/><path d="m10 8.5 5 3.5-5 3.5z"/>',
};
const icon = (n) => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[n]}</svg>`;
const iconBtn = (act, ic, tip) => `<button class="ib ib-${ic}" data-act="${act}" title="${tip}" aria-label="${tip}">${icon(ic)}</button>`;

// Legend under the table, so the icons can be understood on mobile too (no tooltips there).
$('#dev-legend').innerHTML = [['approve', 'Approve'], ['approved', 'Approved (tap to undo)'], ['investigate', 'Investigate'], ['pause', 'Pause internet'], ['paused', 'Paused (tap to resume)'], ['forget', 'Forget']]
  .map(([i, t]) => `<span class="ib-${i}">${icon(i)}${t}</span>`).join('');

// If all devices share the first three parts (e.g. 192.168.0.), only the last part is shown. Otherwise the whole address.
const shortIp = (ip) => {
  if (!ip) return '–';
  const pre = ip.slice(0, ip.lastIndexOf('.') + 1);
  for (const d of state.devices?.values() || []) if (d.ip && !d.ip.startsWith(pre)) return ip;
  return ip.slice(pre.length - 1);
};

// Columns in the device table. Which ones show, and in what order, is saved in the browser.
const DEV_COLS = [
  { id: 'name', label: 'Name', fixed: true, cell: (d, c) => `<td class="name"><span class="nm${d.name ? '' : ' placeholder'} ${c.on ? 'is-on' : 'is-off'}" data-act="rename" title="Click to rename · ${c.on ? 'online' : 'offline'}">${esc(c.label)}</span>${state.status?.router?.blocked?.includes(d.mac) ? ' <span class="badge bad">Internet paused</span>' : ''}${d.watch ? ' <span class="badge" title="You get a notification when it comes online or goes offline">🔔</span>' : ''}${d.share && smartHome() ? ` <span class="badge" title="Shown in ${esc(smartHome())}">🏠</span>` : ''}${c.risky.length ? ` <span class="badge bad" title="Risky open ports">${c.risky.map((p) => esc(c.pr.names[p])).join(', ')}</span>` : ''}${c.sub ? `<span class="host">${esc(c.sub)}</span>` : ''}</td>` },
  { id: 'ip', label: 'IP', cell: (d, c) => `<td class="mono clickable ${c.on ? 'is-on' : 'is-off'}" data-act="investigate" title="${esc(d.ip)} · Investigate: find out what this device is">${esc(shortIp(d.ip))}</td>` },
  { id: 'vendor', label: 'Vendor', cell: (d) => `<td>${esc(d.vendor || '–')}</td>` },
  { id: 'mac', label: 'MAC', cell: (d) => `<td class="mono">${esc(d.mac)}</td>` },
  { id: 'traffic', label: 'Traffic', th: 'class="num" title="Current speed (down/up) and total traffic since connecting"', cell: (d, c) => `<td class="num clickable" data-act="history" title="Show history">${trafficHtml(c.t)}</td>` },
  { id: 'seen', label: 'Last seen', cell: (d, c) => `<td><span class="online-dot ${c.on ? 'on' : ''}"></span>${c.on ? 'Now' : `${fmtAgo(d.last_seen)} ago`}</td>` },
  { id: 'sites', label: 'Top sites', th: 'title="Most looked-up sites in the last 24 h, from the DNS filter"', cell: (d) => {
    const x = state.dnsTop?.[d.ip];
    return `<td class="small sites-cell" title="${x ? `${x.sites} sites · ${x.total} lookups in 24 h` : ''}">${x ? `${esc(x.top.join(', '))}${x.blocked ? ` <span class="bad-text">· ${x.blocked} blocked</span>` : ''}` : '<span class="muted">–</span>'}</td>`;
  } },
  { id: 'conn', label: 'Connection', off: true, cell: (d, c) => `<td>${esc([c.t?.conn, c.t?.signal != null ? `${c.t.signal} dBm` : null].filter(Boolean).join(' · ') || '–')}</td>` },
  { id: 'hostname', label: 'Hostname', off: true, cell: (d) => `<td class="mono">${esc(d.hostname || '–')}</td>` },
  { id: 'first', label: 'First seen', off: true, cell: (d) => `<td>${d.first_seen ? fmtTime(d.first_seen) : '–'}</td>` },
  { id: 'ports', label: 'Open ports', off: true, cell: (d, c) => `<td class="small">${(c.pr?.open?.[d.mac] || []).map((p) => `<span class="badge${c.pr.risky.includes(p) ? ' bad' : ''}">${p}</span>`).join(' ') || '–'}</td>` },
  { id: 'actions', label: 'Actions', th: '', cell: (d) => `<td class="act-cell"><div class="row-actions">${d.trusted
    ? iconBtn('untrust', 'approved', 'Approved (known device). Tap to remove the approval.')
    : iconBtn('trust', 'approve', 'Approve: mark as a known device you recognise')}${
    iconBtn('investigate', 'investigate', 'Investigate: find out what this device is')}${
    state.status?.protected?.[d.mac]
      ? `<span class="ib ib-locked" title="Can't pause internet: this is ${esc(state.status.protected[d.mac])}">${icon('locked')}</span>`
      : state.status?.router?.blocked?.includes(d.mac)
      ? iconBtn('unblock', 'paused', 'Internet is paused for this device. Tap to turn it back on.')
      : iconBtn('block', 'pause', 'Pause internet for this device (blocks it in the router)')}${
    iconBtn('forget', 'forget', 'Forget: remove from the list (alerts again if it reconnects)')}</div></td>` },
];
function devCols() {
  let saved = [];
  try { saved = JSON.parse(localStorage.getItem('nm.devcols') || '[]'); } catch { /* no storage */ }
  const byId = new Map(DEV_COLS.map((c) => [c.id, c]));
  const cols = saved.filter((s) => byId.has(s.id)).map((s) => ({ ...byId.get(s.id), on: byId.get(s.id).fixed || s.on }));
  // New columns (that did not exist when the choice was saved) land in their usual place, before Actions.
  DEV_COLS.forEach((c, i) => { if (!cols.some((x) => x.id === c.id)) cols.splice(Math.min(i, cols.findIndex((x) => x.id === 'actions') + 1 || cols.length), 0, { ...c, on: !c.off }); });
  return cols;
}
function saveDevCols(cols) {
  try { localStorage.setItem('nm.devcols', JSON.stringify(cols.map((c) => ({ id: c.id, on: c.on })))); } catch { /* no storage */ }
}
function renderDevColsPanel() {
  const cols = devCols();
  $('#dev-cols').innerHTML = `<div class="small muted">Choose which columns to show, and their order.</div><ul>${cols.map((c, i) => `<li data-col="${c.id}">
      <label><input type="checkbox" ${c.on ? 'checked' : ''} ${c.fixed ? 'disabled' : ''}> ${esc(c.label)}</label>
      <span><button class="ghost small" data-move="-1" ${i === 0 ? 'disabled' : ''} aria-label="Move up">↑</button><button class="ghost small" data-move="1" ${i === cols.length - 1 ? 'disabled' : ''} aria-label="Move down">↓</button></span></li>`).join('')}</ul>
    <button class="link small" data-reset>Reset to default</button>`;
}
$('#dev-cols-btn').addEventListener('click', (e) => {
  const p = $('#dev-cols');
  p.hidden = !p.hidden;
  e.currentTarget.setAttribute('aria-expanded', String(!p.hidden));
  if (!p.hidden) renderDevColsPanel();
});
$('#dev-cols').addEventListener('click', (e) => {
  if (e.target.closest('[data-reset]')) {
    try { localStorage.removeItem('nm.devcols'); } catch { /* no storage */ }
  } else {
    const li = e.target.closest('[data-col]'), mv = e.target.closest('[data-move]');
    if (!li || !mv) return;
    const cols = devCols(), i = cols.findIndex((c) => c.id === li.dataset.col), j = i + Number(mv.dataset.move);
    [cols[i], cols[j]] = [cols[j], cols[i]];
    saveDevCols(cols);
  }
  renderDevColsPanel();
  renderDevices();
});
$('#dev-cols').addEventListener('change', (e) => {
  const li = e.target.closest('[data-col]');
  if (!li) return;
  const cols = devCols();
  cols.find((c) => c.id === li.dataset.col).on = e.target.checked;
  saveDevCols(cols);
  renderDevices();
});

function renderDevices() {
  if (state.editing) return; // don't overwrite a name that is being edited
  const now = Date.now() / 1000;
  const q = $('#dev-search').value.trim().toLowerCase();
  const all = [...state.devices.values()];
  const list = all.filter((d) => {
    if (state.devFilter === 'new' && d.trusted) return false;
    if (state.devFilter === 'online' && now - d.last_seen > ONLINE_S) return false;
    if (q && ![d.name, d.hostname, d.vendor, d.ip, d.mac].some((x) => (x || '').toLowerCase().includes(q))) return false;
    return true;
  }).sort((a, b) => a.trusted - b.trusted || ipNum(a.ip) - ipNum(b.ip));

  const untrusted = all.filter((d) => !d.trusted).length;
  const online = all.filter((d) => now - d.last_seen < ONLINE_S).length;
  $('#dev-count').textContent = `${all.length} devices · ${online} online`;
  $('#dev-trust-all').hidden = !untrusted;

  const inv = state.status?.security?.inventory;
  let banner = '';
  if (inv?.in_baseline) {
    banner = `<div class="banner">Inventory in progress until ${fmtTime(inv.baseline_until)}. Devices found until then are treated as known. After that, every new device raises an alert.</div>`;
  } else if (untrusted) {
    banner = `<div class="banner warn"><b>${untrusted} device${untrusted > 1 ? 's are' : ' is'} not approved.</b> Approve the ones you recognise. Find out what unknown devices are, or change your Wi-Fi password.</div>`;
  }
  $('#dev-banner').innerHTML = banner;

  const cols = devCols().filter((c) => c.on);
  state.devColCount = cols.length;
  $('#dev-head').innerHTML = cols.map((c) => `<th ${c.th ?? ''}>${c.id === 'actions' ? '' : esc(c.label)}</th>`).join('');
  const pr = state.status?.ports;
  $('#devices').innerHTML = list.map((d) => {
    const ctx = {
      on: now - d.last_seen < ONLINE_S, label: deviceLabel(d), pr, t: state.status?.router?.traffic?.[d.mac],
      sub: [d.name && d.hostname ? d.hostname : null, d.randomized ? 'random MAC' : null].filter(Boolean).join(' · '),
      risky: (pr?.open?.[d.mac] || []).filter((p) => pr.risky.includes(p)),
    };
    return `<tr class="${d.trusted ? '' : 'untrusted'}" data-mac="${d.mac}">${cols.map((c) => c.cell(d, ctx)).join('')}</tr>${state.openHist === d.mac ? histRow(d) : ''}`;
  }).join('') || `<tr><td colspan="${cols.length}" class="muted">No devices</td></tr>`;
}
const ipNum = (ip) => (ip || '0.0.0.0').split('.').reduce((a, b) => a * 256 + Number(b), 0);

$('#devices').addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-act]');
  if (!btn) return;
  const mac = btn.closest('tr').dataset.mac;
  const act = btn.dataset.act;
  if (act === 'rename') return startRename(btn, mac);
  if (act === 'history') {
    state.openHist = state.openHist === mac ? null : mac;
    renderDevices();
    if (state.openHist) {
      api(`/api/usage/${mac}?hours=24`).then((h) => { (state.hist ||= {})[mac] = h; renderDevices(); });
      api(`/api/wifi/${mac}?hours=24`).then((w) => { (state.wifiHist ||= {})[mac] = w; renderDevices(); }).catch(() => {});
      api(`/api/dns/${mac}?hours=24`).then((x) => { (state.dnsHist ||= {})[mac] = x; renderDevices(); }).catch(() => {});
    }
    return;
  }
  if (act === 'inv-close') {
    delete state.inv[mac];
    state.openHist = null;
    renderDevices();
    return;
  }
  if (act === 'investigate') {
    state.openHist = mac;
    if (state.inv?.[mac]?.running) return;
    const run = (state.inv ||= {})[mac] = { running: true, t0: Date.now(), steps: [] };
    renderDevices();
    $(`tr[data-mac="${mac}"] + .hist-row`)?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    if (!state.hist?.[mac]) api(`/api/usage/${mac}?hours=24`).then((h) => { (state.hist ||= {})[mac] = h; renderDevices(); });
    try {
      // The server sends one line of JSON per finished step, so you can see how far it has come.
      const r = await fetch(`/api/devices/${mac}/investigate`, { method: 'POST', cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const reader = r.body.getReader(), dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const ev = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
          if (ev.steps) run.steps = ev.steps;
          if (ev.step) { const s = run.steps.find((x) => x.id === ev.step); if (s) s.summary = ev.summary; }
          if (ev.result) state.inv[mac] = ev.result;
          renderDevices();
        }
      }
      if (state.inv[mac] === run) throw new Error('no result');
    } catch (err) { state.inv[mac] = { error: `Investigation failed: ${err.message}` }; }
    renderDevices();
    return;
  }
  if (act === 'block' || act === 'unblock') {
    const d = state.devices.get(mac), name = d ? deviceLabel(d) : mac;
    if (act === 'block' && !confirm(`Pause internet for ${name}?\n\nThe main router blocks it until you turn it back on. It stays connected to Wi-Fi but gets no internet.`)) return;
    btn.disabled = true;
    try {
      const r = await api(`/api/devices/${mac}/block`, 'POST', { blocked: act === 'block' });
      const ra = state.status.router;
      ra.blocked = (ra.blocked || []).filter((m) => m !== mac).concat(r.blocked ? [mac] : []);
    } catch (err) { alert(err.message); }
    renderDevices();
    return;
  }
  if (act === 'flt') { state.flt = { mac, domain: btn.dataset.domain }; state.dnsOpen = true; renderDevices(); return; }
  if (act === 'flt-cancel') { state.flt = null; renderDevices(); return; }
  if (act === 'flt-do') {
    const box = btn.closest('.flt'), domain = box.querySelector('[name=flt-lv]:checked').value, scope = box.querySelector('[name=flt-scope]').value;
    const action = btn.dataset.action;
    if (action === 'block' && !scope && !confirm(`Block ${domain} and everything under it for all devices?`)) return;
    btn.disabled = true;
    try {
      await api('/api/dnsfilter/rules', 'POST', { domain, action, mac: scope || null });
      state.flt = null;
      renderDevices();
      alert(`${action === 'block' ? 'Blocked' : 'Allowed'}: ${domain}${scope ? ' for this device' : ' for all devices'}. Devices may keep a cached answer for a few minutes.`);
    } catch (err) { alert(err.message); btn.disabled = false; }
    return;
  }
  if (act === 'dns-all') { state.dnsAll = true; state.dnsOpen = true; renderDevices(); return; }
  if (act === 'watch') {
    const d = state.devices.get(mac);
    state.devices.set(mac, await api(`/api/devices/${mac}`, 'PATCH', { watch: !d.watch }));
    renderDevices();
    return;
  }
  if (act === 'share') {
    const d = state.devices.get(mac);
    state.devices.set(mac, await api(`/api/devices/${mac}`, 'PATCH', { share: !d.share }));
    renderDevices();
    return;
  }
  if (act === 'wake') {
    try { await api(`/api/devices/${mac}/wake`, 'POST'); btn.textContent = 'Wake signal sent ✓'; } catch (err) { alert(err.message); }
    return;
  }
  if (act === 'untrust' && !confirm('Remove the approval? The device will be listed as not approved again.')) return;
  if (act === 'forget' && !confirm('Forget this device? It will alert as new if it shows up again.')) return;
  try {
    if (act === 'trust' || act === 'untrust') {
      const d = await api(`/api/devices/${mac}`, 'PATCH', { trusted: act === 'trust' });
      state.devices.set(mac, d);
    } else if (act === 'forget') {
      await api(`/api/devices/${mac}`, 'DELETE');
      state.devices.delete(mac);
    }
    renderDevices();
  } catch (err) { alert(`Failed: ${err.message}`); }
});
function startRename(el, mac) {
  const d = state.devices.get(mac);
  const input = document.createElement('input');
  input.value = d.name || '';
  input.placeholder = d.hostname || d.vendor || 'Name';
  el.replaceWith(input);
  input.focus();
  state.editing = mac;
  let done = false;
  const finish = async (save) => {
    if (done) return;
    done = true;
    state.editing = null;
    if (save && input.value.trim() !== (d.name || '')) {
      try { state.devices.set(mac, await api(`/api/devices/${mac}`, 'PATCH', { name: input.value.trim() })); } catch (err) { alert(err.message); }
    }
    renderDevices();
  };
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') finish(true); if (e.key === 'Escape') finish(false); });
  input.addEventListener('blur', () => finish(true));
}
$$('#dev-filter button').forEach((b) => b.addEventListener('click', () => {
  $$('#dev-filter button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  state.devFilter = b.dataset.f;
  renderDevices();
}));
$('#dev-search').addEventListener('input', renderDevices);
$('#dev-scan').addEventListener('click', async (e) => {
  const b = e.currentTarget; b.disabled = true; b.textContent = 'Scanning…';
  try { await api('/api/devices/scan', 'POST'); await loadDevices(); } catch (err) { alert(err.message); }
  b.disabled = false; b.textContent = 'Scan now';
});
$('#dev-trust-all').addEventListener('click', async () => {
  if (!confirm('Approve all devices that are not approved?')) return;
  await api('/api/devices/trust-all', 'POST');
  loadDevices();
});

// ---------- settings ----------
function row(k, v, act = '') {
  return `<div class="row"><span class="k">${k}</span><span class="v">${v}</span><span class="act">${act}</span></div>`;
}
async function renderAdgRules() {
  const el = $('#adg-rules');
  if (!state.status?.dnsfilter?.enabled) { el.innerHTML = '<div class="muted small">No DNS filter module is set up. Install one under Modules.</div>'; return; }
  try {
    const { rules } = await api('/api/dnsfilter/rules');
    const nice = (r) => { const m = r.match(/^(@@)?\|\|([^^$]+)\^?(?:\$(.*))?$/); if (m) m[3] = (m[3] || '').match(/client='([^']+)'/)?.[1]; return m ? `${m[1] ? '<span class="ok-text">Allow</span>' : '<span class="bad-text">Block</span>'} <span class="mono">${esc(m[2])}</span>${m[3] ? ` <span class="muted">for ${esc(devName([...state.devices.values()].find((d) => d.ip === m[3])?.mac || m[3]))}</span>` : ' <span class="muted">for all devices</span>'}` : `<span class="mono">${esc(r)}</span>`; };
    el.innerHTML = rules.length ? `<ul class="adg-rules">${rules.map((r) => `<li><span>${nice(r)}</span><button class="link small" data-rule="${esc(r)}" title="Remove this rule">remove</button></li>`).join('')}</ul>`
      : '<div class="muted small">No rules yet. Open a device, expand Contacts and tap "filter" next to a site.</div>';
  } catch (err) { el.innerHTML = `<div class="danger-text small">${esc(err.message)}</div>`; }
}
$('#adg-rules').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-rule]');
  if (!b || !confirm('Remove this rule?')) return;
  try { await api('/api/dnsfilter/rules/remove', 'POST', { rule: b.dataset.rule }); } catch (err) { alert(err.message); }
  renderAdgRules();
});

function renderSettings() {
  renderPushPanel();
  renderNotifPrefs();
  renderAdgRules();
  renderModules();
  renderConfig();
  renderAccount();
}

// ---------- modules ----------
function modSettingInput(m, s) {
  const id = `mod-${m.id}-${s.key}`, help = s.help ? `<div class="muted small">${esc(s.help)}</div>` : '';
  let input;
  if (s.type === 'bool') input = `<input type="checkbox" class="switch" id="${id}" data-key="${esc(s.key)}" ${s.value ? 'checked' : ''}>`;
  else if (s.type === 'password') input = `<input type="password" id="${id}" data-key="${esc(s.key)}" autocomplete="new-password" placeholder="${s.is_set ? '•••••• (saved, leave empty to keep)' : ''}">`;
  else input = `<input type="${s.type === 'number' ? 'number' : 'text'}" id="${id}" data-key="${esc(s.key)}" value="${esc(s.value ?? '')}">`;
  return `<div class="cfg-row"><label for="${id}">${esc(s.label || s.key)}</label>${input}${help}</div>`;
}
function modJob(m) {
  const j = state.mods?.jobs?.[m.id];
  if (j?.running) return `<div class="mod-job"><div class="bar"><span style="width:${j.pct}%"></span></div><div class="small muted">${j.pct}% · ${esc(j.step)}</div></div>`;
  if (j?.error) return `<div class="small danger-text">Installation failed: ${esc(j.error)}</div>`;
  return '';
}
// A module's state line. Updated in place on every status message, so it is always current.
function modStatus(m) {
  const live = (state.status?.modules || []).find((x) => x.id === m.id);
  const enabled = live ? live.enabled : m.enabled;
  return !m.installed_version ? '' : !enabled ? '<span class="muted">off</span>'
    : live?.last_error ? `<span class="danger-text">${esc(live.last_error)}</span>`
    : live?.last_ok ? `<span class="ok-text">working · ${fmtAgo(live.last_ok)} ago</span>` : '<span class="muted">starting…</span>';
}
function updateModStatus() {
  for (const m of state.mods?.modules || []) {
    const el = document.querySelector(`#mod-panel [data-mod-st="${m.id}"]`);
    if (!el) continue;
    const html = modStatus(m);
    if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
  }
}
function modHtml(m) {
  const busy = state.mods?.jobs?.[m.id]?.running;
  const st = modStatus(m);
  const tags = [...m.provides, ...(m.requires.length ? [`needs ${m.requires.join(', ')}`] : [])].map((t) => `<span class="tag">${esc(t)}</span>`).join('');
  const head = `<div class="mod-head"><b>${esc(m.name)}</b> <span class="muted small">${esc(m.installed_version || m.available_version || '')}${m.author ? ` · ${esc(m.author)}` : ''}</span>
    ${m.installed_version ? `<input type="checkbox" class="switch" title="On/off" data-mod-toggle="${esc(m.id)}" ${m.enabled ? 'checked' : ''}>` : ''}</div>`;
  const acts = m.installed_version && m.enabled && m.actions?.length ? `<div class="mod-acts">${m.actions.map((a) => `<div class="mod-act" data-mod-act="${esc(m.id)}" data-act-id="${esc(a.id)}">
      ${a.options?.length ? `<select aria-label="${esc(a.label)}">${a.options.map((o) => `<option value="${esc(o.value)}">${esc(o.label)}</option>`).join('')}</select>` : ''}
      <button type="button" class="ghost small">${esc(a.label)}</button>${a.help ? `<div class="muted small">${esc(a.help)}</div>` : ''}<div class="small" data-act-msg></div></div>`).join('')}</div>` : '';
  const body = m.installed_version
    ? `${acts}<details class="mod-cfg"${state.modOpen === m.id ? ' open' : ''}><summary class="small">Settings</summary><form data-mod-form="${esc(m.id)}">${m.settings.map((s) => modSettingInput(m, s)).join('')}
        <div class="cfg-actions"><button type="submit">Save</button>${m.update && !busy ? `<button type="button" class="ghost" data-mod-install="${esc(m.id)}">Update to ${esc(m.available_version)}</button>` : ''}
        <button type="button" class="ghost danger-text" data-mod-remove="${esc(m.id)}">Uninstall</button></div></form></details>`
    : busy ? '' : `<button class="ghost" data-mod-install="${esc(m.id)}">Install</button>`;
  return `<div class="mod" data-mod="${esc(m.id)}">${head}<div class="muted small">${esc(m.description)}</div><div class="tags">${tags}</div><div class="small" data-mod-st="${esc(m.id)}">${st}</div>${modJob(m)}${body}</div>`;
}
async function renderModules(refresh = false) {
  const el = $('#mod-panel');
  if (!el) return;
  try { state.mods = await api(`/api/modules${refresh ? '?refresh=1' : ''}`); } catch (err) { el.innerHTML = `<div class="danger-text small">${esc(err.message)}</div>`; return; }
  const q = (state.modQuery || '').toLowerCase(), mods = state.mods.modules;
  const match = (m) => !q || `${m.name} ${m.description} ${m.provides.join(' ')}`.toLowerCase().includes(q);
  const inst = mods.filter((m) => m.installed_version), avail = mods.filter((m) => !m.installed_version && match(m));
  el.innerHTML = `<h3 class="small muted">Installed</h3>${inst.length ? inst.map(modHtml).join('') : '<div class="muted small">No modules installed yet. Pick the ones for your routers and services below.</div>'}
    <h3 class="small muted mod-market">Marketplace <input type="search" id="mod-search" placeholder="Search modules" value="${esc(state.modQuery || '')}"> <button class="ghost small" id="mod-refresh">Refresh</button></h3>
    ${state.mods.source_error ? `<div class="small danger-text">${esc(state.mods.source_error)}</div>` : ''}
    ${avail.length ? avail.map(modHtml).join('') : `<div class="muted small">${q ? 'No module matches.' : 'Everything in the marketplace is installed.'}</div>`}
    <div class="muted small">Modules add support for specific routers and services, and anyone can write one (see the modules folder on GitHub). Only install modules you trust: they run with the same rights as NetMaster. Source: <span class="mono">${esc(state.mods.source)}</span></div>`;
  if (Object.values(state.mods.jobs || {}).some((j) => j.running)) setTimeout(pollJobs, 500);
}
async function pollJobs() {
  try { state.mods.jobs = await api('/api/modules/jobs'); } catch { return; }
  const running = Object.values(state.mods.jobs).some((j) => j.running);
  if (!running) { renderModules(); return; }
  for (const m of state.mods.modules) {
    const card = document.querySelector(`#mod-panel [data-mod="${m.id}"]`);
    const j = state.mods.jobs[m.id];
    if (card && j?.running) {
      let box = card.querySelector('.mod-job');
      if (!box) { card.querySelector('[data-mod-install]')?.remove(); box = document.createElement('div'); box.className = 'mod-job'; card.append(box); }
      box.innerHTML = `<div class="bar"><span style="width:${j.pct}%"></span></div><div class="small muted">${j.pct}% · ${esc(j.step)}</div>`;
    }
  }
  setTimeout(pollJobs, 500);
}
document.addEventListener('input', (e) => {
  if (e.target.id !== 'mod-search') return;
  state.modQuery = e.target.value;
  clearTimeout(state.modSearchT);
  state.modSearchT = setTimeout(async () => { await renderModules(); const i = $('#mod-search'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }, 250);
});
document.addEventListener('click', async (e) => {
  if (e.target.id === 'mod-refresh') { renderModules(true); return; }
  const b = e.target.closest('[data-mod-install],[data-mod-remove]');
  if (!b || !$('#mod-panel').contains(b)) return;
  const id = b.dataset.modInstall || b.dataset.modRemove;
  if (b.dataset.modRemove) {
    if (!confirm('Uninstall this module? Its settings are removed too.')) return;
    try { await api(`/api/modules/${id}/uninstall`, 'POST'); } catch (err) { alert(err.message); }
    renderModules();
    return;
  }
  b.disabled = true;
  state.modOpen = id;
  try { await api(`/api/modules/${id}/install`, 'POST'); } catch (err) { alert(err.message); }
  pollJobs();
});
// Module buttons ("actions" in module.json)
document.addEventListener('click', async (e) => {
  const b = e.target.closest('.mod-act button');
  if (!b || !$('#mod-panel').contains(b)) return;
  const box = b.closest('.mod-act'), msg = box.querySelector('[data-act-msg]');
  b.disabled = true;
  msg.className = 'small muted'; msg.textContent = 'Working…';
  try {
    const r = await api(`/api/modules/${box.dataset.modAct}/action/${box.dataset.actId}`, 'POST', { value: box.querySelector('select')?.value ?? null });
    msg.className = 'small ok-text'; msg.textContent = r.message;
  } catch (err) { msg.className = 'small danger-text'; msg.textContent = err.message; }
  b.disabled = false;
});
document.addEventListener('change', async (e) => {
  const t = e.target.closest('[data-mod-toggle]');
  if (!t) return;
  try { await api(`/api/modules/${t.dataset.modToggle}`, 'PUT', { enabled: t.checked }); } catch (err) { alert(err.message); }
  setTimeout(renderModules, 800);
});
document.addEventListener('submit', async (e) => {
  const f = e.target.closest('[data-mod-form]');
  if (!f) return;
  e.preventDefault();
  const settings = {};
  f.querySelectorAll('[data-key]').forEach((i) => { settings[i.dataset.key] = i.type === 'checkbox' ? i.checked : i.value; });
  try { await api(`/api/modules/${f.dataset.modForm}`, 'PUT', { settings, enabled: true }); } catch (err) { alert(err.message); return; }
  state.modOpen = null;
  setTimeout(renderModules, 1500);
});

// ---------- general settings ----------
function cfgInput(f) {
  const id = `cfg-${f.key}`;
  if (f.type === 'map') {
    const rows = Object.entries(f.value || {}).concat([['', '']]);
    return `<div class="cfg-map" data-cfg="${f.key}" data-type="map">${rows.map(([k, v]) => `<div class="cfg-pair">
      <input placeholder="${esc(f.key_label || 'Key')}" value="${esc(k)}"><input placeholder="${esc(f.value_label || 'Value')}" value="${esc(v)}"></div>`).join('')}
      <button type="button" class="ghost small" data-cfg-add>+ Add</button></div>`;
  }
  const v = f.type === 'list' || f.type === 'ports' ? (f.value || []).join(', ') : f.value ?? '';
  return `<input id="${id}" data-cfg="${f.key}" data-type="${f.type}" type="${f.type === 'int' || f.type === 'float' ? 'number' : 'text'}" step="any" value="${esc(v)}">`;
}
async function renderConfig() {
  const el = $('#cfg-panel');
  let view;
  try { view = await api('/api/settings'); } catch (err) { el.innerHTML = `<div class="danger-text small">${esc(err.message)}</div>`; return; }
  const sections = [...new Set(view.fields.map((f) => f.section))];
  el.innerHTML = `<form id="cfg-form">${sections.map((sec) => `<details class="cfg-sec"><summary>${esc(sec)}</summary>
    ${view.fields.filter((f) => f.section === sec).map((f) => `<div class="cfg-row"><label for="cfg-${f.key}">${esc(f.label)}${f.restart ? ' <span class="muted small">(restart)</span>' : ''}</label>
      ${cfgInput(f)}${f.help ? `<div class="muted small">${esc(f.help)}</div>` : ''}</div>`).join('')}</details>`).join('')}
    <div class="cfg-actions"><button type="submit">Save</button><span id="cfg-msg" class="small"></span></div></form>`;
}
document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-cfg-add]');
  if (!b) return;
  const pair = b.previousElementSibling.cloneNode(true);
  pair.querySelectorAll('input').forEach((i) => { i.value = ''; });
  b.before(pair);
});
document.addEventListener('submit', async (e) => {
  if (e.target.id !== 'cfg-form') return;
  e.preventDefault();
  const body = {};
  e.target.querySelectorAll('[data-cfg]').forEach((i) => {
    const t = i.dataset.type;
    if (t === 'map') {
      body[i.dataset.cfg] = Object.fromEntries([...i.querySelectorAll('.cfg-pair')].map((p) => [...p.querySelectorAll('input')].map((x) => x.value.trim())).filter(([k]) => k));
    } else if (t === 'list' || t === 'ports') body[i.dataset.cfg] = i.value.split(',').map((x) => x.trim()).filter(Boolean);
    else body[i.dataset.cfg] = i.value;
  });
  const msg = $('#cfg-msg');
  try {
    const r = await api('/api/settings', 'PUT', body);
    if (r.restart_needed && confirm('Some changes need a restart of NetMaster. Restart now?')) {
      await api('/api/restart', 'POST');
      msg.textContent = 'Restarting…';
      setTimeout(() => location.reload(), 8000);
      return;
    }
    msg.textContent = 'Saved.';
    msg.className = 'small ok-text';
  } catch (err) { msg.textContent = err.message; msg.className = 'small danger-text'; }
});

// ---------- which notifications you get ----------
const typeKey = (t) => t.replace(/\d+(?:[.,]\d+)?(?:\s*(?:ms|s|min|h|d|%|Mbit\/s|kbit\/s))?/g, '#').replace(/#(?:\s+#)+/g, '#').trim();
const IPV4 = /^\d+\.\d+\.\d+\.\d+$/, MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
// The device an event is about (its MAC when known), or '' when the event is not about one device.
function evDevice(e) {
  const src = (e.source || '').toLowerCase();
  if (MAC.test(src)) return src;
  if (!IPV4.test(src)) return '';
  for (const d of state.devices?.values() || []) if (d.ip === src) return d.mac;
  return src;
}
const evIds = (e) => { const d = evDevice(e), x = state.devices?.get(d); return new Set([d, (e.source || '').toLowerCase(), x?.ip].filter(Boolean)); };
const typeInfo = (id) => state.notif?.types?.find((t) => t.id === id);
const devLabel = (id) => (MAC.test(id) ? devName(id) : id);
const shortTitle = (k) => k.replace(/#/g, '…');
function ruleText(r) {
  const t = r.type && (typeInfo(r.type)?.label || r.type), d = r.device && devLabel(r.device);
  if (r.title) return `Only "${shortTitle(r.title)}"${d ? ` from ${d}` : ''}`;
  if (t && d) return `"${t}" from ${d}`;
  if (d) return `Everything from ${d}`;
  return t ? `"${t}" from every device` : '?';
}
// Why an event gives no notification: a matching mute rule, or its whole type turned off. null = it does notify.
function muteRules(e) {
  const key = typeKey(e.title);
  let ids = null;
  return (state.notif?.muted || []).filter((r) => (!r.title || r.title === key) && (!r.type || r.type === e.ntype)
    && (!r.device || (ids ||= evIds(e)).has(r.device)));
}
function muteReason(e) {
  if (!state.notif) return null;
  if (e.ntype && typeInfo(e.ntype)?.on === false) return { off: e.ntype, text: `"${typeInfo(e.ntype).label}" is turned off` };
  const rules = muteRules(e);
  return rules.length ? { rules, text: ruleText(rules[0]) } : null;  // turning on again removes all matching rules
}
function muteMark(e) {
  const why = muteReason(e);
  return why
    ? ` <button class="link ev-mute is-muted" data-unmute-ev="${e.id}" title="No notifications: ${esc(why.text)}. Tap to turn on again." aria-label="Notifications off. Turn on again">🔕 <span>Muted</span></button>`
    : ` <button class="link ev-mute" data-mute-ev="${e.id}" title="Notifications on. Tap to stop notifications like this…" aria-label="Stop notifications like this">🔔</button>`;
}
async function renderNotifPrefs() {
  const el = $('#notif-prefs');
  try { state.notif = await api('/api/push/prefs'); } catch (err) { el.innerHTML = `<div class="danger-text small">${esc(err.message)}</div>`; return; }
  const p = state.notif, groups = [...new Set(p.types.map((t) => t.group))];
  const seen = (t) => (t.n ? `${t.n}× last 30 days · latest ${fmtAgo(t.last)} ago` : 'not in the last 30 days');
  el.innerHTML = `<div class="muted small">Turn each kind of notification on or off. Everything is still logged under Events.</div>
    ${groups.map((g) => `<h3 class="notif-h">${esc(g)}</h3><ul class="notif-types">${p.types.filter((t) => t.group === g).map((t) => `
      <li><label class="switch-row"><span><b>${esc(t.label)}</b><span class="muted small">${esc(t.desc)}</span>
        <span class="muted small">${seen(t)}${t.example ? ` · e.g. "${esc(t.example)}"` : ''}</span></span>
        <input type="checkbox" class="switch" data-type="${t.id}" ${t.on ? 'checked' : ''} aria-label="${esc(t.label)}"></label></li>`).join('')}</ul>`).join('')}
    <h3 class="notif-h">Muted with 🔕</h3>
    <div class="muted small">Tap 🔕 on an event to choose what to mute: just that one, that kind on one device, or everything from a device.</div>
    <ul class="notif-types">${p.muted.map((r, i) => `<li><span>${esc(ruleText(r))}</span><button class="ghost small" data-unmute="${i}">Turn on again</button></li>`).join('')
      || '<li class="muted small">None.</li>'}</ul>`;
}
$('#notif-prefs').addEventListener('change', async (e) => {
  const c = e.target.closest('input[data-type]');
  if (!c) return;
  try { await api('/api/push/prefs', 'PUT', { types: { [c.dataset.type]: c.checked } }); } catch (err) { alert(err.message); c.checked = !c.checked; }
  if (state.notif) typeInfo(c.dataset.type).on = c.checked;
  renderEvents();
});
async function setMute(rule, mute) {
  try { state.notif = { ...(state.notif || {}), muted: (await api('/api/push/mute', 'POST', { rule, mute })).muted }; } catch (err) { alert(err.message); return false; }
  renderEvents();
  if ($('#notif-prefs').childElementCount) renderNotifPrefs();
  return true;
}
$('#notif-prefs').addEventListener('click', (e) => {
  const b = e.target.closest('[data-unmute]');
  if (b) setMute(state.notif.muted[+b.dataset.unmute], false);
});
// The choices when muting from an event, from narrow to wide. Only the levels that make sense for this event are shown.
function muteChoices(e) {
  const dev = evDevice(e), t = e.ntype && e.ntype !== 'other' && e.ntype !== 'system' ? typeInfo(e.ntype) : null;
  const dn = dev && devLabel(dev), key = typeKey(e.title), out = [];
  out.push({ rule: { title: key }, label: 'Only this one', sub: `"${shortTitle(key)}"${key.includes('#') ? ' (whatever the number)' : ''}` });
  if (t && dev) out.push({ rule: { type: t.id, device: dev }, label: `All "${t.label}" from ${dn}`, sub: `Other kinds from ${dn}, and this kind from other devices, still notify.` });
  if (dev) out.push({ rule: { device: dev }, label: `Everything from ${dn}`, sub: 'All kinds of notifications about this device.' });
  if (t) out.push({ off: t.id, label: `All "${t.label}" from every device`, sub: 'Turns off this whole kind (same switch as under Settings → Notifications).' });
  return out;
}
function muteDialog(e) {
  const ch = muteChoices(e);
  const dlg = document.createElement('dialog');
  dlg.className = 'mute-dlg';
  dlg.innerHTML = `<form method="dialog"><h3>Stop notifications</h3><div class="muted small">${esc(e.title)}</div>
    ${ch.map((c, i) => `<label class="wiz-opt"><input type="radio" name="lvl" value="${i}" ${i ? '' : 'checked'}><span><b>${esc(c.label)}</b><br><span class="muted small">${esc(c.sub)}</span></span></label>`).join('')}
    <div class="muted small">It is still logged under Events. Turn it on again with 🔕 on the event or under Settings → Notifications.</div>
    <div class="row"><button value="ok">Mute</button> <button value="cancel" class="ghost" formnovalidate>Cancel</button></div></form>`;
  document.body.append(dlg);
  dlg.addEventListener('close', async () => {
    const c = dlg.returnValue === 'ok' && ch[+dlg.querySelector('input[name=lvl]:checked').value];
    dlg.remove();
    if (!c) return;
    if (c.off) {
      try { await api('/api/push/prefs', 'PUT', { types: { [c.off]: false } }); typeInfo(c.off).on = false; } catch (err) { alert(err.message); return; }
      renderEvents();
      if ($('#notif-prefs').childElementCount) renderNotifPrefs();
    } else setMute(c.rule, true);
  });
  dlg.showModal();
}
async function unmuteFromEvent(e) {
  const why = muteReason(e);
  if (!why || !confirm(`Turn notifications on again?\n\nMuted: ${why.text}`)) return;
  if (why.rules) {
    try { state.notif.muted = (await api('/api/push/prefs', 'PUT', { muted: state.notif.muted.filter((r) => !why.rules.includes(r)) })).muted; } catch (err) { alert(err.message); return; }
    renderEvents();
    if ($('#notif-prefs').childElementCount) renderNotifPrefs();
    return;
  }
  try { await api('/api/push/prefs', 'PUT', { types: { [why.off]: true } }); typeInfo(why.off).on = true; } catch (err) { alert(err.message); return; }
  renderEvents();
  if ($('#notif-prefs').childElementCount) renderNotifPrefs();
}
['#events', '#recent-events'].forEach((id) => $(id).addEventListener('click', (ev) => {
  const b = ev.target.closest('[data-mute-ev],[data-unmute-ev]');
  if (!b) return;
  ev.stopPropagation();
  const e = state.events.find((x) => String(x.id) === (b.dataset.muteEv || b.dataset.unmuteEv));
  if (!e) return;
  if (b.dataset.muteEv) muteDialog(e); else unmuteFromEvent(e);
}, true));
api('/api/push/prefs').then((p) => { state.notif = p; renderEvents(); }).catch(() => {});

function renderSecurity() {
  const sec = state.status?.security;
  if (!sec) return;
  const inv = sec.inventory, dhcp = sec.dhcp, dns = sec.dns, l2 = sec.l2;
  const ago = (ts) => (ts ? `${fmtAgo(ts)} ago` : 'not yet');
  const gwMismatch = !inv.arp_ok;
  $('#sec-panel').innerHTML = [
    row('Npcap', l2.available
      ? `<b>Active</b> on ${esc(l2.iface || '')}. Real-time ARP and DHCP monitoring.`
      : `<b class="danger-text">Missing</b> – ${esc(l2.reason || '')}. Basic protection via the ARP table works, but rogue DHCP detection requires Npcap (npcap.com).`),
    row('ARP protection', gwMismatch
      ? `<b class="danger-text">Router MAC has changed!</b> Expected ${esc(inv.gateway_mac)}, now ${esc(inv.current_gateway_mac)}.`
      : `<b>OK</b>. Main router MAC: <span class="mono">${esc(inv.gateway_mac || 'learning…')}</span>`,
      gwMismatch ? '<button class="ghost" id="accept-gw">I replaced my router</button>' : ''),
    row('DHCP check', !dhcp.enabled ? 'Requires Npcap.'
      : dhcp.rogue.length ? `<b class="danger-text">Unknown DHCP server: ${esc(dhcp.rogue.join(', '))}</b>`
        : `<b>${dhcp.last_check ? 'OK' : 'Waiting'}</b>. Allowed: ${esc(dhcp.allowed.join(', '))}. Last checked ${ago(dhcp.last_check)}.`),
    row('DNS check', dns.problems.length ? `<b class="danger-text">Tampered answers:</b> ${esc(dns.problems.join('; '))}`
      : `<b>${dns.last_check ? 'OK' : 'Waiting'}</b>. Last checked ${ago(dns.last_check)}.${dns.system_dns ? ` Server DNS: ${esc(dns.system_dns.join(', '))}.` : ''}${dns.nx_redirect ? ' The router DNS redirects non-existent names.' : ''}`),
    row('Inventory', inv.in_baseline
      ? `Learning until ${fmtTime(inv.baseline_until)}. ${inv.count} devices so far.`
      : `${inv.count} devices, ${inv.untrusted} not approved. Network ${esc(inv.network || '')}. Last scan ${ago(inv.last_sweep)}.`),
  ].join('');
  const ra = state.status.router;
  const mark = (c) => (c.ok === false ? '<b class="danger-text">✗</b> ' : c.ok ? '<b class="ok-text">✓</b> ' : '');
  $('#audit-panel').innerHTML = ra?.audit
    ? ra.audit.map((c) => row(esc(c.title), mark(c) + esc(c.detail))).join('') + `<div class="muted small">Checked ${ago(ra.audit_ts)}.</div>`
    : row('Status', ra?.enabled ? 'Waiting for the first check…' : 'Router API not active.');
  const ex = state.status.exposure, pr = state.status.ports, res = ex?.result;
  const riskyAll = Object.entries(pr?.open || {}).flatMap(([mac, ps]) =>
    ps.filter((p) => pr.risky.includes(p)).map((p) => `${esc(devName(mac))}: ${p} (${esc(pr.names[p])})`));
  $('#expo-panel').innerHTML = [
    row('From the internet', ex?.error ? `<b class="danger-text">Check failed</b> ${esc(ex.error)}` : !res ? 'Not checked yet.'
      : `${res.ports.length ? `Ports seen open on <span class="mono">${esc(res.ip)}</span>: ${res.ports.map((p) => (ex.expected || []).includes(p)
          ? `<span class="badge" title="Expected">${p} ✓</span>` : `<b class="danger-text">${p}</b>`).join(' ')}.`
        : `Nothing seen open on <span class="mono">${esc(res.ip)}</span>.`}${res.vulns.length
        ? ` <b class="danger-text">Known vulnerabilities: ${esc(res.vulns.slice(0, 10).join(', '))}</b>` : ''} Source: Shodan, ${ago(res.ts)}.`),
    row('Inside the network', !pr?.last_scan ? (pr?.running ? 'Scanning…' : 'First scan runs a few minutes after start.')
      : `${Object.keys(pr.open).length} devices scanned ${ago(pr.last_scan)}. ` + (riskyAll.length
        ? `<b class="danger-text">Risky services:</b> ${riskyAll.join('; ')}` : 'No risky services found.')),
  ].join('');
  $('#accept-gw')?.addEventListener('click', async () => {
    if (!confirm('Accept the new MAC address as the main router? Only do this if you actually replaced the router.')) return;
    await api('/api/security/accept-gateway', 'POST');
  });
}
$('#scan-ports').addEventListener('click', async (e) => {
  const b = e.currentTarget; b.disabled = true; b.textContent = 'Scanning…';
  try { await api('/api/portscan', 'POST'); } catch (err) { alert(err.message); }
  b.disabled = false; b.textContent = 'Scan ports now';
});
$('#sec-check').addEventListener('click', async (e) => {
  const b = e.currentTarget; b.disabled = true; b.textContent = 'Checking…';
  try { await api('/api/security/check', 'POST'); } catch (err) { alert(err.message); }
  b.disabled = false; b.textContent = 'Check now';
});

// ---------- notiser (Web Push) ----------
const notifyBtn = $('#notify-btn');
const b64ToBytes = (s) => {
  const b = atob((s + '='.repeat((4 - (s.length % 4)) % 4)).replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
};
async function initPush() {
  if (!state.push.supported) return updateNotifyBtn();
  try {
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (sub) {
      // Renew the subscription if the server's key has changed (e.g. a new installation)
      const { key } = await api('/api/push/key');
      const stored = localStorage.getItem('nm-push-key');
      if (stored && stored !== key) { await sub.unsubscribe(); sub = null; }
      else await api('/api/push/subscribe', 'POST', sub.toJSON()); // make sure the server knows about it
    }
    state.push.sub = sub;
  } catch (e) { console.warn('push', e); }
  updateNotifyBtn();
}
async function enablePush() {
  const perm = await Notification.requestPermission();
  if (perm !== 'granted') { alert('Notifications are blocked. Allow them in your browser settings for this site.'); return; }
  const reg = await navigator.serviceWorker.ready;
  const { key } = await api('/api/push/key');
  const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToBytes(key) });
  await api('/api/push/subscribe', 'POST', sub.toJSON());
  try { localStorage.setItem('nm-push-key', key); } catch {}
  state.push.sub = sub;
  updateNotifyBtn();
  renderPushPanel();
}
async function disablePush() {
  const sub = state.push.sub;
  if (sub) {
    await api('/api/push/unsubscribe', 'POST', { endpoint: sub.endpoint }).catch(() => {});
    await sub.unsubscribe();
  }
  state.push.sub = null;
  updateNotifyBtn();
  renderPushPanel();
}
function updateNotifyBtn() {
  notifyBtn.hidden = !state.push.supported || !!state.push.sub;
}
notifyBtn.addEventListener('click', () => enablePush().catch((e) => alert(`Could not enable notifications: ${e.message}`)));
function renderPushPanel() {
  const p = state.status?.push;
  const isIOS = /iPhone|iPad/.test(navigator.userAgent);
  const standalone = matchMedia('(display-mode: standalone)').matches || navigator.standalone;
  let v, act = '';
  if (!state.push.supported) {
    v = isIOS && !standalone
      ? 'On iPhone/iPad: open the Share menu and choose <b>Add to Home Screen</b>. Then open the app from there and enable notifications.'
      : 'This browser does not support push notifications (requires HTTPS, e.g. via Tailscale).';
  } else if (state.push.sub) {
    v = '<b>On</b> for this device. You get notifications even when the app is closed.';
    act = '<button class="ghost" id="push-test">Send test</button><button class="ghost" id="push-off">Turn off</button>';
  } else {
    v = 'Off for this device.';
    act = '<button class="primary" id="push-on">Enable notifications</button>';
  }
  $('#push-panel').innerHTML = row('This device', v, act) +
    (p ? row('All devices', `${p.subscribers} device${p.subscribers === 1 ? '' : 's'} get notifications.${p.last_error ? ` <span class="danger-text">Last error: ${esc(p.last_error)}</span>` : ''}`) : '');
  $('#push-on')?.addEventListener('click', () => enablePush().catch((e) => alert(`Could not enable notifications: ${e.message}`)));
  $('#push-off')?.addEventListener('click', () => disablePush());
  $('#push-test')?.addEventListener('click', async (e) => {
    const b = e.currentTarget; b.disabled = true;
    const r = await api('/api/push/test', 'POST', { endpoint: state.push.sub.endpoint }).catch((err) => ({ sent: 0, error: err.message }));
    b.disabled = false;
    if (!r.sent) alert(`Test notification failed${r.error ? `: ${r.error}` : ''}`);
  });
}
// Local notification only when push is off (otherwise it comes from the server).
async function notify(ev) {
  if (state.push.sub || !('Notification' in window) || Notification.permission !== 'granted') return;
  if (!NOTIFY_SEVERITIES.has(ev.severity) || (document.visibilityState === 'visible' && document.hasFocus())) return;
  const reg = await navigator.serviceWorker?.getRegistration();
  const opts = { body: ev.detail || '', tag: `nm-${ev.id}`, icon: 'icons/icon-192.png', badge: 'icons/icon-192.png' };
  reg ? reg.showNotification(ev.title, opts) : new Notification(ev.title, opts);
}

// ---------- realtid ----------
let ws, retry = 0, chartTimer;
function connect() {
  const conn = $('#conn');
  ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.onopen = () => {
    retry = 0;
    conn.className = 'conn ok'; conn.lastElementChild.textContent = 'Live';
    loadEvents();
    if (state.logsLoaded) loadLogs();
  };
  ws.onclose = (e) => {
    if (e.code === 4401) { showLogin(); return; }
    conn.className = 'conn bad'; conn.lastElementChild.textContent = 'Disconnected';
    setTimeout(connect, Math.min(15000, 1000 * 2 ** retry++));
  };
  ws.onmessage = (m) => {
    const { type, data } = JSON.parse(m.data);
    if (type === 'status') {
      // New frontend on the server? Reload automatically (not in the middle of a rename).
      if (data.build) {
        if (!state.build) state.build = data.build;
        else if (state.build !== data.build && !state.editing) {
          navigator.serviceWorker?.getRegistration().then((r) => r?.update()).finally(() => location.reload());
          return;
        }
      }
      const trafficChanged = data.router?.last_ok !== state.status?.router?.last_ok;
      const first = !state.status;
      renderStatus(data);
      updateModStatus();
      renderUpdate(data.update);
      if (first && state.pendingProc) { openProcOnMap(state.pendingProc.name, state.pendingProc.ip); state.pendingProc = null; }
      if (first) { loadChart(); loadSpeed(); loadCalls(); loadDevices().then(() => { renderTop(); loadUsage(); }); }
      if (trafficChanged && state.devices?.size) renderDevices();
    } else if (type === 'speedtest') {
      loadSpeed();
    } else if (type === 'event') {
      state.events.unshift(data);
      state.events.length = Math.min(state.events.length, Math.max(500, state.evShown + 200));
      renderEvents();
      notify(data);
    } else if (type === 'device') {
      state.devices.set(data.mac, data);
      if (!$('#tab-devices').hidden) renderDevices();
    } else if (type === 'device_removed') {
      state.devices.delete(data.mac);
      if (!$('#tab-devices').hidden) renderDevices();
    } else if (type === 'syslog' && state.logsLoaded) {
      state.logs.unshift(data);
      state.logs.length = Math.min(state.logs.length, 2000);
      renderLogs();
    }
  };
}
async function loadEvents() {
  try {
    state.events = await api('/api/events?limit=300');
    state.evEnd = state.events.length < 300;
    renderEvents();
  } catch (e) { console.warn(e); }
}

// ---------- login ----------
async function showLogin() {
  if (state.loginShown) return;
  state.loginShown = true;
  let a = { setup_needed: false, setup_local: false };
  try { a = await api('/api/auth/state'); } catch { /* server unreachable: show the login form anyway */ }
  const el = $('#login'), setup = a.setup_needed;
  el.innerHTML = `<form class="login-box" id="login-form">
    <img src="icons/icon-192.png" alt="" width="56" height="56"><h1>NetMaster</h1>
    <p class="muted small">${setup ? 'Welcome! Choose a password for NetMaster (at least 8 characters).' : 'Log in to continue.'}</p>
    <input type="password" id="login-pw" placeholder="Password" autocomplete="${setup ? 'new-password' : 'current-password'}" required autofocus>
    ${setup ? '<input type="password" id="login-pw2" placeholder="Repeat the password" autocomplete="new-password" required>' : ''}
    ${setup && !a.setup_local ? '<input id="login-code" placeholder="Setup code" autocomplete="off" required><div class="muted small">The setup code is in data/setup-code.txt on the computer NetMaster runs on (or open NetMaster on that computer).</div>' : ''}
    <button type="submit">${setup ? 'Set password' : 'Log in'}</button>
    <div id="login-msg" class="small danger-text"></div>${window.i18n?.picker() || ''}</form>`;
  el.hidden = false;
  document.body.classList.add('locked');
  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pw = $('#login-pw').value, msg = $('#login-msg');
    if (setup && pw !== $('#login-pw2').value) { msg.textContent = 'The passwords do not match.'; return; }
    try {
      await api(setup ? '/api/auth/setup' : '/api/auth/login', 'POST', setup ? { password: pw, code: $('#login-code')?.value || '' } : { password: pw });
      location.reload();
    } catch (err) { msg.textContent = err.message; }
  });
}
async function renderAccount() {
  $('#account-panel').innerHTML = `<form id="pw-form" class="cfg-row">
      <input type="password" id="pw-cur" placeholder="Current password" autocomplete="current-password" required>
      <input type="password" id="pw-new" placeholder="New password (at least 8 characters)" autocomplete="new-password" required>
      <div class="cfg-actions"><button type="submit">Change password</button><span id="pw-msg" class="small"></span></div></form>
    <div class="cfg-actions"><button class="ghost" id="logout">Log out</button><button class="ghost" id="logout-all">Log out all other devices</button></div>
    <label class="cfg-row"><span>Language</span>${window.i18n?.picker() || ''}</label>`;
}
document.addEventListener('submit', async (e) => {
  if (e.target.id !== 'pw-form') return;
  e.preventDefault();
  const msg = $('#pw-msg');
  try {
    await api('/api/auth/password', 'POST', { current: $('#pw-cur').value, new: $('#pw-new').value });
    msg.textContent = 'Password changed. Other devices have been logged out.'; msg.className = 'small ok-text';
    e.target.reset();
  } catch (err) { msg.textContent = err.message; msg.className = 'small danger-text'; }
});
document.addEventListener('click', async (e) => {
  if (e.target.id === 'logout') { await api('/api/auth/logout', 'POST').catch(() => {}); location.reload(); }
  if (e.target.id === 'logout-all' && confirm('Log out every other phone and computer?')) {
    try { await api('/api/auth/logout-all', 'POST'); alert('Done.'); } catch (err) { alert(err.message); }
  }
});

// ---------- first-run guide ----------
const WIZ_NET = ['gateway', 'lan_cidr', 'routers', 'uplink'];
async function showWizard(step = 0) {
  const el = $('#wizard'), steps = ['Your network', 'Modules', 'Access', 'Done'];
  el.hidden = false;
  document.body.classList.add('wizard-open');
  const nav = (next, label = 'Next') => `<div class="cfg-actions wiz-nav">${step ? '<button type="button" class="ghost" data-wiz="back">Back</button>' : ''}
    <button type="button" data-wiz="${next}">${label}</button><button type="button" class="ghost small" data-wiz="skip">Skip the guide</button></div>`;
  const head = `<div class="wiz-steps">${steps.map((t, i) => `<span class="${i === step ? 'on' : i < step ? 'done' : ''}">${i + 1}. ${t}</span>`).join('')}</div>`;
  if ($('#wiz-body #mod-panel')) $('#mod-home').append($('#mod-panel'));  // put the module list back
  const info = state.wizInfo ||= await api('/api/setup/info').catch(() => ({}));
  let body = '';
  if (step === 0) {
    const view = await api('/api/settings');
    const fields = view.fields.filter((f) => WIZ_NET.includes(f.key));
    body = `<h2>Your network</h2><p class="muted small">NetMaster found your main router at <b>${esc(info.gateway || 'unknown')}</b>, and this computer is <b>${esc(info.local_ip || 'unknown')}</b>. Usually you can keep these as they are.</p>
      <form id="wiz-net">${fields.map((f) => `<div class="cfg-row"><label>${esc(f.label)}</label>${cfgInput(f)}${f.help ? `<div class="muted small">${esc(f.help)}</div>` : ''}</div>`).join('')}</form>${nav('net')}`;
  } else if (step === 1) {
    body = `<h2>Modules</h2><p class="muted small">Modules add support for your router brand, DNS filter and home servers. Install the ones that match your home, then open Settings on each to connect it. You can always add more later under Settings.</p><div id="wiz-mods"></div>${nav('next')}`;
  } else if (step === 2) {
    const ts = info.tailscale || {};
    body = `<h2>Access</h2><p class="muted small">How do you want to open NetMaster on your phone and other computers?</p>
      <label class="wiz-opt"><input type="radio" name="wiz-host" value="127.0.0.1" ${info.http_host !== '0.0.0.0' ? 'checked' : ''}> <span><b>Only this computer</b><br><span class="muted small">Safest. Use Tailscale (below) or your own reverse proxy to reach it from other devices.</span></span></label>
      <label class="wiz-opt"><input type="radio" name="wiz-host" value="0.0.0.0" ${info.http_host === '0.0.0.0' ? 'checked' : ''}> <span><b>Every device on my home network</b><br><span class="muted small">Open <span class="mono">http://${esc(info.local_ip || 'this-computer')}:${info.http_port}</span> on your phone while at home. Notifications on phones need HTTPS, so they won't work this way.</span></span></label>
      <div class="wiz-ts"><b>Tailscale</b> <span class="muted small">(free, optional): reach NetMaster securely from anywhere, with HTTPS and notifications.</span><br>
      ${ts.running ? (info.urls?.tailscale ? `<button type="button" class="ghost" id="wiz-ts">Publish with Tailscale</button> <span class="small" id="wiz-ts-msg"></span>` : '')
        : ts.installed ? '<span class="small">Tailscale is installed but not logged in. Log in, then come back here.</span>'
        : '<span class="small">Not installed. Get it at <span class="mono">tailscale.com/download</span>, on this computer and your phone.</span>'}</div>
      ${nav('access')}`;
  } else {
    const u = info.urls || {};
    body = `<h2>All set</h2><p>NetMaster is now watching your network. It learns your devices during the first 30 minutes.</p>
      <ul class="small">${u.this_computer ? `<li>On this computer: <span class="mono">${esc(u.this_computer)}</span></li>` : ''}${u.home_network ? `<li>At home: <span class="mono">${esc(u.home_network)}</span></li>` : ''}${u.tailscale ? `<li>With Tailscale: <span class="mono">${esc(u.tailscale)}</span></li>` : ''}</ul>
      <p class="muted small">Tip: open NetMaster on your phone and choose "Add to home screen", then press "Enable notifications".</p>${nav('done', 'Finish')}`;
  }
  el.innerHTML = `<div class="wiz-box">${head}<div id="wiz-body">${body}</div></div>`;
  if (step === 1) { $('#wiz-mods').append($('#mod-panel')); renderModules(); }
  state.wizStep = step;
}
document.addEventListener('click', async (e) => {
  const b = e.target.closest('[data-wiz]');
  if (e.target.id === 'wiz-ts') {
    const msg = $('#wiz-ts-msg');
    try { const r = await api('/api/setup/tailscale', 'POST'); msg.textContent = `Published: ${r.url}`; msg.className = 'small ok-text'; } catch (err) { msg.textContent = err.message; msg.className = 'small danger-text'; }
    return;
  }
  if (!b) return;
  const act = b.dataset.wiz, step = state.wizStep || 0;
  try {
    if (act === 'back') return showWizard(step - 1);
    if (act === 'net') {
      const body = {};
      $('#wiz-net').querySelectorAll('[data-cfg]').forEach((i) => {
        body[i.dataset.cfg] = i.dataset.type === 'map'
          ? Object.fromEntries([...i.querySelectorAll('.cfg-pair')].map((p) => [...p.querySelectorAll('input')].map((x) => x.value.trim())).filter(([k]) => k))
          : i.value;
      });
      await api('/api/settings', 'PUT', body);
    }
    if (act === 'access') {
      const host = document.querySelector('[name=wiz-host]:checked')?.value;
      if (host && host !== state.wizInfo.http_host) { await api('/api/settings', 'PUT', { http_host: host }); state.wizRestart = true; }
      state.wizInfo = null;
    }
    if (act === 'skip' || act === 'done') {
      await api('/api/setup/done', 'POST');
      if ($('#wiz-body #mod-panel')) $('#mod-home').append($('#mod-panel'));
      $('#wizard').hidden = true;
      document.body.classList.remove('wizard-open');
      if (state.wizRestart) { await api('/api/restart', 'POST').catch(() => {}); setTimeout(() => location.reload(), 8000); }
      return;
    }
    showWizard(step + 1);
  } catch (err) { alert(err.message); }
});

// ---------- start ----------
async function start() {
  try {
    const a = await api('/api/auth/state');
    if (!a.logged_in) { showLogin(); return; }
    if (a.wizard_needed) showWizard();
  } catch { /* offline: try the WebSocket anyway, it retries */ }
  updateNotifyBtn();
  try { const t = localStorage.getItem('nm-tab'); if (t) showTab(t); } catch {}
  connect();
  chartTimer = setInterval(() => { if (!$('#tab-overview').hidden) loadChart(); }, 30000);
  setInterval(() => state.status && renderStatus(state.status), 15000);
  initPush();
  if (location.hash === '#events') showTab('events');
}
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' }).catch((e) => console.warn('SW', e));
start();

// A click on a "new program" event (or its push notification, via #proc=name) shows the program on the map.
// The map always shows, even long afterwards: if the program is missing from the last hour's traffic
// the address from the event (or the notification's link) is used.
async function openProcOnMap(name, ip) {
  showTab('overview');
  state.openProc = name;
  const live = state.status?.host_flows?.procs.some((p) => p.name === name);
  if (!live) {
    if (!ip) {
      try { ip = progIp((await api('/api/events?limit=1000')).find((e) => e.title === NEW_PROG + name)?.detail); } catch { /* no address */ }
    }
    if (ip) {
      try { state.mapExtra = { name, ...(await api(`/api/geo/${ip}`)), down: 0, up: 0 }; } catch { state.mapExtra = { name, ip }; }
    }
  }
  renderHostFlows();
  renderMap();
  if (!live) $('#hf-sub').textContent = `${name} has not used the internet in the last hour${ip ? `; showing ${ip} from the alert` : ''}.`;
  if (!live && ip) $('#trace-info').innerHTML = `<button class="link small" data-trace="${esc(ip)}">Trace ${esc(ip)}</button>`;
  setTimeout(() => $(live || ip ? '#map-panel' : '#hostflows').scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
}
$('#trace-info').addEventListener('click', (e) => {
  const b = e.target.closest('[data-trace]');
  if (b) traceRoute(b.dataset.trace);
});
['#events', '#recent-events'].forEach((sel) => $(sel).addEventListener('click', (e) => {
  const li = e.target.closest('[data-proc]');
  if (li) openProcOnMap(li.dataset.proc, li.dataset.ip);
}));
function procFromHash() {
  if (!location.hash.startsWith('#proc=')) return;
  const q = new URLSearchParams(location.hash.slice(1));
  state.pendingProc = { name: q.get('proc'), ip: q.get('ip') || '' };
  history.replaceState(null, '', location.pathname);
  if (state.status) { openProcOnMap(state.pendingProc.name, state.pendingProc.ip); state.pendingProc = null; }
}
window.addEventListener('hashchange', procFromHash);
procFromHash();
// Remember whether the domain list is expanded, so it does not collapse when the list is redrawn.
document.addEventListener('toggle', (e) => { if (e.target.classList?.contains('dns-box')) state.dnsOpen = e.target.open; }, true);

// ---------- folding settings panels (remembered on this device) ----------
const FOLD_KEY = 'nm-open-panels';
function openPanels() { try { return new Set(JSON.parse(localStorage.getItem(FOLD_KEY) || '[]')); } catch { return new Set(); } }
function setFold(panel, open, save = true) {
  panel.classList.toggle('folded', !open);
  panel.querySelector('.fold')?.setAttribute('aria-expanded', String(open));
  if (!save) return;
  const o = openPanels();
  if (open) o.add(panel.dataset.fold); else o.delete(panel.dataset.fold);
  try { localStorage.setItem(FOLD_KEY, JSON.stringify([...o])); } catch { /* storage blocked */ }
}
{
  const o = openPanels();
  document.querySelectorAll('.panel[data-fold]').forEach((p) => setFold(p, o.has(p.dataset.fold), false));
}
document.addEventListener('click', (e) => {
  const b = e.target.closest('.panel[data-fold] > .panel-head');
  if (!b || e.target.closest('a, input, select') || (e.target.closest('button') && !e.target.closest('.fold'))) return;
  const p = b.parentElement;
  setFold(p, p.classList.contains('folded'));
});

// ---------- NetMaster updates (Settings → General) ----------
function renderUpdate(u) {
  if (!u) return;
  state.update = u;
  const box = $('#update-box'), chip = $('#update-chip'), tab = $('.tabs button[data-tab="settings"]');
  chip.hidden = !u.available;
  tab?.classList.toggle('has-update', !!u.available);
  let html;
  if (u.updating) {
    html = `<div><b>Updating to ${esc(u.updating)}…</b></div><div class="muted small">NetMaster restarts in a minute or two. This page reloads by itself.</div>`;
  } else if (u.available) {
    html = `<div><b>NetMaster ${esc(u.latest)} is available</b> <span class="muted small">(you have ${esc(u.current)})</span></div>
      ${u.notes ? `<details class="small"><summary>What's new</summary><pre class="update-notes">${esc(u.notes)}</pre></details>` : ''}
      <div class="row">${u.can_update ? '<button type="button" id="update-go">Update now</button>' : ''}
        ${u.url ? `<a class="small" href="${esc(u.url)}" target="_blank" rel="noopener">Release on GitHub</a>` : ''}</div>
      ${u.why_not ? `<div class="muted small">${esc(u.why_not)}</div>` : ''}`;
  } else {
    html = `<div>NetMaster ${esc(u.current)} · <span class="muted small">${u.latest ? 'up to date' : 'no release found yet'}${u.checked ? ` · checked ${fmtAgo(u.checked)} ago` : ''}</span>
      <button type="button" class="link small" id="update-check">Check now</button></div>`;
  }
  if (u.error && !u.updating) html += `<div class="small warn-text">${esc(u.error)}</div>`;
  if (box.dataset.html !== html) { box.innerHTML = html; box.dataset.html = html; }
  // A small box at the top of the overview while an update is available or being installed.
  const ov = $('#ov-update');
  const ovHtml = u.updating
    ? `<span><b>Updating to ${esc(u.updating)}…</b></span><span class="muted small">This page reloads by itself.</span>`
    : u.available
      ? `<span><b>NetMaster ${esc(u.latest)} is available</b></span><span class="muted small">(you have ${esc(u.current)})</span>
        <button type="button" class="small" data-goto-update>${u.can_update ? 'Update' : 'Show'}</button>`
      : '';
  ov.hidden = !ovHtml;
  if (ov.dataset.html !== ovHtml) { ov.innerHTML = ovHtml; ov.dataset.html = ovHtml; }
}
// Settings → General, opened and scrolled to the update box (from the overview box or a notification).
function gotoUpdate() {
  showTab('settings');
  const p = $('.panel[data-fold="general"]');
  if (p) setFold(p, true);
  setTimeout(() => $('#update-box').scrollIntoView({ behavior: 'smooth', block: 'center' }), 50);
}
$('#ov-update').addEventListener('click', (e) => { if (e.target.closest('[data-goto-update]')) gotoUpdate(); });
function updateFromHash() {
  if (location.hash !== '#update') return;
  history.replaceState(null, '', location.pathname);
  gotoUpdate();
}
window.addEventListener('hashchange', updateFromHash);
updateFromHash();
document.addEventListener('click', async (e) => {
  if (e.target.id === 'update-check') {
    e.target.disabled = true; e.target.textContent = 'Checking…';
    try { renderUpdate(await api('/api/update?check=1')); } catch (err) { alert(err.message); }
  } else if (e.target.id === 'update-go') {
    if (!confirm(`Update NetMaster to ${state.update.latest}?\n\nNetMaster stops for a minute or two while it updates. Your settings and data are kept.`)) return;
    e.target.disabled = true; e.target.textContent = 'Starting…';
    try { renderUpdate(await api('/api/update', 'POST')); } catch (err) { alert(err.message); e.target.disabled = false; e.target.textContent = 'Update now'; }
  }
});
api('/api/update').then(renderUpdate).catch(() => {});
