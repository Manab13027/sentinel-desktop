/* Sentinel renderer - vanilla JS, no external dependencies (fully offline). */
'use strict';

// ------------------------------------------------------------------ bootstrap / API
const Q = new URLSearchParams(location.search);
const bridge = window.sentinel || null;           // Electron preload bridge (absent in browser preview)
let CFG = { port: Q.get('port'), token: Q.get('token'), platform: Q.get('platform') || '' };

async function api(path, opts = {}) {
  const r = await fetch(`http://127.0.0.1:${CFG.port}${path}`, {
    method: opts.method || (opts.body ? 'POST' : 'GET'),
    headers: { 'X-Sentinel-Token': CFG.token, 'Content-Type': 'application/json' },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}

const S = { view: 'dashboard', summary: null, ports: null, conns: null, audit: null, alertsSince: Date.now() / 1000 - 5,
            portFilter: 'exposed', portSearch: '', netFilter: 'flagged', netSearch: '', expanded: new Set(), fixOpen: new Set(),
            chat: [], ai: null, scanning: false };

// ------------------------------------------------------------------ helpers
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEV = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' };
const VERDICT = { malicious: ['var(--critical)', 'Malicious'], unauthorised: ['var(--high)', 'Unauthorised'],
                  suspicious: ['var(--medium)', 'Suspicious'], new: ['var(--violet)', 'New destination'], blocked: ['var(--muted)', 'Blocked'], ok: ['var(--good)', 'Normal'] };
const ago = ts => { if (!ts) return 'never'; const s = Math.round(Date.now() / 1000 - ts); return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : new Date(ts * 1000).toLocaleString(); };
const sevChip = s => `<span class="chip sev" style="color:${SEV[s]};border-color:${SEV[s]}55"><i style="background:${SEV[s]}"></i>${esc(s)}</span>`;
const verdictChip = v => `<span class="chip" style="color:${VERDICT[v][0]};border-color:${VERDICT[v][0]}55"><i style="background:${VERDICT[v][0]}"></i>${VERDICT[v][1]}</span>`;
const recChip = r => `<span class="chip rec-${r}">${{ close: 'Close', review: 'Review', keep: 'Keep', blocked: '🔒 Blocked' }[r]}</span>`;

// Re-fetch everything that an action can change, then redraw the current screen.
async function refreshAll() {
  try {
    [S.ports, S.conns, S.audit, S.summary] = await Promise.all([api('/api/ports'), api('/api/connections'), api('/api/audit'), api('/api/summary')]);
    updateChrome();
  } catch (_) {}
  render();
}

// Run a fix as a background job and wait for it, updating `btn` with elapsed time.
async function runFix(fix_id, args, ref, btn) {
  if (btn) setBusy(btn, true, 'Applying…');
  let r;
  try {
    const { job } = await api('/api/fix', { body: { fix_id, args: args || {}, ref } });
    const t0 = Date.now();
    while (true) {
      await new Promise(res => setTimeout(res, 2000));
      const j = await api(`/api/job?id=${job}`);
      if (j.state === 'done') { r = j.result; break; }
      if (j.state === 'unknown') { r = { ok: false, output: 'The scanning engine restarted while the fix was running. Re-scan to check the result.' }; break; }
      const sec = Math.round((Date.now() - t0) / 1000);
      if (btn) btn.innerHTML = `<span class="spinner"></span> Applying… ${sec < 60 ? sec + 's' : Math.floor(sec / 60) + 'm ' + (sec % 60) + 's'}`;
    }
  } catch (e) { r = { ok: false, output: e.message }; }
  if (btn) setBusy(btn, false);
  if (!r.ok) toast('✗ Fix failed: ' + (r.output || '').split('\n').slice(-3).join('\n'), 'err');
  else if (r.still_failing) toast('Fix ran, but the check still fails. It may need a restart - then press Scan now.', 'err');
  else toast('✓ Fixed and verified', 'ok');
  return r;
}

function toast(msg, kind = '') {
  const t = document.createElement('div');
  t.className = `toast ${kind}`; t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), kind === 'err' ? 9000 : 5000);
}

function modal(html) {
  $('#modalBody').innerHTML = html;
  $('#modal').hidden = false;
  return new Promise(resolve => {
    const done = v => { $('#modal').hidden = true; resolve(v); };
    $('#modalBody').querySelectorAll('[data-m]').forEach(b => b.onclick = () => {
      if (b.dataset.m === 'cancel') return done(null);
      const sel = $('#modalBody input[name=opt]:checked');
      done({ action: b.dataset.m, opt: sel ? sel.value : null });
    });
    $('#modal').onclick = e => { if (e.target.id === 'modal') done(null); };
  });
}

// tooltips: any element with data-tip
document.addEventListener('mousemove', e => {
  const t = e.target.closest('[data-tip]'); const tip = $('#tooltip');
  if (!t) { tip.hidden = true; return; }
  tip.innerHTML = t.dataset.tip; tip.hidden = false;
  const x = Math.min(e.clientX + 14, innerWidth - tip.offsetWidth - 8), y = Math.min(e.clientY + 14, innerHeight - tip.offsetHeight - 8);
  tip.style.left = x + 'px'; tip.style.top = y + 'px';
});

// SVG donut with 2px gaps between segments; segments: [{label, value, color}]
function donut(segs, center, sub, size = 150) {
  const total = segs.reduce((a, s) => a + s.value, 0);
  const r = size / 2 - 8, c = 2 * Math.PI * r, cx = size / 2;
  let off = 0; const gap = segs.filter(s => s.value).length > 1 ? 2 : 0;
  const arcs = total ? segs.filter(s => s.value).map(s => {
    const len = (s.value / total) * c;
    const a = `<circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="${s.color}" stroke-width="3.5"
      stroke-dasharray="${Math.max(len - gap, 0.5)} ${c}" stroke-dashoffset="${-off}" transform="rotate(-90 ${cx} ${cx})"
      data-tip="<b>${esc(s.label)}</b>: ${s.value} (${Math.round(s.value / total * 100)}%)" style="cursor:default"/>
      <circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="transparent" stroke-width="16"
      stroke-dasharray="${len} ${c}" stroke-dashoffset="${-off}" transform="rotate(-90 ${cx} ${cx})"
      data-tip="<b>${esc(s.label)}</b>: ${s.value} (${Math.round(s.value / total * 100)}%)"/>`;
    off += len; return a;
  }).join('') : `<circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="var(--line-2)" stroke-width="3.5"/>`;
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="${esc(sub)}">${arcs}
    <text x="50%" y="48%" text-anchor="middle" fill="var(--text)" font-size="${size > 160 ? 30 : 22}" font-weight="500">${esc(center)}</text>
    <text x="50%" y="62%" text-anchor="middle" fill="var(--text-2)" font-size="9.5" letter-spacing="1.5">${esc(sub.toUpperCase())}</text></svg>`;
}
const legend = segs => `<ul class="legend">${segs.map(s => `<li><span class="sw" style="background:${s.color}"></span><b class="num">${s.value}</b><span class="sep"></span>${esc(s.label)}</li>`).join('')}</ul>`;
const donutBlock = (segs, center, sub) => `<div class="donut-wrap">${donut(segs, center, sub)}${legend(segs)}</div>`;

function hbars(rows, max) {
  max = max || Math.max(1, ...rows.map(r => r[1]));
  if (!rows.length) return '<div class="empty">Nothing to show</div>';
  return `<div class="hbars">${rows.map(([l, v]) => `<div class="hbar" data-tip="<b>${esc(l)}</b>: ${v}">
    <span class="lab">${esc(l)}</span><span class="val num">${v}</span><div class="track"><div class="fill" style="width:${Math.max(2, v / max * 100)}%"></div></div></div>`).join('')}</div>`;
}

function setBusy(btn, busy, label) {
  if (!btn) return;
  if (busy) { btn.dataset.l = btn.innerHTML; btn.innerHTML = `<span class="spinner"></span> ${label || 'Working…'}`; btn.disabled = true; }
  else { btn.innerHTML = btn.dataset.l || btn.innerHTML; btn.disabled = false; }
}

// ------------------------------------------------------------------ navigation
const TITLES = { dashboard: 'Runtime Security', ports: 'Open Ports', network: 'Network Monitor', vulns: 'Vulnerabilities & Patches', advisor: 'AI Security Advisor', settings: 'Settings & Threat Intel' };
function go(view) {
  S.view = view;
  document.querySelectorAll('.rail button[data-view]').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  document.querySelectorAll('.view').forEach(v => v.hidden = v.id !== `view-${view}`);
  $('#viewTitle').textContent = TITLES[view];
  render();
}
document.querySelectorAll('.rail button[data-view]').forEach(b => b.onclick = () => go(b.dataset.view));

function render() {
  ({ dashboard: renderDashboard, ports: renderPorts, network: renderNetwork, vulns: renderVulns, advisor: renderAdvisor, settings: renderSettings })[S.view]();
}

// ------------------------------------------------------------------ scanning
async function fullScan() {
  if (S.scanning) return;
  S.scanning = true; setBusy($('#scanBtn'), true, $('#deepScan').checked ? 'Deep scanning…' : 'Scanning…');
  try {
    S.summary = await api('/api/scan', { body: { deep: $('#deepScan').checked } });
    [S.ports, S.conns, S.audit] = await Promise.all([api('/api/ports'), api('/api/connections'), api('/api/audit')]);
    updateChrome(); render();
  } catch (e) { toast('Scan failed: ' + e.message, 'err'); }
  S.scanning = false; setBusy($('#scanBtn'), false);
}
$('#scanBtn').onclick = fullScan;

async function refreshSummary() { S.summary = await api('/api/summary'); updateChrome(); }

function updateChrome() {
  const s = S.summary; if (!s) return;
  const t = Math.max(...Object.values(s.scanned_at || {}), 0);
  $('#lastScan').innerHTML = `<i>Last scan:</i> ${t ? new Date(t * 1000).toLocaleTimeString() : 'never'}`;
  $('#hostBadge').textContent = `${s.host.hostname} · ${s.host.os === 'Darwin' ? 'macOS' : s.host.os} ${s.host.os_version || s.host.os_release}`;
  $('#adminBanner').hidden = !!s.host.admin;
  const bad = (s.connections.by_verdict.malicious || 0) + (s.connections.by_verdict.unauthorised || 0);
  $('#netDot').hidden = !bad;
}

// ------------------------------------------------------------------ dashboard
function renderDashboard() {
  const el = $('#view-dashboard'); const s = S.summary;
  if (!s) { el.innerHTML = `<div class="loading-full"><span class="spinner"></span>Running first scan…</div>`; return; }
  const sc = s.score, p = s.ports, c = s.connections, v = s.vulns;
  const fails = (S.audit?.findings || []).filter(f => f.status === 'fail');
  const sevCount = k => fails.filter(f => f.severity === k).length;
  const maxSev = Math.max(1, ...['critical', 'high', 'medium', 'low'].map(sevCount));
  const gradeColor = { A: 'var(--good)', B: 'var(--good)', C: 'var(--medium)', D: 'var(--high)', F: 'var(--critical)' }[sc.grade];
  const exposure = { loopback: 0, 'all-interfaces': 0, network: 0 };
  (S.ports?.ports || []).forEach(x => exposure[x.exposure]++);
  const recs = { close: 0, review: 0, keep: 0 };
  (S.ports?.ports || []).forEach(x => recs[x.recommendation]++);
  const vd = c.by_verdict;
  const dashPlan = s.plan.filter(t => !t.applied).slice(0, 6).concat(s.plan.filter(t => t.applied));

  el.innerHTML = `
  <div class="dash-row r1">
    <div class="cell">
      <h3>Top Exposed Ports <span class="sub">(Top 8 by risk)</span></h3>
      <table class="compact"><thead><tr><th>Port</th><th>Application</th><th>Risk</th><th>Advice</th></tr></thead><tbody>
      ${p.top.length ? p.top.map(x => `<tr class="row" data-goto="ports"><td class="strong num">${x.proto} ${x.port}<div class="muted" style="font-size:11px">${esc(x.service)}</div></td>
        <td>${esc(x.process.name || 'unknown')}</td><td>${sevChip(x.severity)}</td><td>${recChip(x.recommendation)}</td></tr>`).join('')
        : '<tr><td colspan="4" class="empty">No listening ports</td></tr>'}
      </tbody></table>
    </div>
    <div class="cell">
      <h3>Security Posture</h3>
      <div class="donut-wrap">
        ${donut([{ label: 'Score', value: sc.score, color: gradeColor }, { label: 'Risk', value: 100 - sc.score, color: 'var(--line-2)' }], sc.score, `grade ${sc.grade}`, 180)}
        ${legend([{ label: 'Critical issues', value: sc.by_severity.critical, color: SEV.critical }, { label: 'High', value: sc.by_severity.high, color: SEV.high },
                  { label: 'Medium', value: sc.by_severity.medium, color: SEV.medium }, { label: 'Ports to close', value: p.close, color: 'var(--violet)' },
                  { label: 'Bad connections', value: (vd.malicious || 0) + (vd.unauthorised || 0), color: 'var(--critical)' }])}
      </div>
    </div>
    <div class="cell">
      <h3>Vulnerability Status Board</h3>
      <div class="headline"><span class="big">${v.fail} Open</span><span class="muted">${v.exploited} actively exploited · ${v.meta.apps_scanned || 0} apps checked</span></div>
      <div class="board">
        ${['critical', 'high', 'medium', 'low'].map(k => `<div class="col">
          <div class="bar" style="height:${sevCount(k) / maxSev * 100}%;background:${SEV[k]}" data-tip="<b>${k}</b>: ${sevCount(k)} open"></div>
          <span class="tag" style="background:${SEV[k]}">${k[0].toUpperCase() + k.slice(1)}</span>
          <span class="cnt num">${sevCount(k)} open</span></div>`).join('')}
      </div>
    </div>
  </div>

  <div class="dash-row r2">
    <div class="cell"><h3>Port Exposure</h3>${donutBlock([
      { label: 'All interfaces', value: exposure['all-interfaces'], color: 'var(--high)' },
      { label: 'Specific network', value: exposure.network, color: 'var(--medium)' },
      { label: 'Loopback only', value: exposure.loopback, color: 'var(--accent)' }], p.total, 'ports')}</div>
    <div class="cell"><h3>Port Recommendations</h3>${donutBlock([
      { label: 'Close', value: recs.close, color: 'var(--critical)' }, { label: 'Review', value: recs.review, color: 'var(--medium)' },
      { label: 'Keep', value: recs.keep, color: 'var(--good)' }], p.total, 'ports')}</div>
    <div class="cell"><h3>Outbound Connections</h3>${donutBlock(Object.keys(VERDICT).map(k => ({ label: VERDICT[k][1], value: vd[k] || 0, color: VERDICT[k][0] })), c.total, 'connections')}</div>
    <div class="cell"><h3>System Checks</h3>${donutBlock([
      { label: 'Failed', value: v.fail, color: 'var(--critical)' }, { label: 'Passed', value: v.pass, color: 'var(--good)' }], v.fail + v.pass, 'checks')}</div>
  </div>

  <div class="dash-row r3">
    <div class="cell">
      <h3 style="display:flex;align-items:center;gap:8px">AI Action Plan <span class="sub">(prioritised by impact ÷ effort)</span>
        <button class="btn sm" data-plan-refresh style="margin-left:auto" data-tip="Re-check the system and remove issues that are fixed">↻ Refresh</button></h3>
      ${planList(dashPlan)}
    </div>
    <div class="cell">
      <h3>Live Threat Alerts <span class="sub">${c.meta.learning ? '· learning baseline until ' + new Date(c.meta.learning_until * 1000).toLocaleString() : ''}</span></h3>
      ${alertsList(s.alerts)}
    </div>
  </div>

  <div class="dash-row r3">
    <div class="cell"><h3>Issues by Category</h3>${hbars(Object.entries(v.by_category).sort((a, b) => b[1] - a[1]))}</div>
    <div class="cell"><h3>Most Active Network Apps</h3>${hbars(c.top_apps)}</div>
  </div>`;
  el.querySelectorAll('[data-goto]').forEach(r => r.onclick = () => go(r.dataset.goto));
  bindPlan(el, dashPlan);
}

function planList(items) {
  if (!items.length) return '<div class="empty">No urgent actions. Keep automatic updates on and re-scan regularly.</div>';
  return `<ol class="plan">${items.map((t, i) => `<li><span class="n">${i + 1}</span>
    <div><div class="t">${esc(t.title)} ${sevChip(t.severity)}</div><div class="r">${esc(t.rationale)}</div></div>
    <div>${t.applied ? `<span class="chip" style="color:var(--medium)" data-tip="Restart, then Scan now to verify">Applied · pending</span>`
      : t.automatable ? `<button class="btn sm primary" data-plan="${i}">Fix</button>` : `<button class="btn sm" data-plan="${i}">How to</button>`}</div></li>`).join('')}</ol>`;
}

async function recheck(btn) {
  setBusy(btn, true, 'Checking…');
  try {
    S.summary = await api('/api/scan', { body: { deep: false } });
    toast('Re-checked - fixed issues removed from the plan', 'ok');
  } catch (e) { toast('Re-check failed: ' + e.message, 'err'); }
  setBusy(btn, false);
  await refreshAll();
}

function bindPlan(root, items) {
  root.querySelectorAll('[data-plan-refresh]').forEach(b => b.onclick = () => recheck(b));
  items = items || S.summary.plan;
  root.querySelectorAll('[data-plan]').forEach(b => b.onclick = async () => {
    const t = items[+b.dataset.plan];
    if (t.kind === 'port') return closePortFlow(S.ports.ports.find(p => p.id === t.ref) || { port: t.port, proto: t.proto, process: { pid: t.pid } });
    if (t.kind === 'connection') return blockConnFlow((S.conns?.connections || []).find(c => c.id === t.ref) || { remote_ip: t.ip, pid: t.pid, app: t.target });
    if (t.automatable && t.fix_id) {
      const ok = await modal(`<h2>${esc(t.title)}?</h2><p>${esc(t.rationale)}</p><p class="muted">Your OS may ask for administrator permission.</p>
        <div class="actions"><button class="btn" data-m="cancel">Cancel</button><button class="btn primary" data-m="yes">Apply fix</button></div>`);
      if (!ok) return;
      await runFix(t.fix_id, t.fix_args, t.ref, b);
      return refreshAll();
    }
    S.fixOpen.add(t.ref); go('vulns');
    setTimeout(() => document.getElementById('f-' + t.ref)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 150);
  });
}

function alertsList(alerts) {
  if (!alerts || !alerts.length) return '<div class="empty">No suspicious or unauthorised connections detected.</div>';
  return `<div class="alerts">${alerts.slice(0, 8).map(a => `<div class="alert" style="border-left-color:${VERDICT[a.verdict][0]}">
    ${verdictChip(a.verdict)}<div><div class="a-t">${esc(a.title)}</div><div class="a-d">${esc(a.detail)}</div></div>
    <span class="muted" style="font-size:11px">${ago(a.ts)}</span></div>`).join('')}</div>`;
}

// ------------------------------------------------------------------ ports
function renderPorts() {
  const el = $('#view-ports');
  if (!S.ports) { el.innerHTML = '<div class="loading-full"><span class="spinner"></span>Loading…</div>'; return; }
  let rows = S.ports.ports;
  if (S.portFilter === 'exposed') rows = rows.filter(r => r.exposure !== 'loopback');
  if (S.portFilter === 'close') rows = rows.filter(r => r.recommendation === 'close');
  const q = S.portSearch.toLowerCase();
  if (q) rows = rows.filter(r => `${r.port} ${r.service} ${r.process.name} ${r.process.exe}`.toLowerCase().includes(q));
  const all = S.ports.ports;
  el.innerHTML = `<div class="page">
    <div class="kpis">
      <div class="kpi"><div class="l">Listening sockets</div><div class="v num">${all.length}</div></div>
      <div class="kpi"><div class="l">Reachable from network</div><div class="v num">${all.filter(r => r.exposure !== 'loopback').length}</div></div>
      <div class="kpi"><div class="l">Recommended to close</div><div class="v num" style="color:var(--critical)">${all.filter(r => r.recommendation === 'close').length}</div></div>
      <div class="kpi"><div class="l">Applications listening</div><div class="v num">${new Set(all.map(r => r.process.name)).size}</div></div>
    </div>
    ${S.ports.note ? `<div class="banner" style="margin-bottom:12px">${esc(S.ports.note)}</div>` : ''}
    <div class="page-head">
      <div class="seg" id="pf">${[['exposed', 'Network-exposed'], ['close', 'Should close'], ['all', 'All']].map(([k, l]) => `<button data-k="${k}" class="${S.portFilter === k ? 'on' : ''}">${l}</button>`).join('')}</div>
      <input type="text" id="ps" placeholder="Search port, service or app…" value="${esc(S.portSearch)}" style="width:260px">
      <span class="grow"></span>
      <button class="btn" id="pr">Refresh</button>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>Port</th><th>Service</th><th>Application</th><th>PID</th><th>User</th><th>Exposure</th><th>Risk</th><th>Advice</th><th></th></tr></thead>
      <tbody>${rows.map(r => portRow(r)).join('') || '<tr><td colspan="9" class="empty">No ports match this filter.</td></tr>'}</tbody>
    </table></div></div>`;
  el.querySelectorAll('#pf button').forEach(b => b.onclick = () => { S.portFilter = b.dataset.k; renderPorts(); });
  const ps = $('#ps'); ps.oninput = () => { S.portSearch = ps.value; clearTimeout(ps._t); ps._t = setTimeout(() => { renderPorts(); const n = $('#ps'); n.focus(); n.setSelectionRange(n.value.length, n.value.length); }, 250); };
  $('#pr').onclick = async () => { setBusy($('#pr'), true); S.ports = await api('/api/ports?refresh=1'); renderPorts(); };
  el.querySelectorAll('tr.row').forEach(tr => tr.onclick = e => {
    if (e.target.closest('button')) return;
    S.expanded.has(tr.dataset.id) ? S.expanded.delete(tr.dataset.id) : S.expanded.add(tr.dataset.id); renderPorts();
  });
  el.querySelectorAll('[data-close]').forEach(b => b.onclick = () => closePortFlow(S.ports.ports.find(p => p.id === b.dataset.close)));
  el.querySelectorAll('[data-kill]').forEach(b => b.onclick = () => killFlow(+b.dataset.kill, b.dataset.name));
  el.querySelectorAll('[data-unblock]').forEach(b => b.onclick = async () => {
    const r = S.ports.ports.find(p => p.id === b.dataset.unblock);
    setBusy(b, true, '');
    const out = await api('/api/port/unblock', { body: { port: r.port, proto: r.proto } }).catch(e => ({ ok: false, output: e.message }));
    toast(out.ok ? `Port ${r.port} unblocked` : out.output, out.ok ? 'ok' : 'err');
    await refreshAll();
  });
  el.querySelectorAll('[data-reveal]').forEach(b => b.onclick = () => bridge?.showItem(b.dataset.reveal));
}

function portRow(r) {
  const open = S.expanded.has(r.id); const p = r.process;
  const riskBar = `<div style="display:flex;align-items:center;gap:6px"><span class="num" style="width:22px;color:var(--text)">${r.risk}</span>
    <div style="width:54px;height:4px;background:var(--line-2);border-radius:4px"><div style="height:4px;border-radius:4px;width:${r.risk}%;background:${SEV[r.severity]}"></div></div></div>`;
  return `<tr class="row ${open ? 'expanded' : ''}" data-id="${esc(r.id)}">
    <td class="strong num">${r.proto} ${r.port}</td><td>${esc(r.service)}</td>
    <td class="strong">${esc(p.name || 'unknown')}<div class="muted mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.exe || '')}</div></td>
    <td class="num">${p.pid ?? '-'}</td><td>${esc((p.user || '').split('\\').pop())}</td>
    <td>${{ loopback: 'This PC only', 'all-interfaces': '<span style="color:var(--high)">All interfaces</span>', network: 'Network' }[r.exposure]}</td>
    <td>${riskBar}</td><td>${recChip(r.recommendation)}</td>
    <td style="text-align:right">${r.blocked ? `<button class="btn sm" data-unblock="${esc(r.id)}">Unblock</button>`
      : r.recommendation !== 'keep' ? `<button class="btn sm ${r.recommendation === 'close' ? 'danger' : ''}" data-close="${esc(r.id)}">Close port</button>` : ''}</td></tr>
    ${open ? `<tr class="detail"><td colspan="9">
      <div style="display:grid;grid-template-columns:1.4fr 1fr;gap:20px">
        <div><div class="muted" style="margin-bottom:6px">AI assessment</div><div style="line-height:1.6;color:var(--text-2)">${esc(explainPort(r))}</div></div>
        <div class="mono" style="color:var(--text-2);line-height:1.7">
          Bound to: ${esc(r.addresses.join(', '))}<br>Parent: ${esc(p.parent || '-')}<br>
          Command: <span style="word-break:break-all">${esc(p.cmdline || '-')}</span>
          <div style="margin-top:10px;display:flex;gap:6px">
            <button class="btn sm danger" data-close="${esc(r.id)}">Close port…</button>
            ${p.pid ? `<button class="btn sm" data-kill="${p.pid}" data-name="${esc(p.name)}">Terminate process</button>` : ''}
            ${p.exe && bridge ? `<button class="btn sm ghost" data-reveal="${esc(p.exe)}">Show file</button>` : ''}
          </div></div></div></td></tr>` : ''}`;
}

function explainPort(r) {
  const p = r.process;
  const exp = { loopback: 'It only accepts connections from this computer, so outside exposure is minimal.',
                'all-interfaces': 'It listens on every network interface, so other devices on your network can reach it.',
                network: 'It is bound to a specific network address and reachable from that network.' }[r.exposure];
  const rec = { close: 'Recommendation: CLOSE - block it in the firewall, or stop the program/service if you do not use it.',
                review: 'Recommendation: REVIEW - keep it only if you recognise the program and need the feature.',
                keep: 'Recommendation: KEEP - low risk.',
                blocked: 'Status: BLOCKED by a Sentinel firewall rule - other devices can no longer reach it.' }[r.recommendation] || '';
  return `${r.proto} ${r.port} (${r.service}) is opened by ${p.name || 'an unidentified process'}. ${exp} ${r.reasons.join(' ')} ${rec}`;
}

async function closePortFlow(r) {
  let services = [];
  if (r.process?.pid && CFG.platform === 'win32') { try { services = (await api(`/api/port/options?pid=${r.process.pid}`)).services; } catch (_) {} }
  const name = r.process?.name || 'the owning process';
  const res = await modal(`<h2>Close ${esc(r.proto)} port ${r.port}?</h2>
    <p>${esc(r.service ? r.service + ' - ' : '')}${esc((r.reasons || [])[0] || '')}<br>
    Sentinel ${r.recommendation === 'close' ? '<b style="color:#ffb4b4">recommends closing this port</b>' : 'suggests reviewing this port'}. Choose how:</p>
    <div class="opts">
      <label class="opt"><input type="radio" name="opt" value="block" checked><div>Block the port in the firewall <small>Recommended. Instant, reversible from Settings → Firewall rules. The app keeps running but nobody can connect to it.</small></div></label>
      ${r.process?.pid ? `<label class="opt"><input type="radio" name="opt" value="block_kill"><div>Block and terminate ${esc(name)} <small>Also stops the program now. It may start again on reboot.</small></div></label>` : ''}
      ${services.map(s => `<label class="opt"><input type="radio" name="opt" value="svc:${esc(s.Name)}"><div>Stop &amp; disable service “${esc(s.DisplayName)}” <small>Permanently stops the Windows service that owns this port (start mode: ${esc(s.StartMode)}).</small></div></label>`).join('')}
    </div>
    <p class="muted" style="font-size:12px">Your OS will ask for administrator permission.</p>
    <div class="actions"><button class="btn" data-m="cancel">Not now</button><button class="btn danger" data-m="yes">Yes, close port</button></div>`);
  if (!res) return;
  toast('Closing port ' + r.port + '…');
  try {
    let out;
    if (res.opt.startsWith('svc:')) out = await api('/api/service/disable', { body: { name: res.opt.slice(4) } });
    else out = await api('/api/port/block', { body: { port: r.port, proto: r.proto, kill: res.opt === 'block_kill', pid: r.process?.pid } });
    toast((out.ok ? '✓ ' : '✗ ') + (out.output || '') + (out.note ? '\n' + out.note : ''), out.ok ? 'ok' : 'err');
    if (out.ok) await refreshAll();
  } catch (e) { toast(e.message, 'err'); }
}

async function killFlow(pid, name) {
  const res = await modal(`<h2>Terminate ${esc(name)} (PID ${pid})?</h2><p>Unsaved work in this program will be lost. System processes may be restarted by the OS.</p>
    <div class="actions"><button class="btn" data-m="cancel">Cancel</button><button class="btn danger" data-m="yes">Terminate</button></div>`);
  if (!res) return;
  const out = await api('/api/process/kill', { body: { pid } }).catch(e => ({ ok: false, output: e.message }));
  toast(out.output, out.ok ? 'ok' : 'err');
  if (out.ok) await refreshAll();
}

// ------------------------------------------------------------------ network
function renderNetwork() {
  const el = $('#view-network');
  if (!S.conns) { el.innerHTML = '<div class="loading-full"><span class="spinner"></span>Loading…</div>'; return; }
  const all = S.conns.connections; const cnt = k => all.filter(c => c.verdict === k).length;
  let rows = all;
  if (S.netFilter === 'flagged') rows = rows.filter(c => c.verdict !== 'ok');
  if (S.netFilter === 'public') rows = rows.filter(c => c.public);
  const q = S.netSearch.toLowerCase();
  if (q) rows = rows.filter(c => `${c.app} ${c.remote_ip} ${c.remote_host} ${c.remote_port}`.toLowerCase().includes(q));
  const m = S.conns;
  el.innerHTML = `<div class="page">
    <div class="kpis">
      <div class="kpi"><div class="l">Active connections</div><div class="v num">${all.length}</div></div>
      ${['malicious', 'unauthorised', 'suspicious', 'new'].map(k => `<div class="kpi"><div class="l">${VERDICT[k][1]}</div><div class="v num" style="color:${cnt(k) ? VERDICT[k][0] : 'var(--text)'}">${cnt(k)}</div></div>`).join('')}
      <div class="kpi"><div class="l">Threat-intel entries</div><div class="v num">${m.intel_entries ?? '-'}</div></div>
    </div>
    ${m.learning ? `<div class="banner" style="margin-bottom:12px;background:#121a2a;border-color:#1f3558;color:#a9c8f5">AI baseline is learning each app's normal destinations until ${new Date(m.learning_until * 1000).toLocaleString()}. After that, first-seen destinations are flagged as anomalies.</div>` : ''}
    ${m.note ? `<div class="banner" style="margin-bottom:12px">${esc(m.note)}</div>` : ''}
    <div class="page-head">
      <div class="seg" id="nf">${[['flagged', 'Flagged'], ['public', 'Internet'], ['all', 'All']].map(([k, l]) => `<button data-k="${k}" class="${S.netFilter === k ? 'on' : ''}">${l}</button>`).join('')}</div>
      <input type="text" id="ns" placeholder="Search app, IP or domain…" value="${esc(S.netSearch)}" style="width:260px">
      <span class="grow"></span>
      <span class="muted">Policy:</span>
      <div class="seg" id="mode">${[['monitor', 'Monitor threats'], ['allowlist', 'Allowlist only']].map(([k, l]) => `<button data-k="${k}" class="${m.mode === k ? 'on' : ''}" data-tip="${k === 'allowlist' ? 'Every internet destination not on your allowed list is flagged as unauthorised' : 'Flag threat-intel matches, block-list hits and anomalies'}">${l}</button>`).join('')}</div>
      <span class="muted" style="font-size:11px">auto-refresh 15s</span>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>Verdict</th><th>Application</th><th>Destination</th><th>Port</th><th>State</th><th>Why</th><th></th></tr></thead>
      <tbody>${rows.map(c => `<tr>
        <td>${verdictChip(c.verdict)}</td>
        <td class="strong">${esc(c.app)} <span class="muted num">(${c.pid})</span></td>
        <td><span class="strong">${esc(c.remote_host || c.remote_ip)}</span>${c.remote_host ? `<div class="muted mono">${esc(c.remote_ip)}</div>` : ''}</td>
        <td class="num">${c.remote_port}</td><td class="muted">${esc(c.status)}${c.count > 1 ? ` <span class="chip" data-tip="${c.count} parallel sockets">×${c.count}</span>` : ''}</td>
        <td style="max-width:380px;font-size:12px">${esc(c.flags.join(' ')) || '<span class="muted">-</span>'}</td>
        <td style="text-align:right;white-space:nowrap">${c.public && c.verdict !== 'blocked' ? `
          <button class="btn sm ${['malicious', 'unauthorised'].includes(c.verdict) ? 'danger' : ''}" data-block="${esc(c.id)}">Block</button>
          ${c.verdict !== 'ok' ? `<button class="btn sm ghost" data-allow="${esc(c.id)}" data-tip="Add destination to allowed list">Trust</button>` : ''}` : ''}</td></tr>`).join('')
        || `<tr><td colspan="7" class="empty">${S.netFilter === 'flagged' ? 'No flagged connections right now - all traffic matches policy.' : 'No connections.'}</td></tr>`}</tbody>
    </table></div></div>`;
  el.querySelectorAll('#nf button').forEach(b => b.onclick = () => { S.netFilter = b.dataset.k; renderNetwork(); });
  el.querySelectorAll('#mode button').forEach(b => b.onclick = async () => {
    await api('/api/policy', { body: { mode: b.dataset.k } }); S.conns = await api('/api/connections?refresh=1'); renderNetwork();
    toast(b.dataset.k === 'allowlist' ? 'Allowlist mode: add trusted domains in Settings, or click Trust on a connection.' : 'Monitoring for threats and anomalies.');
  });
  const ns = $('#ns'); ns.oninput = () => { S.netSearch = ns.value; clearTimeout(ns._t); ns._t = setTimeout(() => { renderNetwork(); const n = $('#ns'); n.focus(); n.setSelectionRange(n.value.length, n.value.length); }, 250); };
  el.querySelectorAll('[data-block]').forEach(b => b.onclick = () => blockConnFlow(all.find(c => c.id === b.dataset.block)));
  el.querySelectorAll('[data-allow]').forEach(b => b.onclick = async () => {
    const c = all.find(x => x.id === b.dataset.allow);
    await api('/api/policy/allow', { body: c.remote_host ? { domain: c.remote_host } : { ip: c.remote_ip } });
    toast(`Trusted ${c.remote_host || c.remote_ip}`, 'ok'); S.conns = await api('/api/connections?refresh=1'); renderNetwork();
  });
}

async function blockConnFlow(c) {
  if (!c) return;
  const res = await modal(`<h2>Block ${esc(c.remote_host || c.remote_ip)}?</h2>
    <p>${esc(c.app)} is connected to <b>${esc(c.remote_ip)}</b>${c.remote_port ? ':' + c.remote_port : ''}. ${esc((c.flags || []).join(' '))}</p>
    <div class="opts">
      <label class="opt"><input type="radio" name="opt" value="block" checked><div>Block all traffic to and from this IP <small>Firewall rule; reversible in Settings.</small></div></label>
      ${c.pid ? `<label class="opt"><input type="radio" name="opt" value="block_kill"><div>Block and terminate ${esc(c.app)} <small>Recommended if you don't recognise the program.</small></div></label>` : ''}
    </div>
    <div class="actions"><button class="btn" data-m="cancel">Cancel</button><button class="btn danger" data-m="yes">Block</button></div>`);
  if (!res) return;
  const out = await api('/api/ip/block', { body: { ip: c.remote_ip, kill: res.opt === 'block_kill', pid: c.pid } }).catch(e => ({ ok: false, output: e.message }));
  toast((out.ok ? '✓ ' : '✗ ') + out.output + (out.kill ? '\n' + out.kill.output : ''), out.ok ? 'ok' : 'err');
  if (out.ok) await refreshAll();
}

// ------------------------------------------------------------------ vulnerabilities
function renderVulns() {
  const el = $('#view-vulns');
  if (!S.audit) { el.innerHTML = '<div class="loading-full"><span class="spinner"></span>Auditing system…</div>'; return; }
  const fs = S.audit.findings; const fails = fs.filter(f => f.status === 'fail'); const passes = fs.filter(f => f.status !== 'fail');
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const cats = {}; fails.sort((a, b) => order[a.severity] - order[b.severity]).forEach(f => (cats[f.category] = cats[f.category] || []).push(f));
  el.innerHTML = `<div class="page">
    <div class="kpis">
      ${['critical', 'high', 'medium', 'low'].map(k => `<div class="kpi"><div class="l">${k[0].toUpperCase() + k.slice(1)}</div><div class="v num" style="color:${fails.some(f => f.severity === k) ? SEV[k] : 'var(--text)'}">${fails.filter(f => f.severity === k).length}</div></div>`).join('')}
      <div class="kpi"><div class="l">Actively exploited</div><div class="v num">${fails.filter(f => f.exploited).length}</div></div>
      <div class="kpi"><div class="l">Apps checked · CVE DB</div><div class="v num" style="font-size:16px;margin-top:8px">${S.audit.apps_scanned} · ${S.audit.cve_db_entries} rules <span class="muted" style="font-size:11px">(${esc(S.audit.cve_db_updated || '')})</span></div></div>
    </div>
    <div class="page-head">
      <span class="muted">Fixes are built in and work offline. Downloading patches themselves needs internet.</span>
      <span class="grow"></span>
      <button class="btn" id="cveImp">Import CVE database…</button>
      <button class="btn primary" id="deep">Deep scan for missing OS patches</button>
    </div>
    ${Object.keys(cats).length ? Object.entries(cats).map(([cat, list]) => `<div class="cat-head">${esc(cat)} · ${list.length}</div>${list.map(findingCard).join('')}`).join('')
      : '<div class="panel empty">No failing checks - nice work.</div>'}
    <details style="margin-top:18px"><summary class="muted" style="cursor:pointer">Passed / informational checks (${passes.length})</summary>
      <div style="margin-top:8px">${passes.map(findingCard).join('')}</div></details>
  </div>`;
  el.querySelectorAll('[data-fix]').forEach(b => b.onclick = () => { const id = b.dataset.fix; S.fixOpen.has(id) ? S.fixOpen.delete(id) : S.fixOpen.add(id); renderVulns(); });
  el.querySelectorAll('.fixbox[data-load]').forEach(loadFixbox);
  $('#deep').onclick = async () => {
    setBusy($('#deep'), true, 'Checking OS updates…');
    try { S.audit = await api('/api/audit?refresh=1&deep=1'); await refreshSummary(); } catch (e) { toast(e.message, 'err'); }
    renderVulns();
  };
  $('#cveImp').onclick = async () => {
    if (!bridge) return toast('Available in the desktop app', 'err');
    const f = await bridge.openFile([{ name: 'JSON', extensions: ['json'] }]); if (!f) return;
    try { const r = await api('/api/cve/import', { body: { text: f.text } }); toast(`Imported ${r.entries} CVE rules. Re-scanning…`, 'ok'); S.audit = await api('/api/audit?refresh=1'); renderVulns(); }
    catch (e) { toast('Import failed: ' + e.message, 'err'); }
  };
}

function findingCard(f) {
  const open = S.fixOpen.has(f.id);
  const color = f.status === 'fail' ? SEV[f.severity] : f.status === 'pass' ? 'var(--good)' : 'var(--muted)';
  return `<div class="finding ${f.status === 'pass' ? 'pass' : ''}" id="f-${esc(f.id)}"><div class="stripe" style="background:${color}"></div>
    <div><div class="ft">${f.status === 'pass' ? '✓ ' : ''}${esc(f.title)} ${f.exploited ? '<span class="chip" style="color:var(--critical);border-color:#6b2326">Exploited in the wild</span>' : ''}</div>
    ${f.detail ? `<div class="fd">${esc(f.detail)}</div>` : ''}</div>
    <div style="display:flex;gap:8px;align-items:center">${f.status === 'fail' ? sevChip(f.severity) : `<span class="chip">${esc(f.status)}</span>`}
    ${f.fix_id ? `<button class="btn sm ${open ? '' : 'primary'}" data-fix="${esc(f.id)}">${open ? 'Hide' : 'How to fix'}</button>` : ''}</div></div>
    ${open && f.fix_id ? `<div class="fixbox" data-load="${esc(f.id)}"><span class="spinner"></span></div>` : ''}`;
}

async function loadFixbox(box) {
  const f = S.audit.findings.find(x => x.id === box.dataset.load); if (!f) return;
  const pb = await api(`/api/playbook?fix_id=${encodeURIComponent(f.fix_id)}&args=${encodeURIComponent(JSON.stringify(f.fix_args || {}))}`);
  box.innerHTML = `<div style="color:var(--text);font-weight:500">${esc(pb.title)}</div>
    <div class="muted" style="margin-top:4px;line-height:1.5">${esc(pb.why)}</div>
    ${pb.manual.length ? `<div style="margin-top:10px" class="muted">Manual steps</div><ol>${pb.manual.map(s => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}
    ${pb.commands.length ? `<div class="muted">What Sentinel will run${pb.elevate ? ' (as administrator)' : ''}</div><pre>${esc(pb.commands.join('\n'))}</pre>` : ''}
    ${pb.note ? `<div class="banner" style="margin:8px 0">${esc(pb.note)}</div>` : ''}
    <div style="display:flex;gap:8px;align-items:center;margin-top:10px">
      ${pb.automatable ? `<button class="btn primary" data-apply>Apply fix automatically</button>`
        : pb.open_url ? `<button class="btn primary" data-open>Open ${CFG.platform === 'darwin' ? 'Software Update' : 'Settings'}</button>`
        : '<span class="muted">This fix must be applied manually (follow the steps above).</span>'}
      ${pb.needs_internet ? '<span class="muted" style="font-size:12px">⚠ Needs internet to download the update.</span>' : ''}
      ${pb.undo.length ? `<span class="muted" style="font-size:12px">Reversible.</span>` : ''}
    </div><pre data-out hidden></pre>`;
  const openBtn = box.querySelector('[data-open]');
  if (openBtn) openBtn.onclick = async () => {
    if (!bridge?.openUrl) return toast('Open System Settings > General > Software Update', 'err');
    await bridge.openUrl(pb.open_url);
    toast('Opened Software Update - click Update Now, then re-scan when it finishes.', 'ok');
  };
  const btn = box.querySelector('[data-apply]');
  if (btn) btn.onclick = async () => {
    const ok = await modal(`<h2>${esc(pb.title)}?</h2><p>${esc(pb.why)}</p><p class="muted">Your OS may ask for administrator permission${pb.timeout > 600 ? '. Updates can take several minutes - you can keep using Sentinel meanwhile' : ''}.</p>
      <div class="actions"><button class="btn" data-m="cancel">Cancel</button><button class="btn primary" data-m="yes">Apply fix</button></div>`);
    if (!ok) return;
    const r = await runFix(f.fix_id, f.fix_args, f.id, btn);
    const out = box.querySelector('[data-out]');
    out.hidden = false;
    out.textContent = (r.ok ? (r.still_failing ? '⚠ Applied, but the check still fails - restart and Scan now\n' : '✓ Fixed and verified\n') : '✗ Failed\n') + (r.output || '');
    if (r.ok) { if (!r.still_failing) S.fixOpen.delete(f.id); setTimeout(refreshAll, 1500); }
  };
}

// ------------------------------------------------------------------ advisor
const SUGGEST = ['What should I fix first?', "What's my overall security score?", 'Why is port 445 risky?', 'How do I turn on the firewall?', 'Is Remote Desktop dangerous?', 'How do I update vulnerable apps?'];
async function renderAdvisor() {
  const el = $('#view-advisor');
  if (!S.ai) { try { S.ai = await api('/api/ai/status'); } catch (_) { S.ai = { available: false }; } }
  const s = S.summary;
  if (!S.chat.length) S.chat.push({ who: 'bot', text: `Hi - I'm Sentinel's offline security advisor. I've analysed your latest scan${s ? ` (score ${s.score.score}/100, grade ${s.score.grade})` : ''}. Ask me about any port, app, connection or finding, or how to fix something.` });
  el.innerHTML = `<div class="page"><div class="adv-grid">
    <div class="chat"><div class="msgs" id="msgs">${S.chat.map(m => `<div class="msg ${m.who}">${esc(m.text)}${m.src ? `<div class="src">Sources: ${esc(m.src)}</div>` : ''}</div>`).join('')}</div>
      <div><div class="suggest">${SUGGEST.map(q => `<button class="btn sm ghost" data-q="${esc(q)}">${esc(q)}</button>`).join('')}</div>
      <form id="askf"><input type="text" id="askq" placeholder="Ask about a port, app, CVE or fix…" autocomplete="off"><button class="btn primary">Ask</button></form></div></div>
    <div style="display:grid;gap:16px;align-content:start">
      <div class="panel"><h3>Engine</h3>
        <div style="display:flex;gap:10px;align-items:center">${S.ai.available
          ? `<span class="chip" style="color:var(--good);border-color:#1e4a1e"><i style="background:var(--good)"></i>Local LLM: ${esc(S.ai.model)}</span><span class="muted">via Ollama, on this device</span>`
          : `<span class="chip" style="color:var(--accent);border-color:#1f3558"><i style="background:var(--accent)"></i>Built-in expert engine</span><span class="muted">Risk scoring, planner & knowledge base - no model required</span>`}</div>
        ${S.ai.available ? '' : '<div class="muted" style="margin-top:8px;font-size:12px;line-height:1.5">Optional: install Ollama and a model (e.g. llama3.2) for conversational answers. All fixes and advice work without it.</div>'}
      </div>
      <div class="panel"><h3 style="display:flex;align-items:center;gap:8px">Action Plan
        <button class="btn sm" data-plan-refresh style="margin-left:auto" data-tip="Re-check the system and remove issues that are fixed">↻ Refresh</button></h3>${s ? planList(s.plan) : '<div class="empty">Run a scan first</div>'}</div>
    </div></div></div>`;
  const msgs = $('#msgs'); msgs.scrollTop = msgs.scrollHeight;
  const ask = async q => {
    if (!q.trim()) return;
    S.chat.push({ who: 'user', text: q }); S.chat.push({ who: 'bot', text: 'Thinking…' }); renderAdvisor();
    try { const r = await api('/api/ask', { body: { question: q } }); S.chat[S.chat.length - 1] = { who: 'bot', text: r.answer, src: r.sources?.slice(0, 3).join(' · ') }; }
    catch (e) { S.chat[S.chat.length - 1] = { who: 'bot', text: 'Error: ' + e.message }; }
    renderAdvisor();
  };
  $('#askf').onsubmit = e => { e.preventDefault(); ask($('#askq').value); };
  el.querySelectorAll('[data-q]').forEach(b => b.onclick = () => ask(b.dataset.q));
  if (s) bindPlan(el, s.plan);
  $('#askq').focus();
}

// ------------------------------------------------------------------ settings
async function renderSettings() {
  const el = $('#view-settings');
  const [pol, rules, log, ai] = await Promise.all([api('/api/policy'), api('/api/rules'), api('/api/events'), api('/api/ai/status').catch(() => ({}))]);
  const ta = (id, arr) => `<textarea id="${id}" class="mono" placeholder="one per line">${esc((arr || []).join('\n'))}</textarea>`;
  el.innerHTML = `<div class="page" style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
    <div class="panel"><h3>Network Policy</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div><div class="muted">Allowed domains</div>${ta('ad', pol.allowed_domains)}</div>
        <div><div class="muted">Blocked domains</div>${ta('bd', pol.blocked_domains)}</div>
        <div><div class="muted">Allowed IPs</div>${ta('ai', pol.allowed_ips)}</div>
        <div><div class="muted">Blocked IPs</div>${ta('bi', pol.blocked_ips)}</div>
        <div><div class="muted">Trusted apps (no anomaly alerts)</div>${ta('ta', pol.trusted_apps)}</div>
        <div><div class="muted">Baseline learning window (hours)</div><input type="number" id="lh" min="0" max="720" value="${pol.learning_hours}" style="width:100px">
          <div class="muted" style="margin-top:12px">Mode</div><select id="md"><option value="monitor" ${pol.mode === 'monitor' ? 'selected' : ''}>Monitor threats</option><option value="allowlist" ${pol.mode === 'allowlist' ? 'selected' : ''}>Allowlist only</option></select></div>
      </div>
      <div style="margin-top:12px"><button class="btn primary" id="savePol">Save policy</button></div>
    </div>
    <div style="display:grid;gap:16px;align-content:start">
      <div class="panel"><h3>Threat Intelligence</h3>
        <p class="muted" style="line-height:1.5;margin-top:0">${S.conns?.intel_entries ?? '-'} offline indicators loaded. Import IP/CIDR/domain lists or hosts files (e.g. FireHOL level1, abuse.ch URLhaus) whenever you are online - they are stored locally.</p>
        <button class="btn" id="impIntel">Import threat feed…</button></div>
      <div class="panel"><h3>Local AI model (optional)</h3>
        <div style="display:grid;grid-template-columns:1fr 160px;gap:8px">
          <input type="text" id="ou" value="${esc(pol.ollama_url)}"><input type="text" id="om" value="${esc(pol.ollama_model)}"></div>
        <div class="muted" style="margin-top:8px">${ai.available ? `Connected · models: ${esc((ai.models || []).join(', '))}` : 'Not detected - the built-in engine is in use.'}</div></div>
      <div class="panel"><h3>Firewall rules created by Sentinel</h3>
        ${rules.rules.length ? `<table class="compact"><tbody>${rules.rules.map(r => `<tr><td class="mono">${esc(r.name)}</td><td style="text-align:right"><button class="btn sm" data-undo="${esc(r.name)}">Remove</button></td></tr>`).join('')}</tbody></table>` : '<div class="muted">None yet.</div>'}
        ${CFG.platform === 'darwin' && rules.rules.length ? '<button class="btn sm" id="reapply" style="margin-top:10px">Re-apply after reboot</button>' : ''}</div>
    </div>
    <div class="panel" style="grid-column:1/-1"><h3>Activity Log</h3>
      <div style="display:flex;gap:8px;margin-bottom:10px"><button class="btn sm" id="export">Export full report (JSON)</button></div>
      <table class="compact"><thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Result</th></tr></thead><tbody>
      ${log.actions.slice(0, 40).map(a => `<tr><td class="num">${new Date(a.ts * 1000).toLocaleString()}</td><td>${esc(a.action)}</td><td class="mono">${esc(a.target)}</td><td>${a.ok ? '<span style="color:var(--good)">✓ ok</span>' : '<span style="color:var(--critical)">✗ failed</span>'}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">No actions yet.</td></tr>'}
      </tbody></table></div></div>`;
  const lines = id => $('#' + id).value.split(/\n+/).map(s => s.trim()).filter(Boolean);
  $('#savePol').onclick = async () => {
    await api('/api/policy', { body: { allowed_domains: lines('ad'), blocked_domains: lines('bd'), allowed_ips: lines('ai'), blocked_ips: lines('bi'),
      trusted_apps: lines('ta'), learning_hours: +$('#lh').value, mode: $('#md').value, ollama_url: $('#ou').value, ollama_model: $('#om').value } });
    S.ai = null; toast('Policy saved', 'ok');
  };
  $('#impIntel').onclick = async () => {
    if (!bridge) return toast('Available in the desktop app', 'err');
    const f = await bridge.openFile(); if (!f) return;
    const r = await api('/api/intel/import', { body: { name: f.name.replace(/\.\w+$/, ''), text: f.text } }).catch(e => ({ error: e.message }));
    r.error ? toast(r.error, 'err') : toast(`Imported ${r.added} indicators (${r.total} total)`, 'ok');
  };
  el.querySelectorAll('[data-undo]').forEach(b => b.onclick = async () => {
    const n = b.dataset.undo; let r;
    const mPort = n.match(/Block (TCP|UDP) (\d+)|proto (tcp|udp) .* port (\d+)/i);
    const mIp = n.match(/Block IP (\S+)|(?:to|from) (\d[\d.:a-f]+)/i);
    if (mPort) r = await api('/api/port/unblock', { body: { proto: (mPort[1] || mPort[3]).toUpperCase(), port: +(mPort[2] || mPort[4]) } });
    else if (mIp) r = await api('/api/ip/unblock', { body: { ip: mIp[1] || mIp[2] } });
    if (r) { toast(r.ok ? 'Rule removed' : r.output, r.ok ? 'ok' : 'err'); renderSettings(); }
  });
  $('#reapply') && ($('#reapply').onclick = async () => { const r = await api('/api/pf/reapply', { body: {} }); toast(r.output, r.ok ? 'ok' : 'err'); });
  $('#export').onclick = async () => {
    const report = { generated: new Date().toISOString(), summary: S.summary, ports: S.ports, connections: S.conns, audit: S.audit, actions: log.actions, events: log.events };
    if (bridge) { (await bridge.saveFile(`sentinel-report-${Date.now()}.json`, JSON.stringify(report, null, 2))) && toast('Report saved', 'ok'); }
  };
}

// ------------------------------------------------------------------ live monitoring
async function pollAlerts() {
  try {
    const { alerts } = await api(`/api/alerts?since=${S.alertsSince}`);
    for (const a of alerts) {
      S.alertsSince = Math.max(S.alertsSince, a.ts);
      if (['malicious', 'unauthorised'].includes(a.verdict) || a.severity === 'high' || a.severity === 'critical') {
        bridge?.notify(`Sentinel: ${VERDICT[a.verdict][1]} connection`, `${a.title}\n${a.detail}`);
        toast(`⚠ ${VERDICT[a.verdict][1]}: ${a.title}`, 'err');
      }
    }
    if (alerts.length || S.view === 'network') {
      S.conns = await api('/api/connections');
      if (S.view === 'network') renderNetwork();
      if (alerts.length) { await refreshSummary(); if (S.view === 'dashboard') renderDashboard(); }
    }
  } catch (_) { /* engine busy */ }
}

// ------------------------------------------------------------------ start
(async function init() {
  if (bridge) {
    CFG = await bridge.config();
    bridge.onNavigate(v => go(v));
    bridge.onBackendDown(() => toast('Scanning engine stopped unexpectedly. Restart Sentinel.', 'err'));
  }
  $('#elevateBtn').onclick = async () => {
    if (!bridge) return;
    const r = await bridge.elevate();
    if (r.ok) { CFG.port = r.port; toast('Engine now running with administrator rights', 'ok'); fullScan(); }
    else toast(r.error, 'err');
  };
  render();
  await fullScan();
  setInterval(pollAlerts, 15000);
})();
