// Video overlay layer (cursor, amber callouts, chapter cards, insets, end card) - styled after the
// Structure Studio tutorial: dark UI, amber (#e8b04a) labels, mono captions, PART cards bottom-left.
(() => {
  if (window.__ov) return;
  const AMBER = '#e8b04a';
  const css = `
  #ov-root{position:fixed;inset:0;pointer-events:none;z-index:2147483000;font-family:Inter,-apple-system,Segoe UI,sans-serif}
  #ov-fade{position:fixed;inset:0;background:#000;opacity:1;transition:opacity 1.2s ease;z-index:2147483600}
  #ov-dim{position:fixed;inset:0;background:rgba(5,6,8,.72);opacity:0;transition:opacity .8s ease;z-index:2147483100}
  #ov-cursor{position:fixed;left:0;top:0;width:26px;height:26px;z-index:2147483500;will-change:transform;
    transition:transform .9s cubic-bezier(.45,.05,.25,1);filter:drop-shadow(0 2px 3px rgba(0,0,0,.55))}
  .ov-ripple{position:fixed;width:14px;height:14px;margin:-7px 0 0 -7px;border:2px solid ${AMBER};border-radius:50%;
    z-index:2147483400;animation:ovr .55s ease-out forwards}
  @keyframes ovr{from{transform:scale(.4);opacity:1}to{transform:scale(3.2);opacity:0}}
  .ov-box{position:fixed;border:2px solid ${AMBER};border-radius:5px;box-shadow:0 0 0 4px rgba(232,176,74,.16),0 0 24px rgba(232,176,74,.25);
    opacity:0;transition:opacity .3s ease, transform .3s ease;transform:scale(1.02);z-index:2147483200}
  .ov-label{position:fixed;background:${AMBER};color:#14110a;font-weight:800;font-size:17px;letter-spacing:.9px;
    text-transform:uppercase;padding:7px 13px;border-radius:3px;white-space:nowrap;box-shadow:0 6px 18px rgba(0,0,0,.45);
    opacity:0;transform:translateY(6px);transition:opacity .3s ease,transform .3s ease;z-index:2147483300}
  .ov-show{opacity:1 !important;transform:none !important}
  #ov-chapter{position:fixed;left:30px;bottom:92px;display:flex;align-items:stretch;gap:0;opacity:0;transform:translateX(-16px);
    transition:opacity .45s ease,transform .45s ease;z-index:2147483300}
  #ov-chapter .bar{width:5px;background:${AMBER};border-radius:2px}
  #ov-chapter .in{background:rgba(10,12,15,.94);border:1px solid #2a2f37;border-left:0;padding:10px 18px 11px 14px}
  #ov-chapter .p{color:${AMBER};font:600 12px/1 ui-monospace,Menlo,Consolas,monospace;letter-spacing:2px}
  #ov-chapter .t{color:#fff;font-weight:800;font-size:24px;letter-spacing:1px;margin-top:6px;text-transform:uppercase}
  .ov-tip{position:fixed;background:rgba(14,16,20,.96);border:1px solid #3a3f48;border-radius:4px;padding:7px 11px;max-width:420px;
    opacity:0;transform:translateY(4px);transition:opacity .25s ease,transform .25s ease;z-index:2147483300}
  .ov-tip .k{color:${AMBER};font:700 11px/1.2 ui-monospace,Menlo,monospace;letter-spacing:1.6px;text-transform:uppercase}
  .ov-tip .v{color:#e9ebef;font:500 15px/1.35 ui-monospace,Menlo,Consolas,monospace;margin-top:3px}
  .ov-inset{position:fixed;background:rgba(10,12,15,.97);border:1px solid #2d323b;border-left:4px solid ${AMBER};border-radius:4px;
    padding:16px 20px;color:#e9ebef;opacity:0;transform:translateY(8px);transition:opacity .35s ease,transform .35s ease;z-index:2147483300;
    box-shadow:0 16px 40px rgba(0,0,0,.55)}
  .ov-inset h4{margin:0 0 10px;color:${AMBER};font:700 12px/1 ui-monospace,Menlo,monospace;letter-spacing:2px;text-transform:uppercase}
  .ov-inset .row{display:flex;gap:10px;align-items:center;font-size:16px;margin:8px 0}
  .ov-inset .n{width:22px;height:22px;border-radius:50%;background:${AMBER};color:#14110a;font-weight:800;font-size:12px;display:grid;place-items:center}
  #ov-card{position:fixed;inset:0;display:grid;place-items:center;z-index:2147483250;opacity:0;transition:opacity .7s ease}
  #ov-card .wrap{text-align:center}
  .ov-logo{width:92px;height:92px;border-radius:22px;background:#fff;color:#0d0f12;display:inline-grid;place-items:center;box-shadow:0 20px 60px rgba(57,135,229,.25)}
  .ov-title{color:#fff;font-weight:800;font-size:76px;letter-spacing:6px;margin-top:22px}
  .ov-sub{color:#b8bcc5;font-size:24px;margin-top:8px;letter-spacing:.4px}
  .ov-chips{display:flex;gap:14px;justify-content:center;margin-top:34px}
  .ov-chip{border:1.5px solid ${AMBER};color:${AMBER};font:700 15px/1 ui-monospace,Menlo,monospace;letter-spacing:2px;padding:11px 16px;border-radius:4px;
    opacity:0;transform:translateY(10px);transition:all .4s ease}
  .ov-cta{display:flex;gap:26px;justify-content:center;margin-top:44px}
  .ov-btn{display:flex;align-items:center;gap:12px;padding:16px 26px;border-radius:999px;font-weight:800;font-size:24px;letter-spacing:1px;
    opacity:0;transform:scale(.7);transition:opacity .35s ease,transform .45s cubic-bezier(.3,1.6,.5,1)}
  .ov-btn svg{width:30px;height:30px}
  .ov-btn.like{background:#1c2430;color:#fff;border:1.5px solid #3a4352}
  .ov-btn.sub{background:#d63a3a;color:#fff}
  .ov-btn.share{background:#1c2430;color:#fff;border:1.5px solid #3a4352}
  .ov-msg{margin-top:46px;display:inline-flex;align-items:center;gap:16px;background:rgba(232,176,74,.1);border:1.5px solid ${AMBER};
    border-radius:10px;padding:18px 28px;color:#fff;font-size:26px;opacity:0;transform:translateY(12px);transition:all .5s ease}
  .ov-msg b{color:${AMBER}}
  `;
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
  const root = document.createElement('div'); root.id = 'ov-root'; document.body.appendChild(root);
  const fade = document.createElement('div'); fade.id = 'ov-fade'; root.appendChild(fade);
  const dim = document.createElement('div'); dim.id = 'ov-dim'; root.appendChild(dim);
  const cur = document.createElement('div'); cur.id = 'ov-cursor';
  cur.innerHTML = `<svg viewBox="0 0 24 24" width="26" height="26"><path d="M4 2.5v17.2l4.6-4.3 2.9 6.6 2.9-1.3-2.9-6.5h6.3z" fill="#111" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>`;
  root.appendChild(cur);
  let cx = innerWidth * 0.62, cy = innerHeight * 0.55;
  cur.style.transform = `translate(${cx}px,${cy}px)`;

  const reg = {};
  const rectOf = t => {
    if (Array.isArray(t)) return { left: t[0], top: t[1], width: t[2], height: t[3] };
    const el = typeof t === 'string' ? document.querySelector(t) : t;
    if (!el) return null;
    return el.getBoundingClientRect();
  };
  const show = el => requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add('ov-show')));

  window.__ov = {
    fadeIn(ms = 1200) { fade.style.transition = `opacity ${ms}ms ease`; fade.style.opacity = 0; },
    fadeOut(ms = 1200) { fade.style.transition = `opacity ${ms}ms ease`; fade.style.opacity = 1; },
    dim(on) { dim.style.opacity = on ? 1 : 0; },
    move(x, y, ms = 900) {
      cur.style.transition = `transform ${ms}ms cubic-bezier(.45,.05,.25,1)`;
      cur.style.transform = `translate(${x}px,${y}px)`; cx = x; cy = y;
    },
    ripple() {
      const r = document.createElement('div'); r.className = 'ov-ripple';
      r.style.left = (cx + 4) + 'px'; r.style.top = (cy + 3) + 'px'; root.appendChild(r);
      setTimeout(() => r.remove(), 700);
      cur.animate([{ transform: `translate(${cx}px,${cy}px) scale(1)` }, { transform: `translate(${cx}px,${cy}px) scale(.82)` },
                   { transform: `translate(${cx}px,${cy}px) scale(1)` }], { duration: 220 });
    },
    callout(id, target, label, side = 'top', pad = 6) {
      this.clear(id, true);
      const r = rectOf(target); if (!r) return false;
      const box = document.createElement('div'); box.className = 'ov-box';
      Object.assign(box.style, { left: (r.left - pad) + 'px', top: (r.top - pad) + 'px', width: (r.width + pad * 2) + 'px', height: (r.height + pad * 2) + 'px' });
      root.appendChild(box);
      const els = [box];
      if (label) {
        const lb = document.createElement('div'); lb.className = 'ov-label'; lb.textContent = label; root.appendChild(lb);
        const w = lb.offsetWidth, h = lb.offsetHeight;
        let x = r.left - pad, y = r.top - pad - h - 8;
        if (side === 'bottom') y = r.bottom + pad + 8;
        if (side === 'right') { x = r.right + pad + 10; y = r.top + r.height / 2 - h / 2; }
        if (side === 'left') { x = r.left - pad - w - 10; y = r.top + r.height / 2 - h / 2; }
        if (side === 'top-right') { x = r.right + pad - w; }
        if (side === 'inside') { x = r.left + 10; y = r.top + 10; }
        x = Math.max(8, Math.min(innerWidth - w - 8, x)); y = Math.max(8, Math.min(innerHeight - h - 8, y));
        lb.style.left = x + 'px'; lb.style.top = y + 'px';
        els.push(lb);
      }
      els.forEach(show); reg[id] = els; return true;
    },
    clear(id, now) {
      const ids = id ? [id] : Object.keys(reg);
      ids.forEach(k => (reg[k] || []).forEach(e => { if (now) e.remove(); else { e.classList.remove('ov-show'); setTimeout(() => e.remove(), 350); } }));
      ids.forEach(k => delete reg[k]);
    },
    tip(id, key, val, x, y) {
      this.clear(id, true);
      const t = document.createElement('div'); t.className = 'ov-tip';
      t.innerHTML = `<div class="k">${key}</div><div class="v">${val}</div>`;
      Object.assign(t.style, { left: x + 'px', top: y + 'px' }); root.appendChild(t); show(t); reg[id] = [t];
    },
    inset(id, title, rows, x, y, w = 360) {
      this.clear(id, true);
      const t = document.createElement('div'); t.className = 'ov-inset';
      t.innerHTML = `<h4>${title}</h4>` + rows.map((r, i) => `<div class="row"><span class="n">${i + 1}</span><span>${r}</span></div>`).join('');
      Object.assign(t.style, { left: x + 'px', top: y + 'px', width: w + 'px' }); root.appendChild(t); show(t); reg[id] = [t];
    },
    chapter(n, title) {
      let c = document.getElementById('ov-chapter');
      if (!c) { c = document.createElement('div'); c.id = 'ov-chapter'; root.appendChild(c); }
      c.innerHTML = `<div class="bar"></div><div class="in"><div class="p">PART ${n}</div><div class="t">${title}</div></div>`;
      c.classList.remove('ov-show'); show(c);
    },
    chapterOff() { const c = document.getElementById('ov-chapter'); if (c) c.classList.remove('ov-show'); },
    card(html) {
      let c = document.getElementById('ov-card');
      if (!c) { c = document.createElement('div'); c.id = 'ov-card'; root.appendChild(c); }
      c.innerHTML = `<div class="wrap">${html}</div>`; requestAnimationFrame(() => requestAnimationFrame(() => c.style.opacity = 1));
    },
    cardOff() { const c = document.getElementById('ov-card'); if (c) c.style.opacity = 0; },
    reveal(sel) { document.querySelectorAll(sel).forEach(e => { e.style.opacity = 1; e.style.transform = 'none'; }); },
    logo: `<div class="ov-logo"><svg viewBox="0 0 24 24" width="54" height="54"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></div>`,
  };
})();
