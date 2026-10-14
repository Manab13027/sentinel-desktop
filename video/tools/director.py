"""Records the Sentinel tutorial: drives the real UI under Xvfb, captures the screen with ffmpeg and logs
when each narration line starts, so the voice clips can be laid onto the exact same timeline.

usage: python3 director.py <out_dir> [durations.json]
"""
import asyncio
import json
import os
import subprocess
import sys
import time

from playwright.async_api import async_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1]
DUR_FILE = sys.argv[2] if len(sys.argv) > 2 else None
os.makedirs(OUT, exist_ok=True)
LINES = json.load(open(os.path.join(HERE, "narration.json")))
URL = "file:///home/claude/sentinel-desktop/renderer/index.html?port=8781&token=demo&platform=win32"
SCALE = 1.35
GAP = 0.45            # silence between lines
PART_GAP = 0.9        # extra pause at chapter changes

if DUR_FILE and os.path.exists(DUR_FILE):
    DUR = json.load(open(DUR_FILE))
else:  # estimate ~2.6 words/s until real voice clips exist
    DUR = {l["id"]: round(len(l["text"].split()) / 2.6 + 0.3, 2) for l in LINES}

page = None


async def ev(js, arg=None):
    return await page.evaluate(js, arg)


async def w(s):
    await asyncio.sleep(s)


async def center(sel, nth=0):
    b = await page.locator(sel).nth(nth).bounding_box()
    return b["x"] + b["width"] / 2, b["y"] + b["height"] / 2


async def move(sel, nth=0, ms=850, dx=0, dy=0):
    x, y = await center(sel, nth)
    x += dx; y += dy
    await ev("([x,y,ms]) => __ov.move(x-4, y-3, ms)", [x, y, ms])
    await page.mouse.move(x, y, steps=8)
    await w(ms / 1000 + 0.08)
    return x, y


async def click(sel, nth=0, ms=850, dx=0, dy=0):
    x, y = await move(sel, nth, ms, dx, dy)
    await ev("() => __ov.ripple()")
    await page.mouse.click(x, y)
    await w(0.25)


async def co(cid, sel, label, side="top", pad=6):
    ok = await ev("([i,s,l,sd,p]) => __ov.callout(i, s, l, sd, p)", [cid, sel, label, side, pad])
    if not ok:
        print("callout target missing:", sel, file=sys.stderr)


async def clear(cid=None):
    await ev("(i) => __ov.clear(i)", cid)


async def chapter(n, title, hold=3.4):
    await ev("([n,t]) => __ov.chapter(n,t)", [n, title])
    asyncio.get_event_loop().call_later(hold, lambda: asyncio.ensure_future(ev("() => __ov.chapterOff()")))


async def scroll(view, top):
    await ev("([v,t]) => document.querySelector(v).scrollTo({top:t, behavior:'smooth'})", [view, top])
    await w(0.9)


async def scroll_into(sel, block="center"):
    await ev("([s,b]) => document.querySelector(s).scrollIntoView({behavior:'smooth', block:b})", [sel, block])
    await w(0.9)


# ------------------------------------------------------------------------- scenes
async def l01(d):
    await ev("""() => { __ov.dim(true); __ov.card(`${__ov.logo}<div class="ov-title">SENTINEL</div>
      <div class="ov-sub">Offline AI security for Windows &amp; macOS</div>
      <div class="ov-chips"><span class="ov-chip">OPEN PORTS</span><span class="ov-chip">ROGUE CONNECTIONS</span><span class="ov-chip">ONE-CLICK PATCHING</span></div>`);
      __ov.fadeIn(1400); }""")


async def l02(d):
    for i, frac in enumerate((0.22, 0.48, 0.74)):
        await w(d * (frac - (0 if i == 0 else (0.22, 0.48, 0.74)[i - 1])))
        await ev(f"() => {{ const c=document.querySelectorAll('.ov-chip')[{i}]; c.style.opacity=1; c.style.transform='none'; }}")
    await w(d * 0.26 - 0.2)
    await ev("() => { __ov.cardOff(); __ov.dim(false); }")


async def l03(d):
    await chapter(1, "The dashboard")
    await w(0.6)
    await click("#scanBtn")
    await co("scan", "#scanBtn", "One scan · everything", "bottom")
    await w(d - 2.2)
    await clear("scan")


async def l04(d):
    await co("a", ".dash-row.r1 > .cell:nth-child(1)", "Ranked by risk", "inside", 0)
    await move(".dash-row.r1 > .cell:nth-child(1) tbody tr", 0, 900, dx=40)
    await w(d - 1.4)
    await clear("a")


async def l05(d):
    await co("b", ".dash-row.r1 > .cell:nth-child(2) svg", "Security score", "bottom", 10)
    await move(".dash-row.r1 > .cell:nth-child(2) svg", 0, 800)
    await w(d * 0.5)
    await co("b2", ".dash-row.r1 > .cell:nth-child(2) .legend li:first-child", "4 critical", "right", 4)
    await w(d * 0.5 - 1.0)
    await clear("b"); await clear("b2")


async def l06(d):
    await co("c", ".dash-row.r1 > .cell:nth-child(3) .board", "Open issues by severity", "top", 8)
    await move(".dash-row.r1 > .cell:nth-child(3) .board", 0, 800)
    await w(d * 0.55)
    await co("c2", ".dash-row.r1 > .cell:nth-child(3) .headline .muted", "Exploited in the wild", "bottom", 4)
    await w(d * 0.45 - 1.0)
    await clear("c"); await clear("c2")


async def l07(d):
    await scroll("#view-dashboard", 380)
    seg = (d - 1.2) / 3
    for i, lab in enumerate(["Exposure", "Recommendations", "Every connection"]):
        sel = f".dash-row.r2 > .cell:nth-child({[1, 2, 3][i]})"
        await co(f"r{i}", sel, lab, "inside", 0)
        await move(sel + " svg", 0, 600)
        await w(seg - 0.7)
        await clear(f"r{i}")


async def l08(d):
    await chapter(2, "Open ports")
    await click(".rail button[data-view=ports]")
    await w(0.6)
    await co("p", "#view-ports thead", "Port · service · program · PID · user", "bottom", 4)
    await w(d * 0.45)
    await clear("p")
    await co("p2", "#view-ports tbody tr.row:first-child td:nth-child(3)", "The exact program", "right", 4)
    await w(d * 0.55 - 2.2)
    await clear("p2")


async def l09(d):
    await click("#view-ports tbody tr.row:first-child td:nth-child(2)")
    await w(0.5)
    await co("ai", "#view-ports tr.detail td > div > div:first-child", "AI assessment", "top", 6)
    await w(d - 1.6)
    await clear("ai")


async def l10(d):
    await co("x1", "#view-ports tbody tr.row:first-child td:nth-child(1)", "Metasploit default", "top", 4)
    await w(d * 0.4)
    await co("x2", "#view-ports tbody tr.row:first-child td:nth-child(3) .mono", "Temp folder", "bottom", 4)
    await move("#view-ports tbody tr.row:first-child td:nth-child(3) .mono", 0, 700)
    await w(d * 0.6 - 0.8)
    await clear("x1"); await clear("x2")


async def l11(d):
    await click("#view-ports tbody tr.row:first-child [data-close]")
    await w(0.6)
    await co("m", "#modalBody .opts", "Block · or stop the program", "top", 6)
    await move("#modalBody .opt:nth-child(1)", 0, 700)
    await w(d - 2.6)
    await clear("m")


async def l12(d):
    await click("#modalBody [data-m=yes]")
    await ev("() => __ov.tip('uac','Windows · User Account Control','Allow Sentinel to make changes? → Yes', innerWidth-470, 90)")
    await w(min(2.2, d * 0.5))
    await clear("uac")
    await w(max(0.2, d - 3.6))


async def l13(d):
    await co("lk", "#view-ports tr.row:has([data-unblock])", "Blocked", "top", 4)
    await move("#view-ports [data-unblock]", 0, 800)
    await co("ub", "#view-ports [data-unblock]", "Undo", "left", 4)
    await w(d - 1.2)
    await clear("lk"); await clear("ub")


async def l14(d):
    await chapter(3, "Network monitor")
    await click(".rail button[data-view=network]")
    await w(0.5)
    await co("k", "#view-network .kpis", "Live · every 15 seconds", "bottom", 6)
    await w(d - 1.8)
    await clear("k")


async def l15(d):
    sel = "#view-network tbody tr:nth-child(1)"
    await co("n1", sel, "Crypto-mining pool", "top", 4)
    await move(sel + " td:nth-child(3)", 0, 800)
    await w(d - 1.2)
    await clear("n1")


async def l16(d):
    sel = "#view-network tbody tr:nth-child(2)"
    await co("n2", sel, "Raw IP · remote-access port", "top", 4)
    await move(sel + " td:nth-child(4)", 0, 800)
    await w(d - 1.2)
    await clear("n2")


async def l17(d):
    sel = "#view-network tbody tr:nth-child(4)"
    await co("n4", sel, "New destination · anomaly", "bottom", 4)
    await move(sel + " td:nth-child(1)", 0, 700)
    await ev("""() => __ov.inset('layers','How Sentinel decides',
      ['Threat-intel lists (offline)','Your allow / block policy','Learned baseline per app','Behaviour heuristics'], innerWidth-430, innerHeight-330, 380)""")
    await w(d - 1.0)
    await clear("n4"); await clear("layers")


async def l18(d):
    await click("#mode button[data-k=allowlist]")
    await w(0.7)
    await co("al", "#mode", "Allowlist mode", "bottom", 4)
    await w(d - 2.0)
    await clear("al")


async def l19(d):
    await click("#mode button[data-k=monitor]", ms=600)
    await w(0.8)
    await click("#view-network tbody tr:nth-child(1) [data-block]")
    await w(0.5)
    await click("#modalBody .opt:nth-child(2)", ms=600)
    await click("#modalBody [data-m=yes]", ms=600)
    await w(1.8)
    await ev("""() => { const r=[...document.querySelectorAll('#view-network tbody tr')].find(t=>t.textContent.includes('update.exe')); if(r) r.id='blocked-row'; }""")
    await co("bl", "#blocked-row", "Blocked + stopped", "top", 4)
    await move("#blocked-row td:nth-child(1)", 0, 700)
    await w(max(0.2, d - 7.0))
    await clear("bl")


async def l20(d):
    await chapter(4, "Vulnerabilities & patches")
    await click(".rail button[data-view=vulns]")
    await w(0.5)
    await co("vk", "#view-vulns .kpis", "OS audit + known-exploit database", "bottom", 6)
    await w(d - 1.8)
    await clear("vk")


async def l21(d):
    await scroll_into("[id^='f-cve-chrome']")
    await co("ex", "[id^='f-cve-chrome'] .chip", "Exploited in the wild", "top", 4)
    await move("[id^='f-cve-chrome'] .ft", 0, 800)
    await w(d - 2.0)
    await clear("ex")


async def l22(d):
    await scroll("#view-vulns", 0)
    await click("#f-win-firewall [data-fix]")
    await w(1.0)
    await co("pb", ".fixbox ol", "Manual steps", "right", 4)
    await w(d * 0.4)
    await co("pc", ".fixbox pre", "Exact commands", "right", 4)
    await w(d * 0.6 - 2.4)
    await clear("pb"); await clear("pc")


async def l23(d):
    await click(".fixbox [data-apply]")
    await w(0.6)
    await click("#modalBody [data-m=yes]", ms=600)
    await co("ap", ".fixbox [data-apply]", "Applying · then re-checking", "right", 4)
    await w(4.6)
    await clear("ap")
    await co("ok", ".fixbox [data-out]", "Fixed and verified", "top", 4)
    await w(max(0.3, d - 7.6))
    await clear("ok")


async def l24(d):
    await w(0.6)
    await click("#deep")
    await w(1.2)
    await ev("""() => { const h=[...document.querySelectorAll('#view-vulns .cat-head')].find(e=>e.textContent.startsWith('Missing patches'));
                        h.id='mp-head'; h.scrollIntoView({behavior:'smooth', block:'start'}); }""")
    await w(1.0)
    await co("mp", "#mp-head", "Missing Windows updates", "right", 4)
    await w(max(0.3, d - 4.0))
    await clear("mp")


async def l25(d):
    await chapter(5, "AI advisor")
    await click(".rail button[data-view=advisor]")
    await w(0.4)
    await click("#askq", ms=600)
    await page.keyboard.type("What should I fix first?", delay=55)
    await w(0.3)
    await page.keyboard.press("Enter")
    await w(max(0.3, d - 3.8))


async def l26(d):
    await co("ans", "#view-advisor .msg.bot:last-child", "Built-in engine · no cloud", "top", 4)
    await w(d - 0.4)
    await clear("ans")


async def l27(d):
    sel = "#view-advisor .adv-grid > div:nth-child(2) > .panel:nth-child(2)"
    await co("pl", sel, "Impact ÷ effort", "left", 4)
    await move(sel + " .plan li:first-child", 0, 800)
    await w(d - 1.2)
    await clear("pl")


async def l28(d):
    await click("#view-advisor [data-plan-refresh]")
    await co("rf", "#view-advisor [data-plan-refresh]", "Refresh", "left", 4)
    await w(d - 1.4)
    await clear("rf")


async def l29(d):
    sel = "#view-advisor .adv-grid > div:nth-child(2) > .panel:nth-child(1)"
    await co("ol", sel, "Optional: local LLM", "left", 4)
    await move(sel + " .chip", 0, 800)
    await w(d - 1.2)
    await clear("ol")


async def l30(d):
    await chapter(6, "Settings")
    await click(".rail button[data-view=settings]")
    await w(0.7)
    await co("np", "#view-settings .page > .panel:nth-child(1)", "Allow / block lists", "inside", 2)
    await w(d * 0.45)
    await clear("np")
    await co("ti", "#view-settings .page > div > .panel:nth-child(1)", "Threat feeds", "left", 4)
    await move("#impIntel", 0, 800)
    await w(d * 0.55 - 2.4)
    await clear("ti")


async def l31(d):
    await co("fw", "#view-settings .page > div > .panel:nth-child(3)", "Undo any rule", "left", 4)
    await move("#view-settings [data-undo]", 0, 800)
    await w(d * 0.55)
    await clear("fw")
    await scroll_into("#view-settings .page > .panel:last-child", "end")
    await co("lg", "#view-settings .page > .panel:last-child", "Activity log", "top", 4)
    await w(d * 0.45 - 2.0)
    await clear("lg")


async def l32(d):
    await click(".rail button[data-view=dashboard]", ms=700)
    await w(0.6)
    await ev("""() => { __ov.dim(true); __ov.card(`${__ov.logo}<div class="ov-title">SENTINEL</div>
      <div class="ov-sub">Your ports, your network and your patches. One place. Fully offline.</div>`); }""")
    await w(max(0.3, d - 1.5))


async def l33(d):
    await ev("""() => { __ov.card(`${__ov.logo}<div class="ov-title" style="font-size:54px">ENJOYED THE VIDEO?</div>
      <div class="ov-cta">
        <div class="ov-btn like"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 10v11H3V10z"/><path d="M7 10l4-8a3 3 0 0 1 3 3v4h6a2 2 0 0 1 2 2.3l-1.4 8A2 2 0 0 1 18.6 21H7"/></svg>LIKE</div>
        <div class="ov-btn sub" id="ov-sub"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg><span>SUBSCRIBE</span></div>
        <div class="ov-btn share"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/></svg>SHARE</div>
      </div>`); }""")
    await w(0.5)
    words = [(0.30, 0), (0.45, 1), (0.58, 2)]  # 'like', 'subscribe', 'share' land around these fractions
    t = 0.5
    for frac, i in words:
        await w(max(0.05, d * frac - t)); t = d * frac
        await ev(f"() => {{ const b=document.querySelectorAll('.ov-btn')[{i}]; b.style.opacity=1; b.style.transform='scale(1)'; }}")
    await click("#ov-sub", ms=700)
    await ev("""() => { const s=document.getElementById('ov-sub'); s.style.background='#3a404b'; s.querySelector('span').textContent='SUBSCRIBED ✓'; }""")
    await w(max(0.2, d - t - 1.2))


async def l34(d):
    await ev("""() => { const c=document.querySelector('#ov-card .wrap'); const m=document.createElement('div'); m.className='ov-msg';
      m.innerHTML=`<svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="#e8b04a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
        <span>Want a copy of Sentinel? <b>Message me on YouTube</b></span>`;
      c.appendChild(document.createElement('br')); c.appendChild(m); requestAnimationFrame(()=>requestAnimationFrame(()=>{m.style.opacity=1;m.style.transform='none';})); }""")
    await ev("() => __ov.move(innerWidth+40, innerHeight*0.7, 1400)")
    await w(d)
    await ev("() => __ov.fadeOut(1600)")
    await w(2.0)


SCENES = {k: v for k, v in globals().items() if k.startswith("l") and k[1:].isdigit()}


async def main():
    global page
    env = dict(os.environ, DISPLAY=":99")
    xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1920x1080x24", "-nolisten", "tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        await record(env)
    finally:
        xvfb.terminate()


async def record(env):
    global page
    time.sleep(1.5)
    async with async_playwright() as p:
        import shutil
        shutil.rmtree("/tmp/claude-0/chrome-profile", ignore_errors=True)
        # --app + --kiosk gives a chrome-less window; window size is in DIPs (1920x1080 px / 1.35)
        ctx = await p.chromium.launch_persistent_context(
            "/tmp/claude-0/chrome-profile", executable_path="/opt/pw-browsers/chromium", headless=False, env=env,
            no_viewport=True, bypass_csp=True, ignore_default_args=["--enable-automation"],
            args=[f"--app={URL}", "--kiosk", "--window-position=0,0", f"--window-size={round(1920 / SCALE)},{round(1080 / SCALE)}",
                  f"--force-device-scale-factor={SCALE}", "--disable-infobars", "--no-first-run", "--disable-features=Translate"])
        browser = ctx
        await w(2.0)
        page = ctx.pages[0]
        await page.wait_for_load_state()
        await page.evaluate(open(os.path.join(HERE, "overlay.js")).read())
        await page.wait_for_selector("#view-dashboard .dash-row.r3", timeout=60000)
        await ev("() => { S.alertsSince = 1e12; }")  # no stray alert toasts during the take
        await w(2.0)

        ff = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "x11grab", "-video_size", "1920x1080", "-framerate", "25",
                               "-draw_mouse", "0", "-i", ":99.0", "-c:v", "libx264", "-preset", "ultrafast", "-crf", "14",
                               "-pix_fmt", "yuv420p", os.path.join(OUT, "raw.mp4")], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, env=env)
        await w(2.0)
        # sync flash: one white beat, then black; video time of the flash is detected afterwards
        await ev("() => { const f=document.getElementById('ov-fade'); f.style.transition='none'; f.style.background='#fff'; }")
        t_flash = time.monotonic()
        await w(0.2)
        await ev("() => { document.getElementById('ov-fade').style.background='#000'; }")
        await w(1.3)

        t0 = time.monotonic()
        marks = {}
        prev_part = None
        for line in LINES:
            lid = line["id"]
            if prev_part and line["part"] != prev_part:
                await w(PART_GAP)
            prev_part = line["part"]
            start = time.monotonic() - t0
            marks[lid] = round(start, 3)
            d = DUR[lid]
            await SCENES[lid](d)
            rest = start + d + GAP - (time.monotonic() - t0)
            if rest > 0:
                await w(rest)
            else:
                print(f"{lid}: action overran narration by {-rest:.2f}s", file=sys.stderr)
        end = time.monotonic() - t0
        await w(0.5)
        ff.communicate(b"q", timeout=60)
        json.dump({"flash_to_t0": round(t0 - t_flash, 3), "marks": marks, "end": round(end, 3), "durations": DUR},
                  open(os.path.join(OUT, "timeline.json"), "w"), indent=1)
        await browser.close()


asyncio.run(main())
