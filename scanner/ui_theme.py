"""Visual effects for the "SOC Network" cyber theme (design 5).

Colours and fonts live in .streamlit/config.toml. This module adds what the
theme config cannot: a live node-network background that links to the mouse
pointer, a custom glowing pointer, and glass-panel styling for keyed containers.
"""
import json

import streamlit as st

_CSS = """
/* Let the animated network show through the app's own background. */
/* The canvas sits at z-index -1, between the page background (on html) and
   the app. The app's own layout containers are left untouched. */
html { background: #071224; }
body, .stApp, [data-testid="stHeader"] { background: transparent !important; }

/* Custom pointer replaces the system one everywhere in the app. */
html, body, body * { cursor: none !important; }

/* Hero header */
.soc-hero { margin: 4px 0 18px; }
.soc-kicker { font-family: 'JetBrains Mono', monospace; font-size: 13px; letter-spacing: 3px;
              text-transform: uppercase; color: #38bdf8; }
.soc-title { font-family: 'Space Grotesk', sans-serif; font-size: 46px; font-weight: 700; line-height: 1.1;
             color: #f2f7ff; margin: 8px 0 6px; }
.soc-title span { color: #38bdf8; text-shadow: 0 0 22px rgba(56,189,248,.45); }
.soc-sub { color: #9fb3cf; font-size: 16px; }

/* Glass panels: containers created with key="panel_*" */
[class*="st-key-panel_"] { background: rgba(10,24,48,.78) !important; backdrop-filter: blur(6px);
    border: 1px solid #1d3a66 !important; border-radius: 14px !important;
    box-shadow: 0 0 0 1px rgba(56,189,248,.04), 0 18px 40px rgba(0,0,0,.35); }

/* Primary action glows */
.st-key-start_scan button { box-shadow: 0 0 22px rgba(56,189,248,.45); font-weight: 700; letter-spacing: 1px; }
.st-key-start_scan button:disabled { box-shadow: none; }

/* Severity metric cards */
[class*="st-key-sev_"] { background: rgba(5,13,27,.65) !important; border: 1px solid #1d3a66 !important;
    border-radius: 12px !important; padding: 10px 14px !important; }
.st-key-sev_Critical [data-testid="stMetricValue"] { color: #ff3b5c; }
.st-key-sev_High [data-testid="stMetricValue"] { color: #ff7a45; }
.st-key-sev_Medium [data-testid="stMetricValue"] { color: #ffc53d; }
.st-key-sev_Low [data-testid="stMetricValue"] { color: #40a9ff; }
.st-key-sev_Info [data-testid="stMetricValue"] { color: #a0aec0; }

.soc-status { display: flex; align-items: center; gap: 8px; font-size: 14px; color: #c9d8ee; }
.soc-dot { width: 9px; height: 9px; border-radius: 50%; }
"""

_JS = """
<script>
(() => {
  const doc = document;
  // Styles go into the document head from here: Streamlit's HTML sanitizer drops
  // style tags, and a style-only st.html lands in a container that reruns clear.
  // (Keep angle brackets out of this script: the sanitizer deletes any script
  // whose text looks like it contains tags.)
  if (!doc.getElementById('soc-theme-css')) {
    const st = doc.createElement('style');
    st.id = 'soc-theme-css';
    st.textContent = __CSS__;
    doc.head.appendChild(st);
  }
  if (window.__socFx) return;          // reruns re-send this element; start the effect only once
  window.__socFx = true;

  // ---- node network background
  const cv = doc.createElement('canvas');
  cv.style.cssText = 'position:fixed;inset:0;z-index:-1;pointer-events:none';
  doc.body.prepend(cv);
  const ctx = cv.getContext('2d');
  let W = 0, H = 0;
  const fit = () => { W = cv.width = innerWidth; H = cv.height = innerHeight; };
  fit(); addEventListener('resize', fit);
  const mouse = { x: innerWidth / 2, y: innerHeight / 2 };
  const nodes = Array.from({ length: 85 }, () => ({ x: Math.random() * W, y: Math.random() * H,
                                                   vx: (Math.random() - .5) * .45, vy: (Math.random() - .5) * .45 }));

  // ---- custom pointer: dot + easing ring
  const dot = doc.createElement('div'), ring = doc.createElement('div');
  dot.style.cssText = 'position:fixed;left:0;top:0;width:8px;height:8px;border-radius:50%;background:#38bdf8;' +
    'box-shadow:0 0 10px #38bdf8;pointer-events:none;z-index:2147483647;transform:translate(-50%,-50%)';
  ring.style.cssText = 'position:fixed;left:0;top:0;width:30px;height:30px;border-radius:50%;' +
    'border:1px solid rgba(56,189,248,.7);pointer-events:none;z-index:2147483646;transform:translate(-50%,-50%);' +
    'transition:width .18s,height .18s,background .18s';
  doc.body.append(dot, ring);
  const rp = { ...mouse };
  addEventListener('mousemove', (e) => { mouse.x = e.clientX; mouse.y = e.clientY; });
  const HOT = 'button,a,input,textarea,label,[role="button"],[role="option"],[role="radio"],[role="checkbox"],[data-baseweb="select"],summary';
  doc.addEventListener('mouseover', (e) => {
    const hot = e.target.closest && e.target.closest(HOT);
    ring.style.width = ring.style.height = hot ? '46px' : '30px';
    ring.style.background = hot ? 'rgba(56,189,248,.10)' : 'transparent';
  });
  addEventListener('mousedown', () => { dot.style.scale = '0.6'; });
  addEventListener('mouseup', () => { dot.style.scale = '1'; });

  function frame() {
    ctx.clearRect(0, 0, W, H);
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > W) n.vx *= -1;
      if (n.y < 0 || n.y > H) n.vy *= -1;
      const d = Math.hypot(n.x - mouse.x, n.y - mouse.y);
      if (d < 170) {
        n.x += (mouse.x - n.x) * .004; n.y += (mouse.y - n.y) * .004;
        ctx.strokeStyle = `rgba(56,189,248,${(1 - d / 170) * .9})`;
        ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke();
      }
      ctx.fillStyle = 'rgba(125,211,252,.75)';
      ctx.beginPath(); ctx.arc(n.x, n.y, 1.8, 0, 6.283); ctx.fill();
    }
    for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j], d = Math.hypot(a.x - b.x, a.y - b.y);
      if (d < 110) { ctx.strokeStyle = `rgba(56,189,248,${.16 * (1 - d / 110)})`;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
    }
    dot.style.left = mouse.x + 'px'; dot.style.top = mouse.y + 'px';
    rp.x += (mouse.x - rp.x) * .2; rp.y += (mouse.y - rp.y) * .2;
    ring.style.left = rp.x + 'px'; ring.style.top = rp.y + 'px';
    requestAnimationFrame(frame);
  }
  frame();
})();
</script>
"""


def apply_theme():
    """Inject the theme's CSS and the background/pointer effects (one script element)."""
    st.html(_JS.replace("__CSS__", json.dumps(_CSS)), unsafe_allow_javascript=True)


def hero(title_html: str, subtitle: str):
    st.html(f'<div class="soc-hero"><div class="soc-kicker">Y23-HTE-PROJECT-150 · OWASP ZAP + custom checks</div>'
            f'<div class="soc-title">{title_html}</div><div class="soc-sub">{subtitle}</div></div>')


def status_dot(ok: bool):
    colour = "#34d399" if ok else "#fb7185"
    label = "ZAP engine connected" if ok else "ZAP engine not running"
    st.html(f'<div class="soc-status"><span class="soc-dot" style="background:{colour};'
            f'box-shadow:0 0 8px {colour}"></span>{label}</div>')
