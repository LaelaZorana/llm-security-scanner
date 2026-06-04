"""
viewer.py — a minimal, offline FastAPI app that turns the scanner into a
one-command browser demo.

It runs a scan once at startup (default: the offline ``stub`` target, no API key
required), then serves:

    GET /                  on-brand landing page with the headline result
    GET /report            the full, self-contained report.html
    GET /report.json       machine-readable findings
    GET /model_card.md     NIST AI RMF / ISO 42001 governance narrative
    GET /risk_register.csv GRC-ready risk register
    GET /healthz           liveness probe

Design goals: lean (FastAPI + the scanner's existing deps only), offline-first,
and fully testable via ``starlette.testclient.TestClient`` without binding a
server. Run it with:

    uvicorn llm_security_scanner.viewer:app --reload
    # or:  llm-scan serve

The landing page shares the report's identity — a dark-first enterprise security
console (near-black slate, a cyan→emerald scanner-signal accent, monospace data,
a severity colour system and a bento severity dashboard) — so the demo and the
report read as one product.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Dict

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from . import __version__
from .engine import Scanner
from .governance import render_model_card, render_risk_register
from .models import ScanResult
from .providers import get_provider
from .reporting import render_html_report, summary_table

# The target the demo scans. Defaults to the offline stub so the viewer needs no
# API key; override with LLM_SCAN_VIEWER_TARGET to point at a real provider.
_TARGET = os.environ.get("LLM_SCAN_VIEWER_TARGET", "stub")


@lru_cache(maxsize=1)
def get_scan_result() -> ScanResult:
    """Run the scan once and memoize it for the life of the process.

    Cached so every request renders from a single, consistent result (and the
    landing page, report and downloads never disagree).
    """
    provider = get_provider(_TARGET)
    return Scanner(provider, scanner_version=__version__).run()


# --------------------------------------------------------------------------- #
# Landing page
# --------------------------------------------------------------------------- #
_SEVERITY_HEX = {
    "CRITICAL": "#f43f5e",  # rose-500
    "HIGH": "#f97316",      # orange-500
    "MEDIUM": "#f59e0b",    # amber-500
    "LOW": "#eab308",       # yellow-500
}


def _result_gradient(result: ScanResult) -> str:
    """Build the CSS conic-gradient for the landing-page severity donut."""
    sc = result.severity_counts()
    total = result.total_findings
    if not total:
        return "conic-gradient(rgb(var(--border)) 0deg 360deg)"
    stops = []
    start = 0.0
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sc[name]
        if not count:
            continue
        end = start + count / total * 360.0
        stops.append(f"{_SEVERITY_HEX[name]} {start:.3f}deg {end:.3f}deg")
        start = end
    return f"conic-gradient({', '.join(stops)})"


def _landing_html(result: ScanResult) -> str:
    sc = result.severity_counts()
    hs = result.highest_severity()
    pass_pct = round(result.pass_rate * 100)
    n_categories = len({o.probe.category for o in result.outcomes})
    result_gradient = _result_gradient(result)

    # Severity accent + verdict driven by the worst finding. Dark-on-light text
    # for the amber/yellow flags, white for the red/orange ones.
    accent = _SEVERITY_HEX.get(hs.name, "#34d399") if hs else "#34d399"
    if hs and hs.value >= 4:
        verdict, verdict_bg, verdict_ink = "Release-blocking", "#f43f5e", "#fff"
    elif hs and hs.value >= 3:
        verdict, verdict_bg, verdict_ink = "Needs remediation", "#f97316", "#fff"
    else:
        verdict, verdict_bg, verdict_ink = "No blockers", "#34d399", "#08121a"

    # Headline icon: a warning triangle when there is high+ exposure, else a tick.
    if hs and hs.value >= 3:
        headline_icon = (
            "<svg width='23' height='23' viewBox='0 0 24 24' fill='none' "
            "stroke='currentColor' stroke-width='2' stroke-linecap='round' "
            "stroke-linejoin='round'><path d='M10.29 3.86 1.82 18a2 2 0 0 0 1.71 "
            "3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z'/>"
            "<line x1='12' y1='9' x2='12' y2='13'/>"
            "<line x1='12' y1='17' x2='12.01' y2='17'/></svg>"
        )
    else:
        headline_icon = (
            "<svg width='23' height='23' viewBox='0 0 24 24' fill='none' "
            "stroke='currentColor' stroke-width='2' stroke-linecap='round' "
            "stroke-linejoin='round'><path d='M22 11.08V12a10 10 0 1 1-5.93-9.14'/>"
            "<polyline points='22 4 12 14.01 9 11.01'/></svg>"
        )

    donut_empty = "<div class='donut-empty'></div>" if result.total_findings == 0 else ""

    # Severity stat tiles (bento) + distribution bars share the same numbers.
    total = result.total_findings or 1
    tiles = ""
    bars = ""
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sc[name]
        pct = round(count / total * 100) if result.total_findings else 0
        color = _SEVERITY_HEX[name]
        zero = "" if count else " zero"
        num_cls = " hit" if count else ""
        tiles += (
            f'<div class="tile{zero}" style="--t:{color}">'
            f'<div class="tlabel"><span class="tdot"></span>{name.title()}</div>'
            f'<div class="tnum{num_cls}">{count}</div>'
            f'<div class="tbar"><span style="width:{pct}%"></span></div></div>'
        )
        bars += (
            f'<div class="bar-row"><span class="bname">'
            f'<span class="sw" style="background:{color}"></span>{name.title()}</span>'
            f'<span class="track"><span style="width:{pct}%;background:{color}"></span></span>'
            f'<span class="bct">{count}</span></div>'
        )

    crit_clause = f" · <em>{sc['CRITICAL']}</em> Critical" if sc["CRITICAL"] else ""
    high_clause = f" · {sc['HIGH']} High" if sc["HIGH"] else ""
    plural = "" if result.total_findings == 1 else "s"
    headline_severity = hs.name.title() if hs else "None"
    findings_cls = "bad" if result.total_findings else "good"
    sev_cls = "bad" if hs else "good"

    return f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>LLM Security Console — live demo</title>
<meta name="description" content="One-command demo of the LLM Security Scanner: run an adversarial battery against an LLM and get an audit-ready governance package." />
<style>
  :root {{
    color-scheme:dark;
    --signal:45 212 191; --signal-2:56 189 248; --signal-ink:8 18 24;
    --bg:7 10 17; --bg-2:10 14 23; --grid:148 163 184;
    --panel:15 20 31; --panel-2:19 25 38; --panel-3:24 31 47;
    --ink:226 232 240; --ink-soft:148 163 184; --muted:100 116 139;
    --border:38 48 66; --border-2:51 65 85; --shadow:0 0 0; --pass:52 211 153;
  }}
  html:not(.dark) {{
    color-scheme:light;
    --signal:13 148 136; --signal-2:2 132 199; --signal-ink:255 255 255;
    --bg:244 247 251; --bg-2:237 242 248; --grid:100 116 139;
    --panel:255 255 255; --panel-2:248 250 252; --panel-3:241 245 249;
    --ink:15 23 42; --ink-soft:51 65 85; --muted:100 116 139;
    --border:226 232 240; --border-2:203 213 225; --shadow:15 23 42; --pass:5 150 105;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; color:rgb(var(--ink)); background-color:rgb(var(--bg));
    background-image:
      radial-gradient(50rem 36rem at 100% -8%, rgb(var(--signal)/0.10), transparent 60%),
      radial-gradient(46rem 36rem at -8% -6%, rgb(var(--signal-2)/0.08), transparent 55%),
      linear-gradient(rgb(var(--grid)/0.035) 1px, transparent 1px),
      linear-gradient(90deg, rgb(var(--grid)/0.035) 1px, transparent 1px);
    background-size:auto, auto, 44px 44px, 44px 44px; background-attachment:fixed;
    font:14.5px/1.6 "Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    -webkit-font-smoothing:antialiased;
  }}
  a {{ color:rgb(var(--signal)); text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .mono {{ font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:0 22px 90px; }}
  header.console {{
    position:sticky; top:0; z-index:30; border-bottom:1px solid rgb(var(--border));
    background:rgb(var(--bg)/0.82); backdrop-filter:blur(12px) saturate(1.2);
  }}
  .console-inner {{ max-width:960px; margin:0 auto; padding:0 22px; height:58px; display:flex; align-items:center; gap:14px; }}
  .brand {{ display:flex; align-items:center; gap:11px; text-decoration:none; }}
  .brand-mark {{ display:grid; place-items:center; height:34px; width:34px; border-radius:9px; color:rgb(var(--signal-ink)); background:linear-gradient(140deg,rgb(var(--signal)),rgb(var(--signal-2))); box-shadow:0 0 0 1px rgb(var(--signal)/0.35),0 8px 22px -10px rgb(var(--signal)/0.8); }}
  .brand-name {{ display:flex; flex-direction:column; line-height:1.1; }}
  .brand-name b {{ font-size:14px; font-weight:700; letter-spacing:0.01em; color:rgb(var(--ink)); }}
  .brand-name span {{ font-size:9.5px; font-weight:600; text-transform:uppercase; letter-spacing:0.16em; color:rgb(var(--muted)); }}
  .signal-text {{ background-image:linear-gradient(100deg,rgb(var(--signal)),rgb(var(--signal-2))); -webkit-background-clip:text; background-clip:text; color:transparent; }}
  .spacer {{ flex:1; }}
  .scan-pill {{ display:inline-flex; align-items:center; gap:8px; padding:5px 12px; border-radius:8px; font-size:11.5px; font-weight:600; color:rgb(var(--ink-soft)); background:rgb(var(--panel-2)); border:1px solid rgb(var(--border)); }}
  .scan-pill .live {{ height:7px; width:7px; border-radius:999px; background:rgb(var(--pass)); box-shadow:0 0 0 3px rgb(var(--pass)/0.18); }}
  .theme-toggle {{ display:grid; place-items:center; height:36px; width:36px; border-radius:8px; border:1px solid rgb(var(--border)); background:rgb(var(--panel)); color:rgb(var(--muted)); cursor:pointer; }}
  .theme-toggle:hover {{ color:rgb(var(--signal)); border-color:rgb(var(--signal)/0.5); }}
  html:not(.dark) .icon-moon {{ display:none; }}
  html.dark .icon-sun {{ display:none; }}
  .hero {{ padding:50px 0 8px; }}
  .kicker {{ display:inline-flex; align-items:center; gap:8px; font-family:"JetBrains Mono",ui-monospace,monospace; font-size:11px; font-weight:600; letter-spacing:0.12em; text-transform:uppercase; color:rgb(var(--signal)); background:rgb(var(--signal)/0.10); border:1px solid rgb(var(--signal)/0.28); padding:5px 11px; border-radius:7px; }}
  .kicker .dot {{ height:6px; width:6px; border-radius:999px; background:rgb(var(--signal)); }}
  h1 {{ font-size:38px; line-height:1.08; letter-spacing:-0.025em; margin:18px 0 10px; font-weight:760; }}
  .lede {{ color:rgb(var(--ink-soft)); font-size:16.5px; max-width:62ch; margin:0; }}
  .cta {{ margin-top:26px; display:flex; flex-wrap:wrap; gap:12px; }}
  .btn {{ display:inline-flex; align-items:center; gap:8px; padding:11px 20px; border-radius:10px; font-size:15px; font-weight:600; text-decoration:none; cursor:pointer; }}
  .btn.primary {{ color:rgb(var(--signal-ink)); background:linear-gradient(135deg,rgb(var(--signal)),rgb(var(--signal-2))); box-shadow:0 10px 26px -12px rgb(var(--signal)/0.9); }}
  .btn.primary:hover {{ filter:brightness(1.06); text-decoration:none; }}
  .btn.ghost {{ color:rgb(var(--ink-soft)); background:rgb(var(--panel)); border:1px solid rgb(var(--border)); }}
  .btn.ghost:hover {{ border-color:rgb(var(--signal)/0.5); color:rgb(var(--ink)); text-decoration:none; }}
  .verdict-bar {{ margin-top:34px; border-radius:14px; overflow:hidden; border:1px solid rgb(var(--border)); background:rgb(var(--panel)/0.92); box-shadow:0 1px 2px rgb(var(--shadow)/0.3),0 22px 50px -30px rgb(var(--shadow)/0.7); }}
  .verdict-top {{ display:flex; flex-wrap:wrap; align-items:center; gap:15px; padding:18px 22px; border-left:4px solid {accent}; }}
  .verdict-icon {{ display:grid; place-items:center; height:46px; width:46px; border-radius:11px; flex-shrink:0; color:{accent}; background:{accent}24; border:1px solid {accent}4d; }}
  .verdict-text {{ flex:1; min-width:0; }}
  .verdict-text .big {{ font-size:20px; font-weight:750; letter-spacing:-0.01em; color:rgb(var(--ink)); }}
  .verdict-text .big em {{ font-style:normal; color:{accent}; }}
  .verdict-text .sub {{ font-size:13px; color:rgb(var(--ink-soft)); margin-top:3px; }}
  .verdict-flag {{ margin-left:auto; display:inline-flex; align-items:center; gap:8px; padding:8px 14px; border-radius:9px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; white-space:nowrap; font-family:"JetBrains Mono",ui-monospace,monospace; color:{verdict_ink}; background:{verdict_bg}; }}
  .verdict-flag .pulse {{ height:7px; width:7px; border-radius:999px; background:currentColor; opacity:.9; }}
  .bento {{ display:grid; grid-template-columns:210px 1fr; grid-template-areas:"donut tiles" "donut bars"; gap:14px; margin-top:34px; }}
  .bento-cell {{ border-radius:14px; border:1px solid rgb(var(--border)); background:rgb(var(--panel)/0.92); box-shadow:0 1px 2px rgb(var(--shadow)/0.25),0 16px 40px -30px rgb(var(--shadow)/0.55); }}
  .cell-donut {{ grid-area:donut; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:14px; padding:22px 16px; }}
  .cell-tiles {{ grid-area:tiles; }}
  .cell-bars {{ grid-area:bars; padding:18px 20px; }}
  .donut {{ position:relative; height:166px; width:166px; border-radius:999px; background:{result_gradient}; box-shadow:inset 0 0 0 1px rgb(var(--border)); }}
  .donut::after {{ content:""; position:absolute; inset:23px; border-radius:999px; background:rgb(var(--panel)); box-shadow:inset 0 0 0 1px rgb(var(--border)/0.6); }}
  .donut-center {{ position:absolute; inset:0; display:grid; place-content:center; text-align:center; z-index:1; }}
  .donut-center .n {{ font-size:38px; font-weight:800; line-height:1; color:rgb(var(--ink)); font-family:"JetBrains Mono",ui-monospace,monospace; }}
  .donut-center .l {{ font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.14em; color:rgb(var(--muted)); margin-top:5px; }}
  .donut-empty {{ position:absolute; inset:0; border-radius:999px; border:15px solid rgb(var(--pass)/0.28); }}
  .donut-cap {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:11px; color:rgb(var(--muted)); }}
  .donut-cap b {{ color:rgb(var(--ink-soft)); }}
  .tiles {{ display:grid; grid-template-columns:repeat(4,1fr); height:100%; }}
  .tile {{ position:relative; padding:16px 16px 15px; border-right:1px solid rgb(var(--border)); display:flex; flex-direction:column; gap:8px; min-width:0; }}
  .tile:last-child {{ border-right:0; }}
  .tile::before {{ content:""; position:absolute; left:0; top:0; height:100%; width:3px; background:var(--t); }}
  .tile .tlabel {{ display:flex; align-items:center; gap:7px; font-size:10.5px; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; color:rgb(var(--ink-soft)); font-family:"JetBrains Mono",ui-monospace,monospace; }}
  .tile .tdot {{ height:8px; width:8px; border-radius:2px; background:var(--t); flex-shrink:0; }}
  .tile .tnum {{ font-size:28px; font-weight:800; line-height:1; color:rgb(var(--ink)); font-family:"JetBrains Mono",ui-monospace,monospace; }}
  .tile.zero .tnum {{ color:rgb(var(--muted)); }}
  .tile .tnum.hit {{ color:var(--t); }}
  .tile .tbar {{ height:4px; border-radius:999px; background:rgb(var(--border)); overflow:hidden; margin-top:auto; }}
  .tile .tbar>span {{ display:block; height:100%; background:var(--t); }}
  .bars-head {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:10px; text-transform:uppercase; letter-spacing:0.12em; color:rgb(var(--muted)); margin-bottom:14px; }}
  .bars {{ display:flex; flex-direction:column; gap:12px; }}
  .bar-row {{ display:grid; grid-template-columns:74px 1fr 30px; gap:12px; align-items:center; }}
  .bname {{ font-size:12px; font-weight:600; display:flex; align-items:center; gap:7px; color:rgb(var(--ink-soft)); font-family:"JetBrains Mono",ui-monospace,monospace; }}
  .sw {{ height:8px; width:8px; border-radius:2px; }}
  .track {{ height:8px; border-radius:999px; background:rgb(var(--bg-2)); border:1px solid rgb(var(--border)); overflow:hidden; }}
  .track>span {{ display:block; height:100%; border-radius:999px; }}
  .bct {{ font-size:13px; font-weight:700; text-align:right; color:rgb(var(--ink)); font-family:"JetBrains Mono",ui-monospace,monospace; }}
  .telemetry {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-top:14px; }}
  .metric {{ border-radius:12px; border:1px solid rgb(var(--border)); background:rgb(var(--panel)/0.92); padding:15px 16px; }}
  .metric .mk {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:10px; text-transform:uppercase; letter-spacing:0.1em; color:rgb(var(--muted)); }}
  .metric .mv {{ font-size:24px; font-weight:800; color:rgb(var(--ink)); margin-top:7px; font-family:"JetBrains Mono",ui-monospace,monospace; line-height:1; }}
  .metric .mv.good {{ color:rgb(var(--pass)); }}
  .metric .mv.bad {{ color:{accent}; }}
  .metric .ms {{ font-size:11px; color:rgb(var(--muted)); margin-top:6px; }}
  .downloads {{ margin-top:44px; }}
  .downloads h2 {{ font-family:"JetBrains Mono",ui-monospace,monospace; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.14em; color:rgb(var(--ink-soft)); margin:0 0 16px; display:flex; align-items:center; gap:11px; }}
  .downloads h2 .idx {{ color:rgb(var(--signal)); }}
  .downloads h2::after {{ content:""; flex:1; height:1px; background:linear-gradient(90deg,rgb(var(--border)),transparent); }}
  .dl-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(215px,1fr)); gap:12px; }}
  .dl {{ display:flex; align-items:center; gap:12px; padding:14px 16px; border-radius:12px; border:1px solid rgb(var(--border)); background:rgb(var(--panel)/0.92); text-decoration:none; color:rgb(var(--ink)); }}
  .dl:hover {{ border-color:rgb(var(--signal)/0.5); text-decoration:none; }}
  .dl .ic {{ display:grid; place-items:center; height:38px; width:38px; border-radius:9px; color:rgb(var(--signal)); background:rgb(var(--signal)/0.10); border:1px solid rgb(var(--signal)/0.24); flex-shrink:0; }}
  .dl b {{ display:block; font-size:14px; }}
  .dl span {{ font-size:11.5px; color:rgb(var(--muted)); font-family:"JetBrains Mono",ui-monospace,monospace; }}
  footer.console {{ margin-top:50px; border-top:1px solid rgb(var(--border)); }}
  .footer-inner {{ max-width:960px; margin:0 auto; padding:26px 22px; display:flex; flex-wrap:wrap; gap:12px; justify-content:space-between; font-size:12.5px; color:rgb(var(--muted)); font-family:"JetBrains Mono",ui-monospace,monospace; }}
  .footer-inner a {{ font-weight:600; text-decoration:none; }}
  .footer-inner b {{ color:rgb(var(--ink-soft)); font-weight:600; }}
  @media (max-width:780px) {{ .bento {{ grid-template-columns:1fr; grid-template-areas:"donut" "tiles" "bars"; }} .telemetry {{ grid-template-columns:repeat(2,1fr); }} }}
  @media (max-width:520px) {{ h1 {{ font-size:29px; }} .tiles {{ grid-template-columns:repeat(2,1fr); }} .tile:nth-child(2) {{ border-right:0; }} .tile:nth-child(1),.tile:nth-child(2) {{ border-bottom:1px solid rgb(var(--border)); }} .telemetry {{ grid-template-columns:1fr; }} .verdict-flag {{ margin-left:0; order:3; }} }}
</style>
<script>
  (function () {{
    try {{
      var s = localStorage.getItem("llmscan-theme");
      var d = s ? s === "dark" : true;
      document.documentElement.classList.toggle("dark", !!d);
    }} catch (e) {{}}
  }})();
  function toggleTheme() {{
    var d = document.documentElement.classList.toggle("dark");
    try {{ localStorage.setItem("llmscan-theme", d ? "dark" : "light"); }} catch (e) {{}}
  }}
</script>
</head>
<body>
<header class="console">
  <div class="console-inner">
    <a class="brand" href="/">
      <span class="brand-mark"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>
      <span class="brand-name"><b>LLM Security <span class="signal-text">Console</span></b><span>Adversarial Scanner</span></span>
    </a>
    <span class="spacer"></span>
    <span class="scan-pill"><span class="live"></span> scan complete</span>
    <button type="button" class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
      <svg class="icon-sun" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
      <svg class="icon-moon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
    </button>
  </div>
</header>

<div class="wrap">
  <section class="hero">
    <span class="kicker"><span class="dot"></span> Live demo · offline, no API key</span>
    <h1>Security-test any LLM. Ship the <span class="signal-text">audit evidence</span>.</h1>
    <p class="lede">An extensible adversarial probe battery — prompt injection, jailbreaks, secret leakage, indirect/RAG injection — with a NIST AI RMF / ISO 42001 governance package generated from the same run.</p>
    <div class="cta">
      <a class="btn primary" href="/report">
        Open the full report
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
      </a>
      <a class="btn ghost" href="https://github.com/LaelaZorana/llm-security-scanner" target="_blank" rel="noopener">View on GitHub</a>
    </div>
  </section>

  <div class="verdict-bar">
    <div class="verdict-top">
      <span class="verdict-icon">{headline_icon}</span>
      <div class="verdict-text">
        <div class="big">Found <em>{result.total_findings}</em> finding{plural}{crit_clause}{high_clause}</div>
        <div class="sub">Target <b class="mono">{result.target}</b> · {result.total_probes} probes · {pass_pct}% pass rate · highest severity {headline_severity}</div>
      </div>
      <span class="verdict-flag"><span class="pulse"></span> {verdict}</span>
    </div>
  </div>

  <div class="bento">
    <div class="bento-cell cell-donut">
      <div class="donut" role="img" aria-label="Findings by severity">
        {donut_empty}
        <div class="donut-center"><div class="n">{result.total_findings}</div><div class="l">Finding{plural}</div></div>
      </div>
      <div class="donut-cap">across <b>{n_categories}</b> categories</div>
    </div>
    <div class="bento-cell cell-tiles">
      <div class="tiles">{tiles}</div>
    </div>
    <div class="bento-cell cell-bars">
      <div class="bars-head">Distribution</div>
      <div class="bars">{bars}</div>
    </div>
  </div>

  <div class="telemetry">
    <div class="metric"><div class="mk">Probes run</div><div class="mv">{result.total_probes}</div><div class="ms">adversarial test cases</div></div>
    <div class="metric"><div class="mk">Pass rate</div><div class="mv good">{pass_pct}%</div><div class="ms">probes handled safely</div></div>
    <div class="metric"><div class="mk">Findings</div><div class="mv {findings_cls}">{result.total_findings}</div><div class="ms">vulnerabilities surfaced</div></div>
    <div class="metric"><div class="mk">Highest severity</div><div class="mv {sev_cls}">{headline_severity}</div><div class="ms">drives the verdict</div></div>
  </div>

  <section class="downloads">
    <h2><span class="idx">&gt;_</span> Governance package</h2>
    <div class="dl-grid">
      <a class="dl" href="/report">
        <span class="ic"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></span>
        <span><b>report.html</b><span>self-contained findings</span></span>
      </a>
      <a class="dl" href="/report.json">
        <span class="ic"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg></span>
        <span><b>report.json</b><span>machine-readable</span></span>
      </a>
      <a class="dl" href="/model_card.md">
        <span class="ic"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg></span>
        <span><b>model_card.md</b><span>NIST AI RMF / ISO 42001</span></span>
      </a>
      <a class="dl" href="/risk_register.csv">
        <span class="ic"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg></span>
        <span><b>risk_register.csv</b><span>GRC-ready register</span></span>
      </a>
    </div>
  </section>
</div>

<footer class="console">
  <div class="footer-inner">
    <span>Built by <b>Laela Zorana</b> · LLM Security Scanner v{__version__}</span>
    <a href="https://github.com/LaelaZorana/llm-security-scanner" target="_blank" rel="noopener">GitHub</a>
  </div>
</footer>
</body>
</html>"""


app = FastAPI(
    title="LLM Security Scanner",
    description="Live demo: adversarial LLM security scan + governance package.",
    version=__version__,
)


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(_landing_html(get_scan_result()))


@app.get("/report", response_class=HTMLResponse)
def report() -> HTMLResponse:
    return HTMLResponse(render_html_report(get_scan_result()))


@app.get("/report.json")
def report_json() -> Response:
    import json

    body = json.dumps(get_scan_result().to_dict(), indent=2)
    return Response(content=body, media_type="application/json")


@app.get("/model_card.md", response_class=PlainTextResponse)
def model_card() -> PlainTextResponse:
    return PlainTextResponse(render_model_card(get_scan_result()))


@app.get("/risk_register.csv")
def risk_register() -> Response:
    return Response(
        content=render_risk_register(get_scan_result()), media_type="text/csv"
    )


@app.get("/summary", response_class=PlainTextResponse)
def summary() -> PlainTextResponse:
    return PlainTextResponse(summary_table(get_scan_result()))


@app.get("/healthz")
def healthz() -> Dict[str, object]:
    result = get_scan_result()
    return {"status": "ok", "target": result.target, "findings": result.total_findings}
