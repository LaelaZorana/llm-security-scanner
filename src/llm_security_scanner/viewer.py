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

The landing page shares the report's brand language (indigo/violet, Inter,
slate, light + dark) so the demo reads as one product.
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
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#0d9488",
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

    # Headline accent + verdict driven by the worst finding.
    accent = _SEVERITY_HEX.get(hs.name, "#16a34a") if hs else "#16a34a"
    if hs and hs.value >= 4:
        verdict, verdict_bg = "Release-blocking", "#dc2626"
    elif hs and hs.value >= 3:
        verdict, verdict_bg = "Needs remediation", "#ea580c"
    else:
        verdict, verdict_bg = "No blockers", "#16a34a"

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

    # Severity mini-bars.
    total = result.total_findings or 1
    bars = ""
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sc[name]
        pct = round(count / total * 100) if result.total_findings else 0
        color = _SEVERITY_HEX[name]
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

    return f"""<!DOCTYPE html>
<html lang="en" class="">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>LLM Security Scanner — live demo</title>
<meta name="description" content="One-command demo of the LLM Security Scanner: run an adversarial battery against an LLM and get an audit-ready governance package." />
<style>
  :root {{
    --brand:79 70 229; --brand-2:139 92 246; --bg:248 250 252; --panel:255 255 255;
    --panel-2:248 250 252; --ink:15 23 42; --ink-soft:51 65 85; --muted:100 116 139;
    --border:226 232 240; --shadow:15 23 42; --pass:22 163 74;
  }}
  html.dark {{
    --bg:2 6 23; --panel:15 23 42; --panel-2:30 41 59; --ink:241 245 249;
    --ink-soft:203 213 225; --muted:148 163 184; --border:51 65 85; --shadow:0 0 0; --pass:74 222 128;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; color:rgb(var(--ink)); background-color:rgb(var(--bg));
    background-image:
      radial-gradient(48rem 48rem at 110% -10%, rgb(var(--brand-2)/0.12), transparent 55%),
      radial-gradient(42rem 42rem at -10% 0%, rgb(var(--brand)/0.12), transparent 50%);
    background-attachment:fixed;
    font:15px/1.6 "Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    -webkit-font-smoothing:antialiased;
  }}
  a {{ color:rgb(var(--brand)); }}
  .wrap {{ max-width:920px; margin:0 auto; padding:0 20px 80px; }}
  header.site {{
    position:sticky; top:0; z-index:30; border-bottom:1px solid rgb(var(--border)/0.7);
    background:rgb(var(--panel)/0.72); backdrop-filter:blur(10px);
  }}
  .site-inner {{ max-width:920px; margin:0 auto; padding:0 20px; height:60px; display:flex; align-items:center; justify-content:space-between; }}
  .brand {{ display:flex; align-items:center; gap:10px; text-decoration:none; }}
  .brand-mark {{ display:grid; place-items:center; height:34px; width:34px; border-radius:10px; color:#fff; background:linear-gradient(135deg,rgb(var(--brand)),rgb(var(--brand-2))); box-shadow:0 6px 16px -6px rgb(var(--brand)/0.7); }}
  .brand-name b {{ font-size:15px; font-weight:700; letter-spacing:-0.01em; color:rgb(var(--ink)); }}
  .brand-name span {{ display:block; font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:0.08em; color:rgb(var(--muted)); }}
  .grad-text {{ background-image:linear-gradient(100deg,rgb(var(--brand)),rgb(var(--brand-2))); -webkit-background-clip:text; background-clip:text; color:transparent; }}
  .theme-toggle {{ display:grid; place-items:center; height:36px; width:36px; border-radius:9px; border:1px solid rgb(var(--border)); background:rgb(var(--panel)); color:rgb(var(--muted)); cursor:pointer; }}
  .theme-toggle:hover {{ color:rgb(var(--ink)); }}
  html:not(.dark) .icon-moon {{ display:none; }}
  html.dark .icon-sun {{ display:none; }}
  .hero {{ padding:54px 0 8px; }}
  .eyebrow {{ display:inline-flex; align-items:center; gap:7px; padding:4px 12px; border-radius:999px; font-size:12px; font-weight:600; color:rgb(var(--brand)); background:rgb(var(--brand)/0.10); border:1px solid rgb(var(--brand)/0.20); }}
  .eyebrow .dot {{ height:6px; width:6px; border-radius:999px; background:rgb(var(--brand)); }}
  h1 {{ font-size:38px; line-height:1.1; letter-spacing:-0.025em; margin:16px 0 10px; }}
  .lede {{ color:rgb(var(--muted)); font-size:17px; max-width:60ch; margin:0; }}
  .cta {{ margin-top:26px; display:flex; flex-wrap:wrap; gap:12px; }}
  .btn {{ display:inline-flex; align-items:center; gap:8px; padding:11px 20px; border-radius:11px; font-size:15px; font-weight:600; text-decoration:none; cursor:pointer; }}
  .btn.primary {{ color:#fff; background:linear-gradient(135deg,rgb(var(--brand)),rgb(var(--brand-2))); box-shadow:0 10px 24px -10px rgb(var(--brand)/0.8); }}
  .btn.primary:hover {{ filter:brightness(1.06); }}
  .btn.ghost {{ color:rgb(var(--ink-soft)); background:rgb(var(--panel)); border:1px solid rgb(var(--border)); }}
  .btn.ghost:hover {{ border-color:rgb(var(--brand)/0.5); }}
  .card {{ margin-top:34px; border-radius:18px; border:1px solid rgb(var(--border)); background:rgb(var(--panel)/0.85); box-shadow:0 1px 2px rgb(var(--shadow)/0.04),0 18px 40px -24px rgb(var(--shadow)/0.28); overflow:hidden; }}
  .headline-top {{ display:flex; flex-wrap:wrap; align-items:center; gap:14px; padding:20px 24px; border-left:5px solid {accent}; }}
  .headline-icon {{ display:grid; place-items:center; height:46px; width:46px; border-radius:12px; flex-shrink:0; color:{accent}; background:{accent}1f; }}
  .headline-text {{ flex:1; min-width:0; }}
  .headline-text .big {{ font-size:23px; font-weight:700; letter-spacing:-0.01em; color:rgb(var(--ink)); }}
  .headline-text .big em {{ font-style:normal; color:{accent}; }}
  .headline-text .sub {{ font-size:14px; color:rgb(var(--muted)); margin-top:3px; }}
  .verdict {{ margin-left:auto; padding:8px 15px; border-radius:10px; font-size:13px; font-weight:700; color:#fff; background:{verdict_bg}; white-space:nowrap; }}
  .dash {{ display:grid; grid-template-columns:200px 1fr; gap:24px; align-items:center; padding:24px; border-top:1px solid rgb(var(--border)); }}
  .donut {{ position:relative; height:170px; width:170px; border-radius:999px; margin:0 auto; background:{result_gradient}; }}
  .donut::after {{ content:""; position:absolute; inset:23px; border-radius:999px; background:rgb(var(--panel)); }}
  .donut-center {{ position:absolute; inset:0; display:grid; place-content:center; text-align:center; z-index:1; }}
  .donut-center .n {{ font-size:38px; font-weight:800; line-height:1; color:rgb(var(--ink)); }}
  .donut-center .l {{ font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.07em; color:rgb(var(--muted)); margin-top:4px; }}
  .donut-empty {{ position:absolute; inset:0; border-radius:999px; border:15px solid rgb(var(--pass)/0.25); }}
  .bars {{ display:flex; flex-direction:column; gap:14px; }}
  .bar-row {{ display:grid; grid-template-columns:86px 1fr 26px; gap:12px; align-items:center; }}
  .bname {{ font-size:13px; font-weight:600; display:flex; align-items:center; gap:8px; color:rgb(var(--ink-soft)); }}
  .sw {{ height:9px; width:9px; border-radius:3px; }}
  .track {{ height:9px; border-radius:999px; background:rgb(var(--border)/0.8); overflow:hidden; }}
  .track>span {{ display:block; height:100%; border-radius:999px; }}
  .bct {{ font-size:13px; font-weight:700; text-align:right; color:rgb(var(--ink)); }}
  .strip {{ display:grid; grid-template-columns:repeat(3,1fr); border-top:1px solid rgb(var(--border)); }}
  .stat {{ padding:16px; text-align:center; border-right:1px solid rgb(var(--border)); }}
  .stat:last-child {{ border-right:0; }}
  .stat .n {{ font-size:22px; font-weight:800; color:rgb(var(--ink)); }}
  .stat .n.good {{ color:rgb(var(--pass)); }}
  .stat .l {{ font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.06em; color:rgb(var(--muted)); margin-top:6px; }}
  .downloads {{ margin-top:30px; }}
  .downloads h2 {{ font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:0.09em; color:rgb(var(--muted)); margin:0 0 14px; }}
  .dl-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:12px; }}
  .dl {{ display:flex; align-items:center; gap:12px; padding:14px 16px; border-radius:13px; border:1px solid rgb(var(--border)); background:rgb(var(--panel)/0.85); text-decoration:none; color:rgb(var(--ink)); }}
  .dl:hover {{ border-color:rgb(var(--brand)/0.5); }}
  .dl .ic {{ display:grid; place-items:center; height:38px; width:38px; border-radius:10px; color:rgb(var(--brand)); background:rgb(var(--brand)/0.10); flex-shrink:0; }}
  .dl b {{ display:block; font-size:14px; }}
  .dl span {{ font-size:12px; color:rgb(var(--muted)); }}
  footer.site {{ margin-top:48px; border-top:1px solid rgb(var(--border)); }}
  .footer-inner {{ max-width:920px; margin:0 auto; padding:24px 20px; display:flex; flex-wrap:wrap; gap:12px; justify-content:space-between; font-size:13px; color:rgb(var(--muted)); }}
  .footer-inner a {{ font-weight:600; text-decoration:none; }}
  @media (max-width:680px) {{ .dash {{ grid-template-columns:1fr; }} h1 {{ font-size:30px; }} .verdict {{ margin-left:0; }} }}
</style>
<script>
  (function () {{
    try {{
      var s = localStorage.getItem("llmscan-theme");
      var d = s ? s === "dark" : (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
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
<header class="site">
  <div class="site-inner">
    <a class="brand" href="/">
      <span class="brand-mark"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>
      <span class="brand-name"><b>LLM Security <span class="grad-text">Scanner</span></b><span>Adversarial assessment &amp; governance</span></span>
    </a>
    <button type="button" class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle dark mode">
      <svg class="icon-sun" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
      <svg class="icon-moon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
    </button>
  </div>
</header>

<div class="wrap">
  <section class="hero">
    <span class="eyebrow"><span class="dot"></span> Live demo · offline, no API key</span>
    <h1>Security-test any LLM, get an <span class="grad-text">audit-ready</span> report.</h1>
    <p class="lede">An extensible adversarial probe battery (prompt injection, jailbreaks, secret leakage, indirect/RAG injection) with a NIST AI RMF / ISO 42001 governance package generated from the same run.</p>
    <div class="cta">
      <a class="btn primary" href="/report">
        View the full report
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
      </a>
      <a class="btn ghost" href="https://github.com/LaelaZorana/llm-security-scanner" target="_blank" rel="noopener">View on GitHub</a>
    </div>
  </section>

  <div class="card">
    <div class="headline-top">
      <span class="headline-icon">{headline_icon}</span>
      <div class="headline-text">
        <div class="big">Found <em>{result.total_findings}</em> finding{plural}{crit_clause}{high_clause}</div>
        <div class="sub">Target <b>{result.target}</b> · {result.total_probes} probes · {pass_pct}% pass rate · highest severity {headline_severity}</div>
      </div>
      <span class="verdict">{verdict}</span>
    </div>
    <div class="dash">
      <div>
        <div class="donut" role="img" aria-label="Findings by severity">
          {donut_empty}
          <div class="donut-center"><div class="n">{result.total_findings}</div><div class="l">Finding{plural}</div></div>
        </div>
      </div>
      <div class="bars">{bars}</div>
    </div>
    <div class="strip">
      <div class="stat"><div class="n">{result.total_probes}</div><div class="l">Probes run</div></div>
      <div class="stat"><div class="n good">{pass_pct}%</div><div class="l">Pass rate</div></div>
      <div class="stat"><div class="n">{n_categories}</div><div class="l">Categories</div></div>
    </div>
  </div>

  <section class="downloads">
    <h2>Governance package</h2>
    <div class="dl-grid">
      <a class="dl" href="/report">
        <span class="ic"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></span>
        <span><b>report.html</b><span>Self-contained findings report</span></span>
      </a>
      <a class="dl" href="/report.json">
        <span class="ic"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg></span>
        <span><b>report.json</b><span>Machine-readable findings</span></span>
      </a>
      <a class="dl" href="/model_card.md">
        <span class="ic"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg></span>
        <span><b>model_card.md</b><span>NIST AI RMF / ISO 42001</span></span>
      </a>
      <a class="dl" href="/risk_register.csv">
        <span class="ic"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg></span>
        <span><b>risk_register.csv</b><span>GRC-ready risk register</span></span>
      </a>
    </div>
  </section>
</div>

<footer class="site">
  <div class="footer-inner">
    <span>Built by <b style="color:rgb(var(--ink-soft))">Laela Zorana</b> · LLM Security Scanner v{__version__}</span>
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
