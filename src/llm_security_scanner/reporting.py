"""
reporting.py — Turn a :class:`ScanResult` into deliverables.

Two output formats, both written from the same result object:
  * ``report.json`` — the machine-readable record (CI gates, dashboards, diffing
    runs over time).
  * ``report.html`` — a polished, fully self-contained page (inline CSS, no
    external assets) so it can be emailed or attached to an audit as-is.

The HTML is rendered with Jinja2 and autoescaping on, so model responses — which
are attacker-controlled and may contain markup — cannot inject script into the
report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .governance import _category_stats, _framework_for
from .models import ScanResult, Severity

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Order severities high-to-low so dashboards and chart legends read top-down.
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
]

# Hex colors for the CSS-only donut (conic-gradient). Chosen to read clearly on
# both the light and dark report backgrounds.
_SEVERITY_HEX = {
    Severity.CRITICAL: "#dc2626",  # red-600
    Severity.HIGH: "#ea580c",      # orange-600
    Severity.MEDIUM: "#d97706",    # amber-600
    Severity.LOW: "#0d9488",       # teal-600
}


def write_json_report(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return path


def _category_rows(result: ScanResult) -> List[Dict[str, object]]:
    """Per-category coverage: probe count, finding count, and OWASP tag."""
    counts: Dict[str, Dict[str, object]] = {}
    for outcome in result.outcomes:
        cat = outcome.probe.category
        row = counts.setdefault(
            cat, {"name": cat, "owasp": outcome.probe.owasp, "probes": 0, "findings": 0}
        )
        row["probes"] = int(row["probes"]) + 1
        if not row["owasp"] and outcome.probe.owasp:
            row["owasp"] = outcome.probe.owasp
    for finding in result.findings:
        if finding.category in counts:
            row = counts[finding.category]
            row["findings"] = int(row["findings"]) + 1
    return [counts[k] for k in sorted(counts)]


def _compliance_rows(result: ScanResult) -> List[Dict[str, object]]:
    """One row per probe category that maps it to its NIST AI RMF function, the
    ISO/IEC 42001 Annex A control area, and the observed coverage.

    Reuses the governance mapping tables so the recruiter-facing HTML report and
    the auditor-facing ``model_card.md`` never drift apart.
    """
    stats = _category_stats(result)
    cat_owasp = {o.probe.category: o.probe.owasp for o in result.outcomes}
    rows: List[Dict[str, object]] = []
    for category in sorted(stats):
        s = stats[category]
        fw = _framework_for(category)
        worst: Severity = s["worst"]  # type: ignore[assignment]
        rows.append(
            {
                "category": category,
                "owasp": cat_owasp.get(category, "") or "",
                "probes": int(s["probes"]),
                "findings": int(s["findings"]),
                "worst": worst.name if worst else "",
                "nist": fw["nist"],
                "iso": fw["iso"],
                "owner": fw["owner"],
            }
        )
    return rows


def _donut_segments(result: ScanResult) -> Dict[str, object]:
    """Pre-compute the severity breakdown as conic-gradient stops so the report
    can draw a CSS-only donut chart (no JS, no external chart library).

    Returns the ordered per-severity segments (with their sweep angles), the
    ready-to-use ``conic-gradient(...)`` string, and the total finding count used
    for the donut's center label.
    """
    sc = result.severity_counts()
    total = result.total_findings
    segments: List[Dict[str, object]] = []
    stops: List[str] = []
    start = 0.0
    for sev in _SEVERITY_ORDER:
        count = sc[sev.name]
        sweep = (count / total * 360.0) if total else 0.0
        end = start + sweep
        if count:
            stops.append(
                f"{_SEVERITY_HEX[sev]} {start:.3f}deg {end:.3f}deg"
            )
        segments.append(
            {
                "name": sev.name,
                "label": sev.name.title(),
                "count": count,
                "pct": round((count / total * 100), 1) if total else 0.0,
            }
        )
        start = end
    gradient = (
        f"conic-gradient({', '.join(stops)})"
        if stops
        else "conic-gradient(rgb(var(--border)) 0deg 360deg)"
    )
    return {"segments": segments, "total": total, "gradient": gradient}


def render_html_report(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    donut = _donut_segments(result)
    return template.render(
        result=result,
        categories=_category_rows(result),
        compliance=_compliance_rows(result),
        donut=donut,
        donut_gradient=donut["gradient"],
        version=result.scanner_version,
    )


def write_html_report(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(result), encoding="utf-8")
    return path


def summary_table(result: ScanResult) -> str:
    """A compact severity table for terminal / Markdown output."""
    sc = result.severity_counts()
    lines = [
        "| Severity | Findings |",
        "|----------|----------|",
        f"| Critical | {sc['CRITICAL']} |",
        f"| High     | {sc['HIGH']} |",
        f"| Medium   | {sc['MEDIUM']} |",
        f"| Low      | {sc['LOW']} |",
        f"| **Total**| **{result.total_findings}** |",
    ]
    return "\n".join(lines)
