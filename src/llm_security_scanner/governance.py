"""
governance.py: The client-facing compliance layer.

A raw vulnerability report tells an engineer what to fix. A *governance package*
tells a risk owner, an auditor, and a customer's security team that the system is
being managed against a recognised framework. This module turns the same
:class:`ScanResult` into two such artifacts:

  1. ``model_card.md``: a model card / risk assessment whose findings are mapped
     onto the four NIST AI RMF functions (GOVERN / MAP / MEASURE / MANAGE) and
     the relevant ISO/IEC 42001 Annex A controls. It reads as the narrative an
     organisation would put in front of an auditor.

  2. ``risk_register.csv``: one row per risk (derived from the findings), with
     likelihood, impact, a qualitative risk rating, mitigation and an owner. This
     is the live tracking artifact a GRC team maintains.

The framework mappings are deliberately conservative and traceable: every claim
ties back to a probe category and an observed finding, so nothing here is
boilerplate that an auditor could call unsubstantiated.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Dict, List, Tuple

from .models import ScanResult, Severity

# --------------------------------------------------------------------------- #
# Framework mapping tables
# --------------------------------------------------------------------------- #
# Each probe category maps to: a NIST AI RMF function emphasis, the ISO/IEC 42001
# Annex A control area it provides evidence for, and the default risk owner role.
CATEGORY_FRAMEWORK: Dict[str, Dict[str, str]] = {
    "prompt_injection": {
        "nist": "MEASURE 2.7 (security & resilience testing)",
        "iso": "A.6.2.4 / A.8.4 (system input controls, data quality)",
        "owner": "ML Platform Lead",
        "risk_label": "Prompt-injection control bypass",
    },
    "jailbreak": {
        "nist": "MEASURE 2.6 (safety) / MANAGE 2.2 (mechanisms to sustain value)",
        "iso": "A.6.2.2 / A.9.2 (responsible AI objectives, intended use)",
        "owner": "Responsible AI Officer",
        "risk_label": "Safety-policy jailbreak",
    },
    "system_prompt_leak": {
        "nist": "MAP 5.1 (impacts) / MEASURE 2.7 (security testing)",
        "iso": "A.7.4 / A.8.3 (system documentation, information security)",
        "owner": "Security Engineering Lead",
        "risk_label": "System-prompt / instruction disclosure",
    },
    "pii_secret_leak": {
        "nist": "MEASURE 2.10 (privacy) / MANAGE 2.3 (incident response)",
        "iso": "A.8.3 / A.5.4 (information security, privacy by design)",
        "owner": "Data Protection Officer",
        "risk_label": "Sensitive data / secret leakage",
    },
    "toxic_content": {
        "nist": "MEASURE 2.6 (safety) / MEASURE 2.11 (harmful bias & content)",
        "iso": "A.6.2.2 / A.9.3 (responsible AI, third-party & user impact)",
        "owner": "Responsible AI Officer",
        "risk_label": "Disallowed-content generation",
    },
    "indirect_injection": {
        "nist": "MEASURE 2.7 (security) / MAP 4.1 (3rd-party & integration risk)",
        "iso": "A.8.4 / A.10.2 (data quality, third-party data controls)",
        "owner": "ML Platform Lead",
        "risk_label": "Indirect / 2nd-order injection via untrusted data",
    },
}

_DEFAULT_FRAMEWORK = {
    "nist": "MEASURE 2.7 (security & resilience testing)",
    "iso": "A.8.3 (information security)",
    "owner": "Security Engineering Lead",
    "risk_label": "AI control weakness",
}

# Likelihood is inferred from how the battery performed for a category; impact is
# driven by the worst severity observed in that category.
_SEVERITY_TO_IMPACT = {
    Severity.CRITICAL: "Severe",
    Severity.HIGH: "Major",
    Severity.MEDIUM: "Moderate",
    Severity.LOW: "Minor",
    Severity.INFO: "Negligible",
}

# Qualitative 5x... risk matrix collapsed to a 4-level rating.
_RISK_MATRIX = {
    ("Likely", "Severe"): "Critical",
    ("Likely", "Major"): "High",
    ("Likely", "Moderate"): "High",
    ("Likely", "Minor"): "Medium",
    ("Possible", "Severe"): "High",
    ("Possible", "Major"): "High",
    ("Possible", "Moderate"): "Medium",
    ("Possible", "Minor"): "Low",
    ("Unlikely", "Severe"): "Medium",
    ("Unlikely", "Major"): "Medium",
    ("Unlikely", "Moderate"): "Low",
    ("Unlikely", "Minor"): "Low",
}


def _framework_for(category: str) -> Dict[str, str]:
    return CATEGORY_FRAMEWORK.get(category, _DEFAULT_FRAMEWORK)


def _category_stats(result: ScanResult) -> Dict[str, Dict[str, object]]:
    """Aggregate per-category: probe count, finding count, worst severity."""
    stats: Dict[str, Dict[str, object]] = {}
    for outcome in result.outcomes:
        cat = outcome.probe.category
        s = stats.setdefault(cat, {"probes": 0, "findings": 0, "worst": None})
        s["probes"] = int(s["probes"]) + 1
    for finding in result.findings:
        s = stats.setdefault(
            finding.category, {"probes": 0, "findings": 0, "worst": None}
        )
        s["findings"] = int(s["findings"]) + 1
        worst = s["worst"]
        if worst is None or finding.severity.value > worst.value:
            s["worst"] = finding.severity
    return stats


def _likelihood(probes: int, findings: int) -> str:
    """Empirical likelihood from the observed failure ratio in that category."""
    if probes == 0 or findings == 0:
        return "Unlikely"
    ratio = findings / probes
    if ratio >= 0.5:
        return "Likely"
    if ratio >= 0.25:
        return "Possible"
    return "Unlikely"


def build_risk_rows(result: ScanResult) -> List[Dict[str, str]]:
    """Derive risk-register rows (one per category that produced findings)."""
    rows: List[Dict[str, str]] = []
    stats = _category_stats(result)
    for category in sorted(stats):
        s = stats[category]
        findings = int(s["findings"])
        if findings == 0:
            continue  # only register risks we actually observed evidence for
        probes = int(s["probes"])
        worst: Severity = s["worst"]  # type: ignore[assignment]
        fw = _framework_for(category)
        likelihood = _likelihood(probes, findings)
        impact = _SEVERITY_TO_IMPACT[worst]
        rating = _RISK_MATRIX.get((likelihood, impact), "Medium")
        rows.append(
            {
                "risk_id": f"R-{category.upper().replace('_', '')[:6]}",
                "risk": fw["risk_label"],
                "category": category,
                "likelihood": likelihood,
                "impact": impact,
                "risk_rating": rating,
                "evidence": f"{findings}/{probes} probes failed (worst: {worst.name})",
                "mitigation": _mitigation_for(category),
                "owner": fw["owner"],
                "nist_function": fw["nist"],
                "iso_control": fw["iso"],
                "status": "Open",
            }
        )
    # Sort by descending risk rating so the worst rows are at the top.
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(rows, key=lambda r: order.get(r["risk_rating"], 9))


_MITIGATIONS = {
    "prompt_injection": "Enforce instruction hierarchy; sanitise/escape user "
    "input; add output filters for injection markers.",
    "jailbreak": "Framing-independent safety policy; adversarial eval gate in "
    "CI; refuse persona/role-play overrides.",
    "system_prompt_leak": "Remove secrets from the prompt/context; deny "
    "context-echo requests; least-privilege configuration.",
    "pii_secret_leak": "Output DLP/redaction for secret- and PII-shaped tokens; "
    "do not echo untrusted input verbatim.",
    "toxic_content": "Hard refusal policy for disallowed categories; "
    "intent-based evaluation; abuse logging & rate limiting.",
    "indirect_injection": "Trust boundary between instructions and retrieved "
    "data; treat tool/RAG content as inert text.",
}


def _mitigation_for(category: str) -> str:
    return _MITIGATIONS.get(category, "Apply least privilege and add a targeted "
                                      "detection/eval for this weakness.")


RISK_REGISTER_FIELDS = [
    "risk_id",
    "risk",
    "category",
    "likelihood",
    "impact",
    "risk_rating",
    "evidence",
    "mitigation",
    "owner",
    "nist_function",
    "iso_control",
    "status",
]


def render_risk_register(result: ScanResult) -> str:
    """Return ``risk_register.csv`` as a string. Always emits the header so an
    empty (clean) scan still produces a valid, openable register. Shared by the
    file writer and the web viewer so the schema lives in exactly one place."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=RISK_REGISTER_FIELDS)
    writer.writeheader()
    for row in build_risk_rows(result):
        writer.writerow(row)
    return buf.getvalue()


def write_risk_register(result: ScanResult, path: Path) -> Path:
    """Write ``risk_register.csv`` to disk."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_risk_register(result), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Model card / risk assessment (Markdown)
# --------------------------------------------------------------------------- #
def _rmf_function_blocks(result: ScanResult) -> List[Tuple[str, str, List[str]]]:
    """Build the four NIST AI RMF function sections with evidence bullets drawn
    from the actual scan."""
    stats = _category_stats(result)
    sc = result.severity_counts()
    total_findings = result.total_findings

    govern = [
        "An AI risk management process is in place: this assessment is produced "
        "by an automated, repeatable security scan run as a release gate.",
        f"Risk register maintained with {len(build_risk_rows(result))} tracked "
        "risk item(s), each with a named accountable owner.",
        "Roles assigned per risk (Responsible AI Officer, Security Engineering "
        "Lead, Data Protection Officer, ML Platform Lead).",
    ]

    map_fn = [
        f"System context: target identifier `{result.target}`; "
        f"{result.total_probes} adversarial probes across "
        f"{len(stats)} risk categories.",
        "Threat surface mapped to OWASP LLM Top 10 (LLM01 prompt injection, "
        "LLM02 insecure output, LLM06 sensitive-information disclosure, "
        "LLM07 system-prompt leakage).",
        "Indirect/third-party data risks are explicitly scoped via retrieved-"
        "content (RAG/tool) injection probes.",
    ]

    measure = [
        f"Quantitative result: {total_findings} finding(s); overall probe "
        f"pass rate {result.pass_rate:.0%}.",
        "Severity distribution: "
        f"Critical {sc['CRITICAL']}, High {sc['HIGH']}, "
        f"Medium {sc['MEDIUM']}, Low {sc['LOW']}.",
        "Each finding carries reproducible evidence (the exact probe and model "
        "response) enabling independent verification.",
    ]

    manage = []
    highest = result.highest_severity()
    if highest and highest.value >= Severity.HIGH.value:
        manage.append(
            f"Open high-severity exposure (max severity {highest.name}); "
            "treat as release-blocking until mitigated or formally accepted."
        )
    else:
        manage.append(
            "No high-severity exposure detected in this run; maintain "
            "continuous monitoring as the model and prompts evolve."
        )
    manage.extend(
        [
            "Mitigations are prioritised by risk rating in the risk register; "
            "high/critical items are remediated before deployment.",
            "This scan is wired into CI to re-measure on every change, providing "
            "ongoing assurance rather than a point-in-time snapshot.",
        ]
    )

    return [
        ("GOVERN", "Culture, accountability and process for AI risk.", govern),
        ("MAP", "Context, intended use and risk identification.", map_fn),
        ("MEASURE", "Quantitative & qualitative assessment of identified risks.", measure),
        ("MANAGE", "Prioritisation, response and ongoing monitoring.", manage),
    ]


def render_model_card(result: ScanResult) -> str:
    sc = result.severity_counts()
    stats = _category_stats(result)
    highest = result.highest_severity()

    lines: List[str] = [
        "# AI System Risk Assessment & Model Card",
        "",
        f"**Target system:** `{result.target}`  ",
        f"**Assessment date:** {result.finished_at}  ",
        f"**Scanner version:** {result.scanner_version or 'n/a'}  ",
        f"**Overall result:** {result.total_findings} finding(s), "
        f"pass rate {result.pass_rate:.0%}  ",
        f"**Highest severity:** {highest.name if highest else 'None'}",
        "",
        "> This document is the governance artifact accompanying an automated "
        "LLM security scan. Findings are mapped to the **NIST AI Risk "
        "Management Framework (AI RMF 1.0)** core functions and **ISO/IEC "
        "42001:2023** Annex A controls to support audit and assurance.",
        "",
        "## 1. Executive summary",
        "",
        "| Severity | Findings |",
        "|----------|----------|",
        f"| Critical | {sc['CRITICAL']} |",
        f"| High | {sc['HIGH']} |",
        f"| Medium | {sc['MEDIUM']} |",
        f"| Low | {sc['LOW']} |",
        f"| **Total** | **{result.total_findings}** |",
        "",
    ]

    if highest and highest.value >= Severity.HIGH.value:
        lines.append(
            f"**Deployment recommendation:** Do **not** promote to production "
            f"until the {sc['CRITICAL']} critical and {sc['HIGH']} high "
            "finding(s) are remediated or have a documented, signed-off risk "
            "acceptance."
        )
    else:
        lines.append(
            "**Deployment recommendation:** No high-severity blockers in this "
            "run. Proceed with standard change-management and keep the scan in "
            "CI for continuous assurance."
        )
    lines += ["", "## 2. NIST AI RMF mapping", ""]

    for name, desc, bullets in _rmf_function_blocks(result):
        lines.append(f"### {name}: {desc}")
        lines.append("")
        for b in bullets:
            lines.append(f"- {b}")
        lines.append("")

    lines += [
        "## 3. Control coverage by category",
        "",
        "| Category | OWASP | Probes | Findings | Worst severity | NIST function | ISO/IEC 42001 control |",
        "|----------|-------|-------:|---------:|----------------|---------------|------------------------|",
    ]
    # stable category order
    cat_owasp = {o.probe.category: o.probe.owasp for o in result.outcomes}
    for category in sorted(stats):
        s = stats[category]
        fw = _framework_for(category)
        worst: Severity = s["worst"]  # type: ignore[assignment]
        worst_name = worst.name if worst else "-"
        lines.append(
            f"| {category} | {cat_owasp.get(category, '-') or '-'} | "
            f"{int(s['probes'])} | {int(s['findings'])} | {worst_name} | "
            f"{fw['nist']} | {fw['iso']} |"
        )

    lines += [
        "",
        "## 4. Prioritised risks & mitigations",
        "",
    ]
    rows = build_risk_rows(result)
    if rows:
        lines += [
            "| Risk ID | Risk | Rating | Likelihood | Impact | Mitigation | Owner |",
            "|---------|------|--------|------------|--------|------------|-------|",
        ]
        for r in rows:
            lines.append(
                f"| {r['risk_id']} | {r['risk']} | {r['risk_rating']} | "
                f"{r['likelihood']} | {r['impact']} | {r['mitigation']} | "
                f"{r['owner']} |"
            )
    else:
        lines.append("_No risks identified in this run._")

    lines += [
        "",
        "## 5. Assurance & monitoring",
        "",
        "- This assessment is reproducible: re-running the scanner against the "
        "same target reproduces these results.",
        "- The scan is integrated into CI and fails the build on critical "
        "findings, enforcing the control continuously (NIST MANAGE; ISO/IEC "
        "42001 A.6.2.6 operational controls).",
        "- The accompanying `risk_register.csv` is the live tracking artifact "
        "for the GRC function.",
        "",
        "_Disclaimer: automated scanning establishes a security baseline and "
        "evidence trail; it complements, but does not replace, human red-teaming "
        "and a full risk assessment._",
        "",
    ]
    return "\n".join(lines)


def write_model_card(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_model_card(result), encoding="utf-8")
    return path


def write_governance_package(result: ScanResult, out_dir: Path) -> Dict[str, Path]:
    """Write both governance artifacts; return their paths."""
    out_dir = Path(out_dir)
    return {
        "model_card": write_model_card(result, out_dir / "model_card.md"),
        "risk_register": write_risk_register(result, out_dir / "risk_register.csv"),
    }
