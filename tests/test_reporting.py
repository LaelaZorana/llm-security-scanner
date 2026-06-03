"""Reporting (JSON + HTML) tests."""

import json

from llm_security_scanner.engine import Scanner
from llm_security_scanner.models import (
    Finding,
    Probe,
    ProbeOutcome,
    ScanResult,
    Severity,
    utcnow_iso,
)
from llm_security_scanner.providers import StubProvider
from llm_security_scanner.reporting import (
    render_html_report,
    summary_table,
    write_html_report,
    write_json_report,
)


def _result():
    return Scanner(StubProvider(), scanner_version="test").run()


def test_write_json_report(tmp_path):
    path = write_json_report(_result(), tmp_path / "report.json")
    assert path.exists()
    data = json.loads(path.read_text())
    assert "summary" in data and "findings" in data
    assert data["summary"]["total_findings"] >= 1


def test_write_html_report(tmp_path):
    path = write_html_report(_result(), tmp_path / "report.html")
    html = path.read_text()
    assert html.startswith("<!DOCTYPE html>")
    assert "LLM Security Scan Report" in html
    # Self-contained: no external stylesheet/script references.
    assert "<link" not in html
    assert "src=" not in html


def test_summary_table_renders():
    table = summary_table(_result())
    assert "| Severity | Findings |" in table
    assert "Critical" in table


def test_html_autoescapes_attacker_response():
    """An attacker-controlled model response containing markup must be escaped,
    never rendered as live HTML in the report."""
    f = Finding(
        probe_id="x-1",
        category="cat",
        name="xss test",
        severity=Severity.HIGH,
        description="d",
        evidence="leaked",
        remediation="r",
        prompt="p",
        response="<script>alert('xss')</script>",
    )
    probe = Probe("x-1", "cat", "n", Severity.HIGH, "p", "refusal_absent")
    result = ScanResult(
        "stub",
        utcnow_iso(),
        utcnow_iso(),
        [ProbeOutcome(probe, f.response, True, f)],
    )
    html = render_html_report(result)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
