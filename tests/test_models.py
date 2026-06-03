"""Core data-model tests."""

import pytest

from llm_security_scanner.models import (
    Finding,
    Probe,
    ProbeOutcome,
    ScanResult,
    Severity,
    utcnow_iso,
)


def test_severity_from_str_case_insensitive():
    assert Severity.from_str("critical") is Severity.CRITICAL
    assert Severity.from_str("  High ") is Severity.HIGH


def test_severity_from_str_invalid():
    with pytest.raises(ValueError, match="Unknown severity"):
        Severity.from_str("catastrophic")


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL


def test_probe_from_dict_minimal():
    p = Probe.from_dict(
        {"id": "x-1", "name": "n", "prompt": "p", "detector": "refusal_absent"},
        category="cat",
    )
    assert p.severity is Severity.MEDIUM  # default
    assert p.category == "cat"


def test_probe_from_dict_missing_field():
    with pytest.raises(ValueError, match="missing required field"):
        Probe.from_dict({"id": "x"}, category="cat")


def _make_result():
    def finding(sev, cat, pid):
        return Finding(
            probe_id=pid,
            category=cat,
            name=pid,
            severity=sev,
            description="d",
            evidence="e",
            remediation="r",
            prompt="p",
            response="resp",
        )

    probe = Probe("p", "cat", "n", Severity.HIGH, "x", "refusal_absent")
    outcomes = [
        ProbeOutcome(probe, "resp", True, finding(Severity.CRITICAL, "a", "a-1")),
        ProbeOutcome(probe, "resp", True, finding(Severity.LOW, "b", "b-1")),
        ProbeOutcome(probe, "ok", False, None),
    ]
    return ScanResult("stub", utcnow_iso(), utcnow_iso(), outcomes)


def test_scan_result_counts():
    r = _make_result()
    assert r.total_probes == 3
    assert r.total_findings == 2
    assert r.severity_counts()["CRITICAL"] == 1
    assert r.severity_counts()["LOW"] == 1
    assert r.severity_counts()["HIGH"] == 0  # always present, zeroed


def test_scan_result_pass_rate():
    r = _make_result()
    assert r.pass_rate == pytest.approx(1 / 3)


def test_scan_result_highest_severity():
    assert _make_result().highest_severity() is Severity.CRITICAL


def test_scan_result_findings_sorted():
    r = _make_result()
    assert r.findings[0].severity is Severity.CRITICAL


def test_scan_result_to_dict_is_json_serializable():
    import json

    r = _make_result()
    blob = json.dumps(r.to_dict())
    assert '"CRITICAL"' in blob
    d = r.to_dict()
    assert d["summary"]["highest_severity"] == "CRITICAL"
    assert d["summary"]["total_findings"] == 2


def test_empty_result_pass_rate_is_one():
    r = ScanResult("stub", utcnow_iso(), utcnow_iso(), [])
    assert r.pass_rate == 1.0
    assert r.highest_severity() is None
