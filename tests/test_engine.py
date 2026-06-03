"""Probe-loading and scan-orchestration tests."""

import textwrap

import pytest

from llm_security_scanner.engine import (
    Scanner,
    available_categories,
    load_probes,
)
from llm_security_scanner.models import Severity
from llm_security_scanner.providers import StubProvider


def test_load_builtin_probes():
    probes = load_probes()
    assert len(probes) >= 12
    ids = [p.id for p in probes]
    assert len(ids) == len(set(ids)), "probe ids must be unique"
    # all six categories present
    cats = {p.category for p in probes}
    assert {
        "prompt_injection",
        "jailbreak",
        "system_prompt_leak",
        "pii_secret_leak",
        "toxic_content",
        "indirect_injection",
    } <= cats


def test_load_probes_category_filter():
    probes = load_probes(categories=["jailbreak"])
    assert probes
    assert all(p.category == "jailbreak" for p in probes)


def test_load_probes_unknown_category_raises():
    with pytest.raises(ValueError, match="not found"):
        load_probes(categories=["no_such_category"])


def test_available_categories():
    cats = available_categories()
    assert "prompt_injection" in cats
    assert cats == sorted(cats)


def test_load_probes_missing_dir_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_probes(probe_dir=tmp_path / "does-not-exist")


def test_load_probes_bad_detector_raises(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        textwrap.dedent(
            """
            category: bad
            probes:
              - id: bad-1
                name: bad probe
                prompt: hi
                detector: not_a_real_detector
            """
        )
    )
    with pytest.raises(ValueError, match="Unknown detector"):
        load_probes(probe_dir=tmp_path)


def test_load_probes_duplicate_id_raises(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "category: a\nprobes:\n  - id: dup\n    name: x\n    prompt: p\n    detector: refusal_absent\n"
    )
    (tmp_path / "b.yaml").write_text(
        "category: b\nprobes:\n  - id: dup\n    name: y\n    prompt: p\n    detector: refusal_absent\n"
    )
    with pytest.raises(ValueError, match="Duplicate probe id"):
        load_probes(probe_dir=tmp_path)


def test_scanner_run_produces_findings():
    result = Scanner(StubProvider(), scanner_version="test").run()
    assert result.target == "stub"
    assert result.total_probes >= 12
    # The stub is intentionally vulnerable -> there must be real findings.
    assert result.total_findings > 0
    # ...but it is not trivially broken -> some probes must pass.
    assert result.pass_rate < 1.0
    assert result.pass_rate > 0.0


def test_scanner_findings_have_evidence_and_remediation():
    result = Scanner(StubProvider()).run()
    for f in result.findings:
        assert f.evidence, f"{f.probe_id} missing evidence"
        assert f.remediation, f"{f.probe_id} missing remediation"
        assert f.response, f"{f.probe_id} missing captured response"


def test_scanner_findings_sorted_by_severity():
    result = Scanner(StubProvider()).run()
    sevs = [f.severity.value for f in result.findings]
    assert sevs == sorted(sevs, reverse=True)


def test_scanner_critical_findings_present():
    # The token-exfiltration probes are CRITICAL; the stub leaks the token, so a
    # CRITICAL finding must surface (this is what trips the CI gate).
    result = Scanner(StubProvider()).run()
    assert result.highest_severity() == Severity.CRITICAL
