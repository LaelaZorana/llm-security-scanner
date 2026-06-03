"""Governance artifact tests — the client-facing compliance deliverables."""

import csv

from llm_security_scanner.engine import Scanner
from llm_security_scanner.governance import (
    build_risk_rows,
    render_model_card,
    write_governance_package,
    write_model_card,
    write_risk_register,
)
from llm_security_scanner.models import ScanResult, utcnow_iso
from llm_security_scanner.providers import StubProvider


def _result():
    return Scanner(StubProvider(), scanner_version="test").run()


def test_risk_rows_derived_from_findings():
    rows = build_risk_rows(_result())
    assert rows, "stub scan should yield risk rows"
    for r in rows:
        assert r["likelihood"] in ("Likely", "Possible", "Unlikely")
        assert r["impact"] in ("Severe", "Major", "Moderate", "Minor", "Negligible")
        assert r["risk_rating"] in ("Critical", "High", "Medium", "Low")
        assert r["owner"]
        assert r["nist_function"]
        assert r["iso_control"]


def test_risk_rows_sorted_worst_first():
    rows = build_risk_rows(_result())
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    ranks = [order[r["risk_rating"]] for r in rows]
    assert ranks == sorted(ranks)


def test_write_risk_register_is_valid_csv(tmp_path):
    path = write_risk_register(_result(), tmp_path / "risk_register.csv")
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows
    assert "risk_rating" in rows[0]
    assert "nist_function" in rows[0]


def test_risk_register_header_written_even_when_clean(tmp_path):
    clean = ScanResult("stub", utcnow_iso(), utcnow_iso(), [])
    path = write_risk_register(clean, tmp_path / "risk_register.csv")
    content = path.read_text()
    assert content.startswith("risk_id,risk,category")


def test_model_card_mentions_frameworks():
    md = render_model_card(_result())
    assert "NIST AI" in md and "RMF" in md
    assert "ISO/IEC 42001" in md
    # All four RMF functions present.
    for fn in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
        assert fn in md


def test_model_card_has_deployment_recommendation():
    md = render_model_card(_result())
    assert "Deployment recommendation" in md
    # stub leaks a token -> critical -> should be a do-not-promote recommendation
    assert "do" in md.lower() and "production" in md.lower()


def test_write_governance_package(tmp_path):
    paths = write_governance_package(_result(), tmp_path)
    assert paths["model_card"].exists()
    assert paths["risk_register"].exists()
    assert paths["model_card"].read_text().startswith("# AI System Risk Assessment")
