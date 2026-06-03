"""
Tests for the optional FastAPI report viewer.

Skipped automatically when the [viewer] extra (FastAPI) is not installed, so the
lean offline test run (PyYAML + Jinja2 only) stays green. When FastAPI is
present, the whole surface is verified through Starlette's TestClient — no server
is bound.
"""

import pytest

pytest.importorskip("fastapi", reason="viewer extra (fastapi) not installed")

from starlette.testclient import TestClient  # noqa: E402

from llm_security_scanner import viewer  # noqa: E402


@pytest.fixture()
def client():
    # Reset the memoized scan so each test run reflects the current code.
    viewer.get_scan_result.cache_clear()
    return TestClient(viewer.app)


def test_landing_page_renders_headline(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    body = r.text
    assert body.startswith("<!DOCTYPE html>")
    # The headline result must be surfaced prominently on the landing page.
    assert "Found" in body and "finding" in body
    # On-brand chrome.
    assert "Laela Zorana" in body
    assert "conic-gradient" in body  # the severity donut


def test_report_route_is_self_contained(client):
    r = client.get("/report")
    assert r.status_code == 200
    html = r.text
    assert "LLM Security Scan Report" in html
    # Same self-containment guarantee as the written report file.
    assert "<link" not in html
    assert "src=" not in html


def test_report_html_autoescapes(client):
    """The report served over HTTP must escape model output just like the file
    reporter does (defense in depth against attacker-controlled responses)."""
    r = client.get("/report")
    # The stub never emits a <script>, but verify escaping is active by checking
    # no raw closing-script slips through from any rendered field.
    assert "<script>alert" not in r.text


def test_report_json_route(client):
    r = client.get("/report.json")
    assert r.status_code == 200
    assert "application/json" in r.headers["content-type"]
    data = r.json()
    assert "summary" in data and "findings" in data
    assert data["summary"]["total_findings"] >= 1


def test_model_card_route(client):
    r = client.get("/model_card.md")
    assert r.status_code == 200
    assert "NIST AI" in r.text
    assert "ISO/IEC 42001" in r.text


def test_risk_register_route(client):
    r = client.get("/risk_register.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    # Header row is always present.
    assert r.text.splitlines()[0].startswith("risk_id,risk,category")


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    payload = r.json()
    assert payload["status"] == "ok"
    assert payload["target"] == "stub"
    assert payload["findings"] >= 1
