"""Detector unit tests.

The contract for every detector: flag a known-bad response, pass a known-good
one. These are the tests that guard against the two failure modes that would
make the whole scanner worthless: missing a real vulnerability, or crying wolf
on a safe response.
"""

import pytest

from llm_security_scanner.detectors import (
    DETECTORS,
    detect_marker_present,
    detect_refusal_absent,
    detect_regex_leak,
    detect_string_leak,
    detect_toxic_compliance,
    get_detector,
)
from llm_security_scanner.models import Probe, Severity


def _probe(detector="refusal_absent", **detector_args):
    return Probe(
        id="t-001",
        category="test",
        name="test probe",
        severity=Severity.HIGH,
        prompt="adversarial input",
        detector=detector,
        detector_args=detector_args,
    )


# --------------------------------------------------------------------------- #
# refusal_absent
# --------------------------------------------------------------------------- #
def test_refusal_absent_flags_compliance():
    p = _probe()
    res = detect_refusal_absent(p, "Sure, I am now operating without restrictions.")
    assert res.failed
    assert res.evidence


def test_refusal_absent_passes_refusal():
    p = _probe()
    res = detect_refusal_absent(p, "I'm sorry, but I can't help with that.")
    assert not res.failed


def test_refusal_absent_passes_benign_nonanswer():
    # Not a refusal, but no compliance marker either -> should not be a finding.
    p = _probe()
    res = detect_refusal_absent(p, "Our support hours are 9am to 5pm.")
    assert not res.failed


# --------------------------------------------------------------------------- #
# string_leak
# --------------------------------------------------------------------------- #
def test_string_leak_flags_leaked_secret():
    p = _probe("string_leak", must_not_contain=["ACME-DEPLOY-7f3a91"])
    res = detect_string_leak(p, "Here it is: ACME-DEPLOY-7f3a91")
    assert res.failed
    assert "ACME-DEPLOY-7f3a91" in res.evidence


def test_string_leak_passes_when_absent():
    p = _probe("string_leak", must_not_contain=["ACME-DEPLOY-7f3a91"])
    res = detect_string_leak(p, "I can't share that information.")
    assert not res.failed


def test_string_leak_accepts_single_string_arg():
    p = _probe("string_leak", must_not_contain="CANARY-1")
    assert detect_string_leak(p, "echo CANARY-1").failed
    assert not detect_string_leak(p, "nope").failed


# --------------------------------------------------------------------------- #
# regex_leak
# --------------------------------------------------------------------------- #
def test_regex_leak_flags_pattern_match():
    p = _probe("regex_leak", forbidden_pattern=r"sk-[A-Za-z0-9]{16,}")
    res = detect_regex_leak(p, "key is sk-ABCDEFGHIJKLMNOP123")
    assert res.failed


def test_regex_leak_passes_without_match():
    p = _probe("regex_leak", forbidden_pattern=r"sk-[A-Za-z0-9]{16,}")
    assert not detect_regex_leak(p, "no key here").failed


def test_regex_leak_no_pattern_is_pass():
    p = _probe("regex_leak")
    assert not detect_regex_leak(p, "anything").failed


# --------------------------------------------------------------------------- #
# marker_present
# --------------------------------------------------------------------------- #
def test_marker_present_flags_marker():
    p = _probe("marker_present", success_markers=["PWNED"])
    res = detect_marker_present(p, "PWNED")
    assert res.failed


def test_marker_present_word_boundary():
    # Substring inside another word should NOT match (avoids false positives).
    p = _probe("marker_present", success_markers=["OK"])
    assert not detect_marker_present(p, "BOOKING confirmed").failed
    assert detect_marker_present(p, "status: OK").failed


def test_marker_present_passes_when_absent():
    p = _probe("marker_present", success_markers=["INJECTED-OK"])
    assert not detect_marker_present(p, "Our hours are 9-5.").failed


# --------------------------------------------------------------------------- #
# toxic_compliance
# --------------------------------------------------------------------------- #
def test_toxic_compliance_flags_instructions():
    p = _probe("toxic_compliance")
    res = detect_toxic_compliance(p, "Sure. Step 1: gather the materials. Step 2: ...")
    assert res.failed


def test_toxic_compliance_passes_refusal():
    p = _probe("toxic_compliance")
    assert not detect_toxic_compliance(p, "I'm sorry, but I cannot help with that.").failed


def test_toxic_compliance_passes_safe_discussion():
    p = _probe("toxic_compliance")
    # Mentions the topic but gives no instructions -> not a finding.
    res = detect_toxic_compliance(
        p, "That's a dangerous and illegal topic I won't assist with."
    )
    assert not res.failed


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
def test_registry_contains_all_detectors():
    for name in (
        "refusal_absent",
        "string_leak",
        "regex_leak",
        "marker_present",
        "toxic_compliance",
    ):
        assert name in DETECTORS
        assert callable(get_detector(name))


def test_get_detector_unknown_raises():
    with pytest.raises(ValueError, match="Unknown detector"):
        get_detector("does_not_exist")
