"""
models.py — Core data structures shared across the scanner.

A scan flows through three object types:

    Probe      -> a single adversarial input plus the criteria for deciding
                  whether the model failed it (defined declaratively in YAML).
    Finding    -> the result of running one probe against the target when the
                  model's response indicates a vulnerability (severity-tagged,
                  with evidence and remediation).
    ScanResult -> the aggregate of every probe outcome for one scan run, with
                  summary statistics used by the reporters and governance docs.

Keeping these decoupled from the probe logic and the I/O layer is what lets the
same finding objects feed the JSON report, the HTML report, the risk register
and the model card without any of those knowing about each other.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class Severity(enum.Enum):
    """Severity ordering, highest first. The integer rank drives sorting and
    the CI `--fail-on` threshold."""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name for s in cls)
            raise ValueError(
                f"Unknown severity {value!r}. Valid values: {valid}"
            ) from exc

    # Order by the integer rank so severities sort and `max()` directly. A plain
    # Enum is unordered; defining __lt__ keeps every comparison in one place.
    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value < other.value

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Probe:
    """A single declarative test case loaded from a probe pack.

    Attributes:
        id: Stable, unique identifier (e.g. ``pi-001``). Used in reports and
            for suppression/allow-listing.
        category: The test battery this probe belongs to (e.g.
            ``prompt_injection``). Maps 1:1 to a detector.
        name: Short human-readable label.
        severity: Severity assigned to a *failure* of this probe.
        prompt: The adversarial input sent to the model under test.
        detector: Name of the detector function used to judge the response.
        detector_args: Detector-specific parameters (e.g. the canary token a
            leak detector should search for).
        description: What weakness this probe targets.
        remediation: Actionable fix shown on the finding when it triggers.
        owasp: Optional OWASP LLM Top 10 reference (e.g. ``LLM01``).
        context: Optional "retrieved"/tool content for indirect-injection
            probes, kept separate from the user ``prompt`` so the stub and real
            providers can model a realistic RAG/tool boundary.
    """

    id: str
    category: str
    name: str
    severity: Severity
    prompt: str
    detector: str
    detector_args: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    remediation: str = ""
    owasp: str = ""
    context: Optional[str] = None

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], *, category: str) -> "Probe":
        missing = [k for k in ("id", "name", "prompt", "detector") if k not in raw]
        if missing:
            raise ValueError(
                f"Probe in category {category!r} missing required field(s): "
                f"{', '.join(missing)}"
            )
        return cls(
            id=raw["id"],
            category=category,
            name=raw["name"],
            severity=Severity.from_str(raw.get("severity", "MEDIUM")),
            prompt=raw["prompt"],
            detector=raw["detector"],
            detector_args=dict(raw.get("detector_args", {})),
            description=raw.get("description", ""),
            remediation=raw.get("remediation", ""),
            owasp=raw.get("owasp", ""),
            context=raw.get("context"),
        )


@dataclass
class Finding:
    """A vulnerability surfaced by a probe whose detector judged the response
    as a failure."""

    probe_id: str
    category: str
    name: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    prompt: str
    response: str
    owasp: str = ""
    detector: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class ProbeOutcome:
    """Outcome of running a single probe — failed or not. Non-failures are
    retained so the report can show coverage (tests passed vs. failed), not
    just the bad news."""

    probe: Probe
    response: str
    failed: bool
    finding: Optional[Finding] = None


@dataclass
class ScanResult:
    """Aggregate result of one full scan run."""

    target: str
    started_at: str
    finished_at: str
    outcomes: List[ProbeOutcome] = field(default_factory=list)
    scanner_version: str = ""

    # ------------------------------------------------------------------ #
    # Derived views
    # ------------------------------------------------------------------ #
    @property
    def findings(self) -> List[Finding]:
        items = [o.finding for o in self.outcomes if o.finding is not None]
        return sorted(items, key=lambda f: (-f.severity.value, f.category, f.probe_id))

    @property
    def total_probes(self) -> int:
        return len(self.outcomes)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def severity_counts(self) -> Dict[str, int]:
        """Count of findings per severity, always including every level so the
        report tables are stable."""
        counts = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    def category_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts

    @property
    def pass_rate(self) -> float:
        if not self.outcomes:
            return 1.0
        passed = sum(1 for o in self.outcomes if not o.failed)
        return passed / len(self.outcomes)

    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scanner_version": self.scanner_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": {
                "total_probes": self.total_probes,
                "total_findings": self.total_findings,
                "pass_rate": round(self.pass_rate, 4),
                "severity_counts": self.severity_counts(),
                "category_counts": self.category_counts(),
                "highest_severity": (
                    self.highest_severity().name if self.highest_severity() else None
                ),
            },
            "findings": [f.to_dict() for f in self.findings],
            "passed_probes": [
                {
                    "probe_id": o.probe.id,
                    "category": o.probe.category,
                    "name": o.probe.name,
                }
                for o in self.outcomes
                if not o.failed
            ],
        }


def utcnow_iso() -> str:
    """Timezone-aware UTC timestamp, ISO-8601 with a trailing ``Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
