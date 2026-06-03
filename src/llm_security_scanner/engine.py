"""
engine.py — Probe loading and scan orchestration.

Responsibilities:
  * Discover and parse the YAML probe packs into :class:`Probe` objects
    (:func:`load_probes`). Packs ship inside the package but a caller can point
    at any directory to extend or replace the battery.
  * Run a battery against a :class:`Provider`, apply each probe's detector, and
    assemble a :class:`ScanResult` (:class:`Scanner`).

The engine is intentionally thin: all the security knowledge lives in the YAML
packs and the detectors, and all the rendering lives in the reporters. That
separation is what makes the tool easy to audit and extend.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

from .detectors import get_detector
from .models import (
    Finding,
    Probe,
    ProbeOutcome,
    ScanResult,
    utcnow_iso,
)
from .providers import Provider

DEFAULT_PROBE_DIR = Path(__file__).parent / "probes"


def load_probes(
    probe_dir: Optional[Path] = None,
    categories: Optional[Iterable[str]] = None,
) -> List[Probe]:
    """Load every probe from the YAML packs in ``probe_dir``.

    Args:
        probe_dir: Directory of ``*.yaml`` probe packs. Defaults to the packs
            bundled with the package.
        categories: Optional allow-list of category names to include. ``None``
            loads everything.

    Returns:
        Probes sorted by ``(category, id)`` for stable, reproducible runs.

    Raises:
        FileNotFoundError: if the directory does not exist.
        ValueError: if a pack is malformed or a probe references an unknown
            detector (fail fast — a broken pack must not silently shrink the
            battery).
    """
    probe_dir = Path(probe_dir) if probe_dir else DEFAULT_PROBE_DIR
    if not probe_dir.is_dir():
        raise FileNotFoundError(f"Probe directory not found: {probe_dir}")

    wanted = set(categories) if categories else None
    probes: List[Probe] = []
    seen_ids: Dict[str, str] = {}

    for path in sorted(probe_dir.glob("*.y*ml")):
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

        category = data.get("category")
        if not category:
            raise ValueError(f"Probe pack {path.name} is missing a 'category'.")
        if wanted is not None and category not in wanted:
            continue

        pack_owasp = data.get("owasp", "")
        for raw in data.get("probes", []):
            raw.setdefault("owasp", pack_owasp)
            probe = Probe.from_dict(raw, category=category)

            # Validate the detector reference eagerly.
            get_detector(probe.detector)

            if probe.id in seen_ids:
                raise ValueError(
                    f"Duplicate probe id {probe.id!r} in {path.name} "
                    f"(already defined in {seen_ids[probe.id]})."
                )
            seen_ids[probe.id] = path.name
            probes.append(probe)

    if wanted:
        missing = wanted - {p.category for p in probes}
        if missing:
            raise ValueError(
                f"Requested categories not found: {', '.join(sorted(missing))}."
            )

    return sorted(probes, key=lambda p: (p.category, p.id))


def available_categories(probe_dir: Optional[Path] = None) -> List[str]:
    """List the probe categories available in ``probe_dir``."""
    return sorted({p.category for p in load_probes(probe_dir)})


class Scanner:
    """Runs a probe battery against a target provider."""

    def __init__(
        self,
        provider: Provider,
        probes: Optional[List[Probe]] = None,
        *,
        probe_dir: Optional[Path] = None,
        categories: Optional[Iterable[str]] = None,
        scanner_version: str = "",
    ):
        self.provider = provider
        self.probes = (
            probes if probes is not None else load_probes(probe_dir, categories)
        )
        self.scanner_version = scanner_version

    def run_probe(self, probe: Probe) -> ProbeOutcome:
        """Execute one probe end-to-end: query the provider, judge, package."""
        response = self.provider.complete(probe.prompt, context=probe.context)
        detector = get_detector(probe.detector)
        result = detector(probe, response)

        if not result.failed:
            return ProbeOutcome(probe=probe, response=response, failed=False)

        finding = Finding(
            probe_id=probe.id,
            category=probe.category,
            name=probe.name,
            severity=probe.severity,
            description=probe.description,
            evidence=result.evidence,
            remediation=probe.remediation,
            prompt=probe.prompt,
            response=response,
            owasp=probe.owasp,
            detector=probe.detector,
        )
        return ProbeOutcome(probe=probe, response=response, failed=True, finding=finding)

    def run(self) -> ScanResult:
        """Run the full battery and return an aggregate result."""
        started = utcnow_iso()
        outcomes = [self.run_probe(p) for p in self.probes]
        finished = utcnow_iso()
        return ScanResult(
            target=self.provider.name,
            started_at=started,
            finished_at=finished,
            outcomes=outcomes,
            scanner_version=self.scanner_version,
        )
