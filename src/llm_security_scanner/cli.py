"""
cli.py — Command-line interface.

Uses argparse only (no third-party CLI dependency) so the tool runs anywhere
Python does. Entry points:

    llm-scan run --target stub --out ./reports
    llm-scan list-probes
    llm-scan version

``run`` produces the full deliverable set in ``--out``:
  report.json, report.html, model_card.md, risk_register.csv

and exits non-zero when findings at/above ``--fail-on`` are present, which is the
hook CI uses to block a release.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .engine import Scanner, available_categories, load_probes
from .governance import write_governance_package
from .models import Severity
from .providers import get_provider
from .reporting import summary_table, write_html_report, write_json_report

EXIT_OK = 0
EXIT_FINDINGS = 2  # threshold exceeded — distinct from generic error (1)
EXIT_ERROR = 1


def _print_summary(result, out_dir: Path) -> None:
    sc = result.severity_counts()
    print()
    print(f"Scan complete: target={result.target}  probes={result.total_probes}")
    print(f"Findings: {result.total_findings}  (pass rate {result.pass_rate:.0%})")
    print(
        "  Critical={CRITICAL}  High={HIGH}  Medium={MEDIUM}  Low={LOW}".format(**sc)
    )
    print()
    print("Artifacts written to", out_dir.resolve())
    for name in ("report.json", "report.html", "model_card.md", "risk_register.csv"):
        print(f"  - {out_dir / name}")
    print()


def cmd_run(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    categories = (
        [c.strip() for c in args.categories.split(",") if c.strip()]
        if args.categories
        else None
    )

    try:
        provider = get_provider(args.target)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        probes = load_probes(
            Path(args.probe_dir) if args.probe_dir else None, categories
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    scanner = Scanner(provider, probes=probes, scanner_version=__version__)
    result = scanner.run()

    write_json_report(result, out_dir / "report.json")
    write_html_report(result, out_dir / "report.html")
    if not args.no_governance:
        write_governance_package(result, out_dir)

    if not args.quiet:
        _print_summary(result, out_dir)

    # CI gate: fail if any finding is at/above the threshold.
    threshold = Severity.from_str(args.fail_on)
    highest = result.highest_severity()
    if highest is not None and highest.value >= threshold.value:
        if not args.quiet:
            print(
                f"FAIL: highest severity {highest.name} >= threshold "
                f"{threshold.name}.",
                file=sys.stderr,
            )
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_list_probes(args: argparse.Namespace) -> int:
    probe_dir = Path(args.probe_dir) if args.probe_dir else None
    try:
        probes = load_probes(probe_dir)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"{len(probes)} probes across {len(available_categories(probe_dir))} categories:\n")
    current = None
    for p in probes:
        if p.category != current:
            current = p.category
            print(f"[{p.category}]")
        print(f"  {p.id:<8} {p.severity.name:<8} {p.name}")
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    """Launch the offline report viewer (FastAPI) in the browser.

    Lazily imports uvicorn + the viewer so the core scanner keeps zero hard
    dependency on the web stack — install it with ``pip install ".[viewer]"``.
    """
    try:
        import uvicorn  # type: ignore
    except ImportError:
        print(
            "error: the report viewer needs FastAPI + uvicorn. Install with "
            '`pip install "llm-security-scanner[viewer]"` (or `pip install '
            "fastapi uvicorn`), then re-run `llm-scan serve`.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    print(
        f"LLM Security Scanner viewer → http://{args.host}:{args.port}\n"
        f"  Running a scan against target '{args.target}' on first request.\n"
        "  Press Ctrl+C to stop."
    )
    # Point the viewer at the requested target via the env var it reads.
    import os

    os.environ["LLM_SCAN_VIEWER_TARGET"] = args.target
    uvicorn.run(
        "llm_security_scanner.viewer:app",
        host=args.host,
        port=args.port,
        log_level="warning",
    )
    return EXIT_OK


def cmd_version(args: argparse.Namespace) -> int:
    print(f"llm-security-scanner {__version__}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-scan",
        description="Security-test an LLM endpoint and generate a governance package.",
    )
    parser.add_argument(
        "--version", action="version", version=f"llm-security-scanner {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="Run a scan and write the report + governance package.")
    run.add_argument(
        "--target",
        default="stub",
        help="Target to scan: 'stub' (offline, default) or 'openai' (uses OPENAI_API_KEY).",
    )
    run.add_argument(
        "--out",
        default="./reports",
        help="Output directory for artifacts (default: ./reports).",
    )
    run.add_argument(
        "--categories",
        default=None,
        help="Comma-separated subset of probe categories (default: all).",
    )
    run.add_argument(
        "--probe-dir",
        default=None,
        help="Custom directory of YAML probe packs (default: built-in packs).",
    )
    run.add_argument(
        "--fail-on",
        default="CRITICAL",
        help="Exit non-zero if a finding at/above this severity is present "
        "(CRITICAL/HIGH/MEDIUM/LOW). Default: CRITICAL.",
    )
    run.add_argument(
        "--no-governance",
        action="store_true",
        help="Skip generating the model card and risk register.",
    )
    run.add_argument("--quiet", action="store_true", help="Suppress summary output.")
    run.set_defaults(func=cmd_run)

    lst = sub.add_parser("list-probes", help="List the loaded probe battery.")
    lst.add_argument("--probe-dir", default=None, help="Custom probe pack directory.")
    lst.set_defaults(func=cmd_list_probes)

    srv = sub.add_parser(
        "serve",
        help="Launch the offline web report viewer (needs the [viewer] extra).",
    )
    srv.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    srv.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000).")
    srv.add_argument(
        "--target",
        default="stub",
        help="Target to scan for the demo: 'stub' (offline, default) or 'openai'.",
    )
    srv.set_defaults(func=cmd_serve)

    ver = sub.add_parser("version", help="Print version.")
    ver.set_defaults(func=cmd_version)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
