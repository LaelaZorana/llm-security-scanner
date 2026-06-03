"""End-to-end CLI tests via the argparse entry point."""

import sys

from llm_security_scanner.cli import (
    EXIT_FINDINGS,
    EXIT_OK,
    build_parser,
    main,
)


def test_cli_run_writes_all_artifacts(tmp_path):
    out = tmp_path / "reports"
    # Default --fail-on CRITICAL and the stub leaks a token -> exit code 2.
    code = main(["run", "--target", "stub", "--out", str(out), "--quiet"])
    assert code == EXIT_FINDINGS
    for name in ("report.json", "report.html", "model_card.md", "risk_register.csv"):
        assert (out / name).exists(), f"{name} not generated"


def test_cli_run_fail_on_low_still_fails(tmp_path):
    out = tmp_path / "reports"
    code = main(["run", "--target", "stub", "--out", str(out), "--quiet", "--fail-on", "LOW"])
    assert code == EXIT_FINDINGS


def test_cli_run_no_governance_skips_files(tmp_path):
    out = tmp_path / "reports"
    main(["run", "--target", "stub", "--out", str(out), "--quiet", "--no-governance"])
    assert (out / "report.json").exists()
    assert not (out / "model_card.md").exists()
    assert not (out / "risk_register.csv").exists()


def test_cli_run_single_category(tmp_path):
    out = tmp_path / "reports"
    # toxic_content: the stub refuses both probes -> no findings -> exit 0.
    code = main(
        [
            "run",
            "--target",
            "stub",
            "--out",
            str(out),
            "--quiet",
            "--categories",
            "toxic_content",
        ]
    )
    assert code == EXIT_OK


def test_cli_unknown_target_errors(tmp_path):
    code = main(["run", "--target", "bogus", "--out", str(tmp_path), "--quiet"])
    assert code == 1


def test_cli_list_probes(capsys):
    code = main(["list-probes"])
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "prompt_injection" in out


def test_cli_no_command_prints_help(capsys):
    code = main([])
    assert code == EXIT_OK
    assert "usage" in capsys.readouterr().out.lower()


def test_cli_serve_is_registered():
    """The `serve` subcommand parses and binds to its handler (without running
    a server)."""
    args = build_parser().parse_args(
        ["serve", "--host", "0.0.0.0", "--port", "9001", "--target", "stub"]
    )
    assert args.command == "serve"
    assert args.host == "0.0.0.0"
    assert args.port == 9001
    assert hasattr(args, "func")


def test_cli_serve_runs_uvicorn(monkeypatch):
    """`serve` should hand off to uvicorn.run with the viewer app; we stub the
    server so the test never binds a port."""
    import types

    calls = {}

    fake_uvicorn = types.ModuleType("uvicorn")

    def fake_run(app, host, port, **kwargs):  # noqa: ANN001
        calls["app"] = app
        calls["host"] = host
        calls["port"] = port

    fake_uvicorn.run = fake_run
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)

    code = main(["serve", "--port", "9002"])
    assert code == EXIT_OK
    assert calls["app"] == "llm_security_scanner.viewer:app"
    assert calls["port"] == 9002
