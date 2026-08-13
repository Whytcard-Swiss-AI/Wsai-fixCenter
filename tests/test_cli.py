import json
import runpy
import sys

import fixcenter.cli as cli


def invoke(monkeypatch, capsys, *arguments):
    monkeypatch.setattr(sys, "argv", ["fixcenter", *arguments])
    cli.main()
    return capsys.readouterr().out.strip()


def test_catalog_coverage_self_test_and_collect(monkeypatch, capsys):
    assert json.loads(invoke(monkeypatch, capsys, "catalog"))["total"] == 38
    assert (
        json.loads(invoke(monkeypatch, capsys, "coverage", "--platform", "linux"))[
            "design_coverage_percent"
        ]
        == 100.0
    )
    assert (
        json.loads(invoke(monkeypatch, capsys, "self-test"))["success_rate_percent"]
        == 100.0
    )
    plan = json.loads(
        invoke(monkeypatch, capsys, "collect", "os.identity", "--platform", "darwin")
    )
    assert plan["observations"][0]["status"] == "planned"


def test_diagnose_from_stdin_file_and_report(monkeypatch, capsys, tmp_path):
    payload = json.dumps({"description": "Plugin not found", "problem_type": "plugin"})
    monkeypatch.setattr(
        sys, "stdin", type("Input", (), {"read": lambda self: payload})()
    )
    assert (
        json.loads(invoke(monkeypatch, capsys, "diagnose"))["findings"][0]["id"]
        == "component-missing"
    )
    source = tmp_path / "problem.json"
    source.write_text(payload, encoding="utf-8")
    output = invoke(
        monkeypatch, capsys, "diagnose", str(source), "--out", str(tmp_path / "reports")
    )
    assert output.endswith(".json")


def test_cli_serve_dispatch(monkeypatch):
    called = []
    monkeypatch.setattr(cli, "serve", lambda: called.append(True))
    monkeypatch.setattr(sys, "argv", ["fixcenter", "serve"])
    cli.main()
    assert called == [True]


def test_package_main_module(monkeypatch):
    called = []
    monkeypatch.setattr(cli, "main", lambda: called.append(True))
    runpy.run_module("fixcenter.__main__", run_name="__main__")
    assert called == [True]
