import json
import runpy
import sys

from wsai_fckdot import cli


def invoke(monkeypatch, capsys, *arguments):
    monkeypatch.setattr(sys, "argv", ["wsai_fckdot", *arguments])
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
    monkeypatch.setattr(sys, "argv", ["wsai_fckdot", "serve"])
    cli.main()
    assert called == [True]


def test_setup_cli_workflow(monkeypatch, capsys, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = tmp_path / "setup.json"
    source.write_text(
        json.dumps(
            {
                "version": 1,
                "active_profile": "personal",
                "profiles": {"personal": {"variables": {}}},
                "instructions": ["Write tests."],
                "tools": ["agents"],
            }
        ),
        encoding="utf-8",
    )
    assert (
        json.loads(invoke(monkeypatch, capsys, "setup-catalog"))["manifest_version"]
        == 1
    )
    inventory = json.loads(
        invoke(
            monkeypatch,
            capsys,
            "setup-inventory",
            str(workspace),
            "--consent",
            "--include-home",
            "--include-unknown-names",
        )
    )
    assert inventory["workspace"]["unknown_dot_directory_count"] == 0
    plan = json.loads(
        invoke(
            monkeypatch,
            capsys,
            "setup-plan",
            str(workspace),
            str(source),
            "--consent",
        )
    )
    applied = json.loads(
        invoke(
            monkeypatch,
            capsys,
            "setup-apply",
            str(workspace),
            str(source),
            plan["plan_id"],
            "--consent",
        )
    )
    assert applied["applied"] is True


def test_package_main_module(monkeypatch):
    called = []
    monkeypatch.setattr(cli, "main", lambda: called.append(True))
    runpy.run_module("wsai_fckdot.__main__", run_name="__main__")
    assert called == [True]
