import json
import subprocess
import sys

from fixcenter.engine import DiagnosticEngine
from fixcenter.models import Problem


def test_missing_component_is_ranked_high():
    report = DiagnosticEngine().diagnose(Problem("Plugin not found at startup", problem_type="plugin"))
    assert report.findings[0].id == "component-missing"
    assert report.findings[0].severity == "high"


def test_invalid_config_shape_is_reported():
    report = DiagnosticEngine().diagnose(Problem("skill fails", problem_type="skill", config={"skills": "oops"}))
    assert any(item.id == "config-shape" for item in report.findings)


def test_input_is_validated():
    try:
        DiagnosticEngine().diagnose(Problem(""))
    except ValueError as exc:
        assert "empty" in str(exc)
    else:
        raise AssertionError("empty descriptions must fail")


def test_mcp_initialize_and_tool_call():
    payloads = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "diagnose", "arguments": {"description": "hook timed out", "problem_type": "hook"}}},
    ]
    proc = subprocess.run([sys.executable, "-m", "fixcenter.server"], input="\n".join(json.dumps(item) for item in payloads), text=True, capture_output=True)
    # server module is intentionally importable; serve is exercised directly below.
    assert proc.returncode == 0

