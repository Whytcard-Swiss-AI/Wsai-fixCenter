import json
import logging

import pytest

from fixcenter.diagnostics.base import DEFAULT_DIAGNOSTICS, Diagnostic
from fixcenter.engine import DiagnosticEngine, write_report
from fixcenter.models import Finding, Observation, Problem, Report


def test_rank_validation_and_no_findings(caplog):
    caplog.set_level(logging.INFO)
    low = Finding("low", "low", "low", 0.9, [], "", [], "test")
    high = Finding("high", "high", "high", 0.5, [], "", [], "test")
    engine = DiagnosticEngine(
        (Diagnostic("mixed", frozenset({"unknown"}), lambda _: [low, high]),)
    )
    report = engine.diagnose(Problem("valid"))
    assert [item.id for item in report.findings] == ["high", "low"]
    assert report.to_dict()["findings"][0] == high.to_dict()
    assert "diagnosis_complete" in caplog.text
    empty = DiagnosticEngine(()).diagnose(Problem("valid"))
    assert empty.warnings and empty.checks_run == []


def test_diagnostic_failure_is_isolated(caplog):
    def fail(_):
        raise RuntimeError("synthetic")

    report = DiagnosticEngine(
        (Diagnostic("bad", frozenset({"unknown"}), fail),)
    ).diagnose(Problem("valid"))
    assert report.findings == []
    assert "Diagnostic failed" in caplog.text


@pytest.mark.parametrize(
    "problem,error_type,message",
    [
        (Problem(""), ValueError, "empty"),
        (Problem("x" * 20_001), ValueError, "too long"),
        (Problem("x", logs=["x"] * 201), ValueError, "at most 200"),
        (Problem("x", logs=["x" * 20_001]), ValueError, "log entry"),
        (Problem("x", observations=[{}] * 101), ValueError, "at most 100"),
        (Problem("x", problem_type="other"), ValueError, "unsupported"),
        (Problem(3), TypeError, "description must be a string"),
        (Problem("x", problem_type=3), TypeError, "problem_type must be a string"),
        (Problem("x", logs=[3]), TypeError, "logs must be a list"),
        (Problem("x", observations=[3]), TypeError, "observations must be a list"),
    ],
)
def test_validation(problem, error_type, message):
    with pytest.raises(error_type, match=message):
        DiagnosticEngine().diagnose(problem)


def test_write_report_and_model_serialization(tmp_path):
    observation = Observation("os.identity", "ok", "done", "safe", 4)
    assert observation.to_dict()["duration_ms"] == 4
    report = Report("fixed", Problem("valid").to_dict(), [], [])
    path = write_report(report, tmp_path / "nested")
    assert path.name.endswith("-fixed.json")
    assert json.loads(path.read_text(encoding="utf-8"))["report_id"] == "fixed"
    sanitized = Problem("token=secret", logs=["user@example.com"]).to_dict()
    assert "secret" not in sanitized["description"]
    assert sanitized["logs"] == ["<EMAIL>"]


def test_each_diagnostic_has_unique_name():
    assert len({item.name for item in DEFAULT_DIAGNOSTICS}) == len(DEFAULT_DIAGNOSTICS)
