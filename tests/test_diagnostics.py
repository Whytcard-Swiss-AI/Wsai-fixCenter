import pytest

from fixcenter.diagnostics.base import DEFAULT_DIAGNOSTICS
from fixcenter.engine import DiagnosticEngine
from fixcenter.evaluation import CASES, run_evaluation
from fixcenter.models import Problem


def test_synthetic_evaluation_is_perfect():
    result = run_evaluation()
    assert result["passed"] == result["total"] == len(CASES)
    assert result["success_rate_percent"] == 100.0


@pytest.mark.parametrize("diagnostic", DEFAULT_DIAGNOSTICS)
def test_every_diagnostic_has_a_negative_path(diagnostic):
    assert diagnostic.run(Problem("ordinary successful operation", "unknown")) == []


def test_evaluation_can_report_a_failure():
    result = run_evaluation(DiagnosticEngine(()))
    assert result["success_rate_percent"] < 100
    assert any(not item["passed"] for item in result["results"])


def test_config_shape_accepts_valid_and_empty_config():
    engine = DiagnosticEngine()
    assert "config-shape" not in {
        item.id for item in engine.diagnose(Problem("valid", config={})).findings
    }
    assert "config-shape" not in {
        item.id
        for item in engine.diagnose(Problem("valid", config={"skills": []})).findings
    }


def test_observation_rule_ignores_success_and_caps_evidence():
    engine = DiagnosticEngine()
    assert not engine.diagnose(
        Problem("valid", observations=[{"control_id": "x", "status": "ok"}])
    ).findings
    observations = [{"control_id": f"x{i}", "status": "error"} for i in range(10)]
    finding = engine.diagnose(Problem("valid", observations=observations)).findings[0]
    assert "x7" in finding.evidence[0] and "x8" not in finding.evidence[0]
