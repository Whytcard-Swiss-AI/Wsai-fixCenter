from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fixcenter.engine import DiagnosticEngine
from fixcenter.models import Problem


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    problem: Problem
    expected: frozenset[str]


CASES = (
    EvaluationCase(
        "missing plugin",
        Problem("Plugin not found", "plugin"),
        frozenset({"component-missing"}),
    ),
    EvaluationCase(
        "invalid skill config",
        Problem("Skill ignored", "skill", config={"skills": "bad"}),
        frozenset({"config-shape"}),
    ),
    EvaluationCase(
        "hook timeout",
        Problem("Hook timed out after previous hook", "hook"),
        frozenset({"hook-order"}),
    ),
    EvaluationCase(
        "permission",
        Problem("Access denied while loading configuration", "config"),
        frozenset({"permission-denied"}),
    ),
    EvaluationCase(
        "dependency",
        Problem("Dependency conflict: incompatible version", "runtime"),
        frozenset({"dependency-conflict"}),
    ),
    EvaluationCase(
        "authentication",
        Problem("API returned 401 unauthorized", "integration"),
        frozenset({"authentication-failed"}),
    ),
    EvaluationCase(
        "network",
        Problem("DNS ENOTFOUND for registry", "network"),
        frozenset({"network-path"}),
    ),
    EvaluationCase(
        "protocol",
        Problem("JSONRPC invalid params -32602", "integration"),
        frozenset({"protocol-schema"}),
    ),
    EvaluationCase(
        "duplicate",
        Problem("Plugin already registered", "plugin"),
        frozenset({"duplicate-registration"}),
    ),
    EvaluationCase(
        "path",
        Problem("python is not recognized as a command", "runtime"),
        frozenset({"path-resolution"}),
    ),
    EvaluationCase(
        "crash",
        Problem("Traceback: unhandled exception", "runtime"),
        frozenset({"runtime-crash"}),
    ),
    EvaluationCase(
        "observation",
        Problem(
            "System check",
            "system",
            observations=[{"control_id": "network.dns", "status": "timeout"}],
        ),
        frozenset({"observation-incomplete"}),
    ),
    EvaluationCase(
        "clean",
        Problem("Request for inspection with no failure signal", "unknown"),
        frozenset(),
    ),
    EvaluationCase(
        "remote control",
        Problem("Unable to update remote control availability", "codex"),
        frozenset({"remote-control-state"}),
    ),
    EvaluationCase(
        "chat stream",
        Problem("Error creating chat: conversation is not being streamed", "codex"),
        frozenset({"conversation-stream"}),
    ),
    EvaluationCase(
        "hook source",
        Problem("User configuration hook problem in plugin", "codex"),
        frozenset({"hook-source-health"}),
    ),
)


def run_evaluation(engine: DiagnosticEngine | None = None) -> dict[str, Any]:
    active_engine = engine or DiagnosticEngine()
    results = []
    passed = 0
    for case in CASES:
        actual = frozenset(
            item.id for item in active_engine.diagnose(case.problem).findings
        )
        success = case.expected.issubset(actual) and (bool(case.expected) or not actual)
        passed += int(success)
        results.append(
            {
                "name": case.name,
                "passed": success,
                "expected": sorted(case.expected),
                "actual": sorted(actual),
            }
        )
    return {
        "suite_version": "1.0",
        "total": len(CASES),
        "passed": passed,
        "success_rate_percent": round(passed * 100 / len(CASES), 2),
        "results": results,
    }
