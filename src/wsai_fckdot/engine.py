from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from wsai_fckdot.diagnostics.base import DEFAULT_DIAGNOSTICS, Diagnostic
from wsai_fckdot.models import Finding, Problem, Report

LOGGER = logging.getLogger("wsai_fckdot")


class DiagnosticEngine:
    def __init__(self, diagnostics: Iterable[Diagnostic] = DEFAULT_DIAGNOSTICS) -> None:
        self.diagnostics = tuple(diagnostics)

    def diagnose(self, problem: Problem) -> Report:
        self._validate(problem)
        findings: list[Finding] = []
        checks_run: list[str] = []
        for diagnostic in self.diagnostics:
            if problem.problem_type not in diagnostic.supported_types:
                continue
            checks_run.append(diagnostic.name)
            try:
                findings.extend(diagnostic.run(problem))
            except Exception:
                LOGGER.exception("Diagnostic failed: %s", diagnostic.name)
        findings.sort(
            key=lambda item: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[
                    item.severity
                ],
                -item.confidence,
            )
        )
        warnings = (
            [
                "Aucun finding déclenché: collecter davantage de logs et de configuration sûre."
            ]
            if not findings
            else []
        )
        report = Report(str(uuid4()), problem.to_dict(), findings, checks_run, warnings)
        LOGGER.info(
            "diagnosis_complete report_id=%s checks=%s findings=%s",
            report.report_id,
            len(checks_run),
            len(findings),
        )
        return report

    @staticmethod
    def _validate(problem: Problem) -> None:
        allowed_types = {
            "hook",
            "plugin",
            "skill",
            "config",
            "system",
            "network",
            "runtime",
            "security",
            "integration",
            "codex",
            "unknown",
        }
        if not isinstance(problem.description, str):
            raise TypeError("description must be a string")
        if not isinstance(problem.problem_type, str):
            raise TypeError("problem_type must be a string")
        if problem.problem_type not in allowed_types:
            raise ValueError(f"unsupported problem_type: {problem.problem_type}")
        if not problem.description.strip():
            raise ValueError("description must not be empty")
        if len(problem.description) > 20_000:
            raise ValueError("description is too long")
        if not isinstance(problem.logs, list) or any(
            not isinstance(line, str) for line in problem.logs
        ):
            raise TypeError("logs must be a list of strings")
        if len(problem.logs) > 200:
            raise ValueError("logs must contain at most 200 entries")
        if any(len(line) > 20_000 for line in problem.logs):
            raise ValueError("a log entry is too long")
        if not isinstance(problem.observations, list) or any(
            not isinstance(item, dict) for item in problem.observations
        ):
            raise TypeError("observations must be a list of objects")
        if len(problem.observations) > 100:
            raise ValueError("observations must contain at most 100 entries")


def write_report(report: Report, directory: str | Path) -> Path:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    path = (
        target
        / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{report.report_id}.json"
    )
    path.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return path
