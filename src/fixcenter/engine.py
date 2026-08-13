from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from fixcenter.diagnostics.base import DEFAULT_DIAGNOSTICS, Diagnostic
from fixcenter.models import Finding, Problem, Report

LOGGER = logging.getLogger("fixcenter")


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
        findings.sort(key=lambda item: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[item.severity], -item.confidence))
        warnings = ["Aucun finding déclenché: collecter davantage de logs et de configuration sûre."] if not findings else []
        report = Report(str(uuid4()), problem.to_dict(), findings, checks_run, warnings)
        LOGGER.info("diagnosis_complete report_id=%s checks=%s findings=%s", report.report_id, len(checks_run), len(findings))
        return report

    @staticmethod
    def _validate(problem: Problem) -> None:
        if not problem.description.strip():
            raise ValueError("description must not be empty")
        if len(problem.description) > 20_000:
            raise ValueError("description is too long")
        if len(problem.logs) > 200:
            raise ValueError("logs must contain at most 200 entries")
        if any(len(line) > 20_000 for line in problem.logs):
            raise ValueError("a log entry is too long")


def write_report(report: Report, directory: str | Path) -> Path:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{report.report_id}.json"
    path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return path

