from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ProblemType = Literal["hook", "plugin", "skill", "config", "unknown"]


@dataclass
class Problem:
    description: str
    problem_type: ProblemType = "unknown"
    logs: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    components: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    workspace: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float
    evidence: list[str]
    explanation: str
    fixes: list[str]
    diagnostic: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    report_id: str
    problem: dict[str, Any]
    findings: list[Finding]
    checks_run: list[str]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "findings": [finding.to_dict() for finding in self.findings]}

