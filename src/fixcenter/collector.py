from __future__ import annotations

import platform
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from fixcenter.catalog import CONTROL_BY_ID, CONTROL_CATALOG, ProbeSpec, coverage_report
from fixcenter.models import Observation
from fixcenter.privacy import redact

Runner = Callable[..., subprocess.CompletedProcess[str]]


def current_platform() -> str:
    name = platform.system().lower()
    return (
        "darwin"
        if name == "darwin"
        else "windows"
        if name == "windows"
        else "linux"
        if name == "linux"
        else name
    )


@dataclass
class CollectionResult:
    platform: str
    executed: bool
    controls_requested: int
    controls_observed: int
    runtime_coverage_percent: float
    observations: list[Observation]
    privacy: str = "strict-redaction"

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "executed": self.executed,
            "controls_requested": self.controls_requested,
            "controls_observed": self.controls_observed,
            "runtime_coverage_percent": self.runtime_coverage_percent,
            "privacy": self.privacy,
            "observations": [item.to_dict() for item in self.observations],
        }


class SafeCollector:
    """Runs only catalogued read-only probes; caller input can never become a command."""

    def __init__(self, runner: Runner = subprocess.run) -> None:
        self._runner = runner

    def collect(
        self,
        control_ids: Sequence[str] | None = None,
        *,
        execute: bool = False,
        consent: bool = False,
        include_output: bool = False,
        platform_name: str | None = None,
    ) -> CollectionResult:
        target_platform = (platform_name or current_platform()).lower()
        selected = self._select(control_ids)
        if execute and not consent:
            raise ValueError("consent=true is required when execute=true")
        if execute and target_platform != current_platform():
            raise ValueError(
                f"cannot execute {target_platform} probes on a {current_platform()} host"
            )
        observations = [
            self._observe(control, target_platform, execute, include_output)
            for control in selected
        ]
        observed = sum(item.status == "ok" for item in observations) if execute else 0
        percent = round(observed * 100 / len(selected), 2) if selected else 0.0
        return CollectionResult(
            target_platform, execute, len(selected), observed, percent, observations
        )

    @staticmethod
    def design_coverage(platform_name: str | None = None) -> dict[str, Any]:
        return coverage_report(platform_name or current_platform())

    @staticmethod
    def _select(control_ids: Sequence[str] | None):
        if control_ids is None:
            return list(CONTROL_CATALOG)
        if len(control_ids) > len(CONTROL_CATALOG):
            raise ValueError(
                f"control_ids must contain at most {len(CONTROL_CATALOG)} entries"
            )
        unknown = sorted(set(control_ids) - CONTROL_BY_ID.keys())
        if unknown:
            raise ValueError(f"unknown controls: {', '.join(unknown)}")
        return [CONTROL_BY_ID[control_id] for control_id in dict.fromkeys(control_ids)]

    def _observe(
        self, control, target_platform: str, execute: bool, include_output: bool
    ) -> Observation:
        probe: ProbeSpec | None = control.probes.get(target_platform)
        if probe is None:
            return Observation(
                control.id,
                "unavailable",
                f"No probe is defined for platform '{target_platform}'.",
            )
        if not execute:
            return Observation(
                control.id,
                "planned",
                f"Read-only probe available for {target_platform}.",
            )
        started = time.monotonic()
        try:
            completed = self._runner(
                list(probe.argv),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=probe.timeout_seconds,
                shell=False,
                check=False,
            )
            duration = round((time.monotonic() - started) * 1000)
            combined = "\n".join(
                part for part in (completed.stdout, completed.stderr) if part
            ).strip()
            status = "ok" if completed.returncode == 0 else "nonzero"
            summary = f"Probe completed with exit code {completed.returncode}."
            return Observation(
                control.id,
                status,
                summary,
                redact(combined) if include_output else None,
                duration,
            )
        except FileNotFoundError:
            return Observation(
                control.id,
                "unavailable",
                f"Probe executable is unavailable: {probe.argv[0]}.",
            )
        except subprocess.TimeoutExpired:
            duration = round((time.monotonic() - started) * 1000)
            return Observation(
                control.id,
                "timeout",
                f"Probe exceeded {probe.timeout_seconds}s.",
                duration_ms=duration,
            )
        except OSError as exc:
            return Observation(
                control.id, "error", f"Probe failed safely: {type(exc).__name__}."
            )
