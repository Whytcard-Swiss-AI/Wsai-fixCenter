import subprocess

import pytest

import wsai_fckdot.collector as module
from wsai_fckdot.catalog import CONTROL_CATALOG
from wsai_fckdot.collector import SafeCollector, current_platform


def completed(argv, **_):
    return subprocess.CompletedProcess(
        argv, 0, "token=secret user@example.com 10.0.0.1", ""
    )


def test_plan_and_successful_collection_are_separate():
    collector = SafeCollector(completed)
    host_platform = current_platform()
    full_plan = collector.collect(platform_name=host_platform)
    assert full_plan.controls_requested == len(CONTROL_CATALOG)
    plan = collector.collect(["os.identity"], platform_name=host_platform)
    assert plan.executed is False and plan.runtime_coverage_percent == 0.0
    assert plan.observations[0].status == "planned"
    run = collector.collect(
        ["os.identity"],
        platform_name=host_platform,
        execute=True,
        consent=True,
        include_output=True,
    )
    data = run.to_dict()
    assert data["runtime_coverage_percent"] == 100.0 and data["controls_observed"] == 1
    assert "secret" not in data["observations"][0]["output"]


def test_success_without_output_and_duplicate_selection():
    result = SafeCollector(completed).collect(
        ["os.identity", "os.identity"],
        platform_name=current_platform(),
        execute=True,
        consent=True,
    )
    assert result.controls_requested == 1 and result.observations[0].output is None


def test_nonzero_probe():
    def runner(argv, **_):
        return subprocess.CompletedProcess(argv, 2, "", "failed")

    result = SafeCollector(runner).collect(
        ["os.identity"],
        platform_name=current_platform(),
        execute=True,
        consent=True,
        include_output=True,
    )
    assert result.observations[0].status == "nonzero"
    assert result.runtime_coverage_percent == 0.0


@pytest.mark.parametrize(
    "exception,status",
    [
        (FileNotFoundError(), "unavailable"),
        (subprocess.TimeoutExpired("probe", 1), "timeout"),
        (OSError("synthetic"), "error"),
    ],
)
def test_safe_probe_failures(exception, status):
    def runner(*_, **__):
        raise exception

    item = (
        SafeCollector(runner)
        .collect(
            ["os.identity"],
            platform_name=current_platform(),
            execute=True,
            consent=True,
        )
        .observations[0]
    )
    assert item.status == status


def test_selection_and_consent_validation():
    with pytest.raises(ValueError, match="consent"):
        SafeCollector().collect(["os.identity"], execute=True)
    with pytest.raises(ValueError, match="unknown"):
        SafeCollector().collect(["nope"])
    with pytest.raises(ValueError, match="at most"):
        SafeCollector().collect(["os.identity"] * (len(CONTROL_CATALOG) + 1))
    empty = SafeCollector().collect([], platform_name="windows")
    assert empty.controls_requested == 0 and empty.runtime_coverage_percent == 0.0


def test_unknown_platform_is_unavailable(monkeypatch):
    monkeypatch.setattr(module, "current_platform", lambda: "solaris")
    result = SafeCollector().collect(
        ["os.identity"], platform_name="solaris", execute=True, consent=True
    )
    assert result.observations[0].status == "unavailable"


def test_execution_rejects_a_different_host_platform():
    other = "darwin" if current_platform() != "darwin" else "linux"
    with pytest.raises(ValueError, match="cannot execute"):
        SafeCollector().collect(
            ["os.identity"], platform_name=other, execute=True, consent=True
        )


def test_design_coverage_and_platform_normalization(monkeypatch):
    assert SafeCollector.design_coverage("windows")["design_coverage_percent"] == 100.0
    for source, expected in (
        ("Windows", "windows"),
        ("Darwin", "darwin"),
        ("Linux", "linux"),
        ("Plan9", "plan9"),
    ):
        monkeypatch.setattr(module.platform, "system", lambda value=source: value)
        assert current_platform() == expected
    monkeypatch.setattr(module, "current_platform", lambda: "windows")
    assert SafeCollector.design_coverage()["platform"] == "windows"
