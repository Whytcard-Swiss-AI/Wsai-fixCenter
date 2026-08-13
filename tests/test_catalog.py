from fixcenter.catalog import (
    CONTROL_BY_ID,
    CONTROL_CATALOG,
    SUPPORTED_PLATFORMS,
    coverage_report,
)


def test_catalog_is_complete_for_supported_platforms():
    assert len(CONTROL_CATALOG) == 38
    assert len(CONTROL_BY_ID) == len(CONTROL_CATALOG)
    for control in CONTROL_CATALOG:
        assert set(control.probes) == set(SUPPORTED_PLATFORMS)
        assert all(
            probe.argv and probe.timeout_seconds > 0
            for probe in control.probes.values()
        )
        public = control.to_dict()
        detailed = control.to_dict(include_commands=True)
        assert public["probes"] == sorted(SUPPORTED_PLATFORMS)
        assert isinstance(detailed["probes"]["windows"]["argv"], list)


def test_coverage_report_supported_and_unknown_platform():
    for platform_name in SUPPORTED_PLATFORMS:
        report = coverage_report(platform_name.upper())
        assert report["design_coverage_percent"] == 100.0
        assert report["covered_controls"] == report["total_controls"] == 38
        assert sum(item["total"] for item in report["categories"].values()) == 38
    assert coverage_report("solaris")["design_coverage_percent"] == 0.0
