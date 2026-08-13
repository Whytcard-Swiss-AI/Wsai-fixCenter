# Contributing

Changes must preserve the read-only and privacy boundaries.

1. Add or update a catalog control with probes for Windows, Linux and macOS.
2. Do not interpolate user input into probe commands.
3. Add synthetic tests; never commit real machine output.
4. Run `python -m fixcenter self-test` and the full test suite.
5. Update `docs/COVERAGE.md` when the catalog definition changes.

A new diagnostic needs a stable finding ID, evidence, explanation, least-invasive fixes, a registry entry and at least one positive and one negative test.
