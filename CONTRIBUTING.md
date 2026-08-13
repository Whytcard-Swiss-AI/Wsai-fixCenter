# Contributing

Changes must preserve the read-only and privacy boundaries.

1. Add or update a catalog control with probes for Windows, Linux and macOS.
2. Do not interpolate user input into probe commands.
3. Add synthetic tests; never commit real machine output.
4. Run `python -m fixcenter self-test` and the full test suite.
5. Update `docs/COVERAGE.md` when the catalog definition changes.

A new diagnostic needs a stable finding ID, evidence, explanation, least-invasive fixes, a registry entry and at least one positive and one negative test.

A setup adapter lives in `fixcenter.setup_manager` and must use a fixed workspace-relative path, carry a generated ownership marker, contain no credential values, preserve user-owned files, and include create/update/conflict, profile-switching and cross-platform tests. Never add an adapter that writes directly to a user home directory.
