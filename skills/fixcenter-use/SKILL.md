---
name: fixcenter-use
description: Diagnose hooks, plugins, skills, MCP integrations, configuration, runtime, network, and PC control surfaces with WSAI FixCenter.
---

# Use WSAI FixCenter

Use this skill when a user reports a technical failure that may involve hooks, plugins, skills, MCP, local configuration, runtimes, networking, permissions, or system state.

## Privacy and control rules

- Start from user-supplied symptoms; do not collect the PC by default.
- Call `get_control_catalog` or `audit_coverage` before collection when scope is unclear.
- Call `collect_context` first with `execute=false` to show the exact plan.
- Execute probes only with explicit approval represented by both `execute=true` and `consent=true`.
- Keep `include_output=false` unless redacted output is necessary for the diagnosis.
- Never apply a proposed fix automatically. Ask before any mutation, installation, restart, permission change, deletion, or configuration edit.
- For multi-tool setup conflicts, hand off to the `fixcenter-setup` workflow; do not treat setup application as diagnostic collection.
- Treat a runtime coverage below 100% as incomplete observation, not as a healthy machine.

## Diagnostic workflow

1. Normalize the problem into `description`, `problem_type`, relevant logs and secret-free configuration fragments.
2. Call `diagnose` immediately on the supplied evidence.
3. Read findings in severity and confidence order.
4. Identify the smallest relevant controls from the 38-control catalog.
5. Plan those controls with `collect_context(execute=false)`.
6. If the user approves, run only those controls with strict redaction.
7. Add returned observations to a second `diagnose` call.
8. Distinguish confirmed evidence, probable causes, unknowns and proposed corrections.
9. Re-run the same controls after an authorized correction to verify the change.

## Tool selection

- `diagnose`: rank causes from a concrete problem.
- `list_diagnostics`: inspect the 15 registered rule families.
- `get_control_catalog`: choose controls without touching the host.
- `audit_coverage`: measure catalog design coverage only.
- `collect_context`: plan or explicitly run allowlisted read-only probes.
- `run_self_test`: validate the diagnostic engine using synthetic public cases.

## Completion standard

A diagnosis is complete only when the report states:

- what was directly observed;
- what remains inferred;
- which controls ran, failed, timed out, or were unavailable;
- the runtime coverage for the selected scope;
- the least invasive correction and how to verify it.
