---
name: fixcenter-setup
description: Inventory and consolidate messy multi-agent project setup, dot-directories, account profiles, environment references and conflicting instructions with WSAI FixCenter.
---

# Govern agent setup with WSAI FixCenter

Use this skill when a user has accumulated configuration from many AI tools, sees conflicting instructions or variables, changes accounts often, or wants one repeatable setup across tools.

## Non-negotiable safety rules

- Start with `get_setup_catalog`; it touches no machine data.
- Inspect only an explicitly selected absolute workspace path.
- Set `include_home=false` unless the user explicitly asks to include home-level metadata.
- Keep `include_unknown_names=false` unless names are necessary for the diagnosis.
- Never request, accept or store tokens, passwords, cookies or credential values in a setup manifest.
- Profiles may contain only labels and `env:VARIABLE` references.
- Never edit or remove `.xxx` directories directly as part of this workflow.
- Always call `plan_setup` before `apply_setup`.
- Show blocked paths and every planned create/update/retire action to the user.
- Call `apply_setup` only after explicit approval, using the exact unchanged manifest and returned `plan_id` with `consent=true`.
- If a user-owned file blocks the plan, preserve it and explain how to reconcile it manually.

## Guided workflow

1. Explain in plain language that FixCenter will create one source of truth and generated adapters, not erase tool folders.
2. Call `get_setup_catalog`.
3. Call `inspect_setup` with metadata consent for the selected workspace.
4. Summarize known tool surfaces, unknown count, instruction layers and environment-variable names. Never claim values were inspected.
5. Build a manifest with:
   - short, non-conflicting canonical instructions;
   - one named profile per account context;
   - only environment-variable references;
   - the smallest relevant adapter set.
6. Call `plan_setup` and present its actions.
7. If blocked, stop and resolve ownership with the user. Do not bypass the guard.
8. After explicit approval, call `apply_setup` with the exact plan ID.
9. Tell the user how to activate the selected generated `.ps1` or `.sh` profile and restart active agent sessions.
10. Re-run `inspect_setup` and `plan_setup`; completion means managed adapters are synchronized and no action remains except `unchanged`.

## Profile switching

To switch accounts, change only `active_profile`, plan again and apply the new plan. Then activate the matching script in a fresh or current shell. The scripts clear all declared target variables before mapping the selected references, preventing cross-account variable residue.

## Completion report

State separately:

- what metadata was observed;
- which files FixCenter created, updated or retired to recoverable storage;
- which user-owned files were preserved;
- which account profile is active;
- whether any unknown tool surfaces remain;
- whether agent sessions must be restarted.
