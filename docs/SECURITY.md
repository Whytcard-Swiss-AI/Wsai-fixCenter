# Security and privacy

wsai_fckdot is local-first. Diagnostics and setup inspection are read-only by design; its narrow setup writer is separately consent-gated and ownership-aware.

## Collection guardrails

- Collection defaults to planning only.
- Execution requires both `execute=true` and `consent=true`.
- Commands are immutable entries in the public catalog. User input is never interpolated into a command.
- Subprocesses run with `shell=false`, a fixed timeout and no privilege escalation.
- Output is omitted by default.
- Requested output passes through tested pattern-based redaction and an 8,000-character limit.
- The server has no network client and sends no telemetry.
- Reports and local `.wsai_fckdot` data are ignored by Git.

## Setup write guardrails

- Setup inventory returns metadata, exact generated-ownership status and selected environment-variable names, never variable values or instruction contents; setup symlinks are reported without being followed.
- Unknown dot-directory names are hidden unless explicitly requested.
- Manifests reject common credential-shaped text and accept only `env:VARIABLE` account bindings. Pattern detection cannot identify every arbitrary secret, so free-form instructions still require user review.
- `plan_setup` is read-only and requires metadata consent.
- `apply_setup` requires explicit consent, the unchanged manifest and the exact current `plan_id`.
- Application uses an exclusive workspace lock, rechecks every target immediately before mutation and creates new files with no-overwrite semantics.
- Application is refused at the filesystem root and user home.
- Adapter paths are fixed by the public registry; caller-provided paths cannot become write targets.
- Symlinked paths, oversized files, directories at file targets and user-owned files are blocked.
- Existing wsai_fckdot-managed files are moved atomically to recoverable storage before an exclusive no-overwrite replacement is created.
- If a write fails and targets still match wsai_fckdot's transaction state, changed files are restored or removed. Concurrent third-party files are preserved, and displaced originals remain in recoverable storage rather than being overwritten.
- Profile scripts validate every source before clearing targets, copy credential values only inside the current process environment and never write those values to disk.

## Redaction

The default redactor masks common credentials, bearer values, email addresses, user home paths, IPv4 addresses, usernames and hostnames. Redaction reduces exposure but cannot guarantee that arbitrary application output contains no private data. Review any report before sharing it.

## Non-goals

wsai_fckdot does not remediate system findings automatically, bypass policy, elevate privileges, install packages, stop processes, restart services, change firewall rules, edit the registry, delete or move tool directories, write global/home setup, or upload reports. Its only mutation surface is an explicitly approved workspace setup plan containing fixed adapter paths.

## Reporting a vulnerability

Do not open a public issue containing secrets, private logs or personal paths. Open a minimal report that uses synthetic examples and identifies the affected version and control ID.
