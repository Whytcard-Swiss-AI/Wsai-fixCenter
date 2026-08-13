# Security and privacy

FixCenter is local-first and read-only by design.

## Collection guardrails

- Collection defaults to planning only.
- Execution requires both `execute=true` and `consent=true`.
- Commands are immutable entries in the public catalog. User input is never interpolated into a command.
- Subprocesses run with `shell=false`, a fixed timeout and no privilege escalation.
- Output is omitted by default.
- Requested output passes through strict redaction and an 8,000-character limit.
- The server has no network client and sends no telemetry.
- Reports and local `.fixcenter` data are ignored by Git.

## Redaction

The default redactor masks common credentials, bearer values, email addresses, user home paths, IPv4 addresses, usernames and hostnames. Redaction reduces exposure but cannot guarantee that arbitrary application output contains no private data. Review any report before sharing it.

## Non-goals

FixCenter does not remediate automatically, bypass policy, elevate privileges, install packages, stop processes, restart services, change firewall rules, edit the registry, or upload reports.

## Reporting a vulnerability

Do not open a public issue containing secrets, private logs or personal paths. Open a minimal report that uses synthetic examples and identifies the affected version and control ID.
