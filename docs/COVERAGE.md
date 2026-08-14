# Coverage model

wsai_fckdot uses two deliberately separate coverage metrics.

## Design coverage

`design_coverage_percent` is the percentage of controls in the public catalog that have an allowlisted, read-only probe for a target platform. Catalog v1 contains 38 controls in 12 domains. Every control has a Windows, Linux and macOS probe, so design coverage is 100% for those three platforms.

This proves completeness against the declared catalog. It does not prove that a particular machine was inspected, that every third-party application is known, or that every probe will be permitted by local policy.

## Runtime coverage

`runtime_coverage_percent` is the percentage of requested controls that completed successfully during one explicit collection. Planned, unavailable, timed-out, error and non-zero probes do not count as observed.

A runtime score of 100% proves that every selected control returned successfully. It does not prove that the PC has no defect. The report's findings still determine what the evidence means.

## Catalog domains

| Domain | Covered surfaces |
| --- | --- |
| system | OS identity, time and locale |
| hardware | compute resources, device health |
| storage | mounted volumes and capacity |
| runtime | processes, services, startup, scheduled tasks |
| configuration | environment names, executable search path |
| observability | system log availability |
| network | adapters, DNS, proxy, listeners |
| security | permissions, firewall, certificates, protection, execution policies |
| tooling | package managers, language runtimes, shells, Git, editors |
| agents | MCP clients, hooks, plugins, skills, Codex runtime, remote-control prerequisites, chat streaming and configuration layers |
| virtualization | containers and guest environments |
| maintenance | update visibility |

## Honest boundary

No finite public catalog can prove coverage of every future peripheral, proprietary application, kernel extension or organization-specific control. New controls can be added without weakening the metric: each catalog release is versioned, and 100% requires a probe for every declared control on every supported platform.
