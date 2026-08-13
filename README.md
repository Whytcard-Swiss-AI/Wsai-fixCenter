# WSAI FixCenter

WSAI FixCenter is a public, privacy-first MCP server for diagnosing hooks, plugins, skills, MCP integrations, configuration, runtimes, networking and PC system state. It combines ranked probable causes with a consent-gated catalog of read-only controls for Windows, Linux and macOS.

It never repairs a machine automatically, never interpolates user input into commands, never elevates privileges, and never sends telemetry.

## Verified scope

- 38 read-only controls in 12 domains;
- 100% catalog design coverage on Windows, Linux and macOS;
- 15 diagnostic rule families;
- 16 synthetic evaluation cases with a 100% success gate;
- 6 MCP tools;
- 100% Python statement coverage enforced in CI;
- strict output redaction and explicit execution consent.
- compatibility with both legacy MCP handshakes and the stateless `2026-07-28` era.

The meaning of “100%” is precise. Design coverage means every declared catalog control has a probe on every supported platform. Runtime coverage means every requested probe completed successfully on one execution. Neither metric claims that every possible future application or peripheral is known. See [the coverage model](docs/COVERAGE.md).

## MCP tools

| Tool | Purpose | Reads the PC by default? |
| --- | --- | --- |
| `diagnose` | Rank causes and propose least-invasive corrections | No |
| `list_diagnostics` | List the 15 diagnostic rule families | No |
| `get_control_catalog` | Browse the 38 controls | No |
| `audit_coverage` | Measure catalog design coverage | No |
| `collect_context` | Plan or execute selected read-only probes | Plan only |
| `run_self_test` | Run public synthetic regression cases | No |

`collect_context` executes only when both `execute=true` and `consent=true`. Output is excluded unless `include_output=true`, and included output is strictly redacted and truncated.

## Covered domains

System identity, time and locale; CPU, memory and devices; storage; processes, services, startup and scheduled tasks; environment and PATH; log availability; adapters, DNS, proxy and listeners; permissions, firewall, certificates, protection and policies; package managers, language runtimes, shells, Git and editors; MCP, hooks, plugins, skills, Codex runtime, remote-control prerequisites and chat streaming; containers and guest environments; update visibility.

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/Whytcard-Swiss-AI/Wsai-fixCenter.git
cd Wsai-fixCenter
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install -e .
python -m fixcenter self-test
```

For development:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

## MCP configuration

Use the virtual environment's absolute Python executable:

```json
{
  "mcpServers": {
    "wsai-fixcenter": {
      "command": "/absolute/path/to/Wsai-fixCenter/.venv/bin/python",
      "args": ["-m", "fixcenter", "serve"],
      "cwd": "/absolute/path/to/Wsai-fixCenter"
    }
  }
}
```

On Windows, `command` normally ends in `.venv\\Scripts\\python.exe`.

See [MCP compatibility](docs/MCP_COMPATIBILITY.md) for protocol versions and wire behavior.

## Safe workflow

First diagnose only the evidence already available:

```json
{
  "description": "The deploy hook is not found after enabling the plugin",
  "problem_type": "hook",
  "logs": ["ERROR hook deploy: not found"],
  "config": {"hooks": [{"name": "deploy"}]},
  "components": ["release-tools", "deploy"]
}
```

Then inspect the catalog or plan a narrow collection:

```json
{
  "control_ids": ["agents.hooks", "agents.plugins", "environment.path"],
  "platform": "windows",
  "execute": false
}
```

After the user explicitly approves those exact controls:

```json
{
  "control_ids": ["agents.hooks", "agents.plugins", "environment.path"],
  "platform": "windows",
  "execute": true,
  "consent": true,
  "include_output": false
}
```

Add the returned observations to a second `diagnose` call. A failed or unavailable probe becomes an explicit `observation-incomplete` finding.

## CLI

```bash
python -m fixcenter catalog
python -m fixcenter coverage --platform windows
python -m fixcenter collect agents.hooks agents.plugins --platform windows
python -m fixcenter collect agents.hooks --platform windows --execute --consent
python -m fixcenter diagnose problem.json --out reports
python -m fixcenter self-test
```

The first `collect` command only produces a plan. The second explicitly executes one allowlisted probe and still omits output.

## Agent skills

Two reusable public skills are included:

- [`fixcenter-install`](skills/fixcenter-install/SKILL.md) installs and verifies the MCP without collecting machine data;
- [`fixcenter-use`](skills/fixcenter-use/SKILL.md) guides diagnosis, consent, narrow collection and post-fix verification.

## Extending FixCenter

Controls live in `fixcenter.catalog`; diagnostics live in `fixcenter.diagnostics`. Every new control needs Windows, Linux and macOS probes, synthetic tests and an updated catalog version. Every new diagnostic needs a stable ID, evidence, explanation, safe fixes and positive/negative evaluation cases. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Read [SECURITY.md](docs/SECURITY.md) before enabling output collection. Never share a report without reviewing it, because no generic redactor can guarantee removal of every private value from arbitrary third-party output.

## License

MIT.
