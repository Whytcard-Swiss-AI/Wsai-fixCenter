# wsai_fckdot

wsai_fckdot is a public, privacy-first MCP server for diagnosing hooks, plugins, skills, MCP integrations, configuration, runtimes, networking and PC system state. It also turns a chaotic multi-agent setup into one canonical manifest, isolated account profiles and generated adapters for each supported tool.

It never repairs a machine automatically, never interpolates user input into commands, never elevates privileges and never sends telemetry. Account bindings accept environment-variable references rather than values; common credential-shaped text is rejected, but users must still keep secrets out of free-form instructions. Setup files are written only after a reviewed plan and explicit consent.

## Verified scope

- 38 read-only controls in 12 domains;
- 100% catalog design coverage on Windows, Linux and macOS;
- 15 diagnostic rule families;
- 16 synthetic evaluation cases with a 100% success gate;
- 10 MCP tools;
- 100% Python statement coverage enforced in CI;
- tested redaction of common sensitive formats and explicit execution consent.
- compatibility with both legacy MCP handshakes and the stateless `2026-07-28` era.
- one canonical `.wsai_fckdot/setup.json` format, five tool adapters and secret-free account profile activators.

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
| `get_setup_catalog` | Explain adapters, profiles and precedence | No |
| `inspect_setup` | Inventory setup metadata, never variable values | No, until consent |
| `plan_setup` | Compare a canonical manifest and preserve conflicts | No, until consent |
| `apply_setup` | Apply the exact reviewed plan | Yes, explicit consent |

`collect_context` executes only when both `execute=true` and `consent=true`. Output is excluded unless `include_output=true`; included output is passed through the tested redactor and truncated. As with any pattern-based redaction, review it before sharing.

## One setup instead of endless `.xxx` folders

wsai_fckdot uses `.wsai_fckdot/setup.json` as the project source of truth. Write instructions once, declare account profiles using environment-variable references, and select the adapters your tools need. It can generate:

- `AGENTS.md`;
- `.cursor/rules/wsai_fckdot.mdc`;
- `CLAUDE.md`;
- `GEMINI.md`;
- `.github/copilot-instructions.md`;
- PowerShell and POSIX-shell profile activators under `.wsai_fckdot/profiles/`.

The activators contain no secrets. They clear declared target variables before mapping the chosen profile from references such as `env:OPENAI_WORK_API_KEY`, preventing personal and work account state from remaining mixed in one shell.

wsai_fckdot inventories known tool directories and counts unknown dot-directories. Unknown names are hidden by default. It does not delete or move any `.xxx` directory, does not follow setup symlinks during inventory, and refuses to overwrite an existing adapter file unless it starts with an exact wsai_fckdot ownership header.

The workflow is deliberately simple:

1. inspect metadata;
2. create a canonical manifest;
3. review a plan containing `create`, `update`, `retire`, `unchanged` and `blocked` actions;
4. apply that exact plan ID with explicit consent;
5. activate the selected account profile and restart active agent sessions.

Read the [complete setup governance guide](docs/SETUP_GOVERNANCE.md) and start from [`setup.example.json`](setup.example.json).

## Covered domains

System identity, time and locale; CPU, memory and devices; storage; processes, services, startup and scheduled tasks; environment and PATH; log availability; adapters, DNS, proxy and listeners; permissions, firewall, certificates, protection and policies; package managers, language runtimes, shells, Git and editors; MCP, hooks, plugins, skills, Codex runtime, remote-control prerequisites and chat streaming; containers and guest environments; update visibility.

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/Whytcard-Swiss-AI/wsai_fckdot.git
cd wsai_fckdot
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install -e .
python -m wsai_fckdot self-test
python -m wsai_fckdot setup-catalog
python -m wsai_fckdot setup-inventory C:\absolute\project --consent
python -m wsai_fckdot setup-plan C:\absolute\project setup.example.json --consent
# Review the plan_id, then:
python -m wsai_fckdot setup-apply C:\absolute\project setup.example.json PLAN_ID --consent
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
    "wsai_fckdot": {
      "command": "/absolute/path/to/wsai_fckdot/.venv/bin/python",
      "args": ["-m", "wsai_fckdot", "serve"],
      "cwd": "/absolute/path/to/wsai_fckdot"
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
python -m wsai_fckdot catalog
python -m wsai_fckdot coverage --platform windows
python -m wsai_fckdot collect agents.hooks agents.plugins --platform windows
python -m wsai_fckdot collect agents.hooks --platform windows --execute --consent
python -m wsai_fckdot diagnose problem.json --out reports
python -m wsai_fckdot self-test
```

The first `collect` command only produces a plan. The second explicitly executes one allowlisted probe and still omits output.

## Agent skills

Three reusable public skills are included:

- [`wsai_fckdot-install`](skills/wsai_fckdot-install/SKILL.md) installs and verifies the MCP without collecting machine data;
- [`wsai_fckdot-use`](skills/wsai_fckdot-use/SKILL.md) guides diagnosis, consent, narrow collection and post-fix verification;
- [`wsai_fckdot-setup`](skills/wsai_fckdot-setup/SKILL.md) guides setup inventory, conflict-safe consolidation, account profiles and approved application.

Source archives and wheels both include every skill's `SKILL.md` and `agents/openai.yaml` under the distribution's `share/wsai_fckdot/skills` data directory. Installing the Python package does not silently activate a skill in an agent client; copy or link the selected skill into that client's documented skill directory.

## Extending wsai_fckdot

Controls live in `wsai_fckdot.catalog`; diagnostics live in `wsai_fckdot.diagnostics`. Every new control needs Windows, Linux and macOS probes, synthetic tests and an updated catalog version. Every new diagnostic needs a stable ID, evidence, explanation, safe fixes and positive/negative evaluation cases. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Read [SECURITY.md](docs/SECURITY.md) before enabling output collection or setup application. Never share a report without reviewing it, because no generic redactor can guarantee removal of every private value from arbitrary third-party output.

## License

MIT.
