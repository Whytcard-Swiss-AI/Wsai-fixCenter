# WSAI FixCenter

WSAI FixCenter is an evidence-first MCP server for diagnosing problems around hooks, plugins, skills and configuration. It does not silently modify a workspace: it collects supplied evidence, runs targeted checks, ranks probable causes and returns concrete, reviewable fixes.

## What it does

- accepts a problem description plus logs, safe configuration fragments, affected components, environment metadata and an optional workspace reference;
- runs diagnostics selected by problem type through an extensible registry;
- returns findings with severity, confidence, evidence, explanation, diagnostic ID and suggested fixes;
- validates input sizes and types and keeps protocol output on stdout while operational logs go to stderr;
- exposes a small MCP surface: `diagnose` and `list_diagnostics`;
- supports a local CLI and JSON report export.

The initial diagnostics cover missing components, malformed `hooks`/`plugins`/`skills` sections, and suspicious hook ordering/timeouts. Add a diagnostic by implementing a function in `fixcenter/diagnostics/` and registering a `Diagnostic` in `DEFAULT_DIAGNOSTICS`.

## Installation

Requires Python 3.10 or newer.

```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -e .
```

## MCP configuration

For an MCP client that supports stdio, point it to:

```json
{
  "mcpServers": {
    "wsai-fixcenter": {
      "command": "python",
      "args": ["-m", "fixcenter", "serve"],
      "cwd": "/absolute/path/to/Wsai-fixCenter"
    }
  }
}
```

The server implements JSON-RPC MCP initialization, `tools/list`, and `tools/call`. It never executes arbitrary commands from a problem payload and does not apply fixes automatically.

## Example call

```json
{
  "description": "The deploy hook is not found after enabling the plugin",
  "problem_type": "hook",
  "logs": ["ERROR hook deploy: not found", "plugin loaded: release-tools"],
  "config": {"hooks": [{"name": "deploy"}]},
  "components": ["release-tools", "deploy"]
}
```

The report contains a stable diagnostic ID, for example `component-missing`, plus ranked evidence and next actions. Redact tokens, API keys, cookies and private user data before sending logs or configuration.

## CLI

```bash
echo '{"description":"Plugin not found","problem_type":"plugin","logs":["not found"]}' | python -m fixcenter diagnose
python -m fixcenter diagnose problem.json --out reports
```

## Development

```bash
python -m pip install -e . pytest
python -m pytest -q
```

The test suite covers ranking, validation, malformed configuration detection and the executable package entry point. The project is intentionally dependency-light so it can run inside constrained MCP hosts.

## Safety and scope

FixCenter is a diagnostic engine, not an autonomous repair agent. A proposed fix is advice until a human reviews it. Workspace paths are treated as context only in this release; the server does not read files, install packages, change settings or contact third-party services. Future collectors should be explicit, bounded, redacted and opt-in.

## License

MIT.

