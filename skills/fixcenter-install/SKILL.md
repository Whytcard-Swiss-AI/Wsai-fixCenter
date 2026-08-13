---
name: fixcenter-install
description: Install and connect the public WSAI FixCenter MCP server to a compatible client on Windows, Linux, or macOS.
---

# Install WSAI FixCenter

Use this skill when a user asks to install, update, connect, or validate WSAI FixCenter.

## Safety boundary

- Never request, print, copy, or commit credentials.
- Never run a system probe during installation.
- Do not modify an existing MCP configuration until its exact path and format are known.
- Preserve existing servers and create a backup before an authorized configuration edit.
- Installation success and MCP client activation are separate checks.

## Procedure

1. Confirm Python 3.10 or newer and Git are available.
2. Clone `https://github.com/Whytcard-Swiss-AI/Wsai-fixCenter.git` into a user-approved directory, or update an existing clone with a normal fast-forward pull.
3. Create a project-local virtual environment.
4. Install with `python -m pip install -e .`.
5. Run `python -m fixcenter self-test`; require `success_rate_percent: 100.0`.
6. Run `python -m fixcenter coverage --platform <windows|linux|darwin>`; explain that design coverage is not runtime observation.
7. Add the MCP entry only after locating the client's real configuration format. Use the virtual environment's absolute Python executable and `-m fixcenter serve`.
8. Restart the client and verify `tools/list` exposes six tools.

## MCP entry template

```json
{
  "mcpServers": {
    "wsai-fixcenter": {
      "command": "/absolute/path/to/.venv/python",
      "args": ["-m", "fixcenter", "serve"],
      "cwd": "/absolute/path/to/Wsai-fixCenter"
    }
  }
}
```

On Windows, the executable is normally `.venv\\Scripts\\python.exe`. Never overwrite unrelated keys in the client's configuration.

## Completion evidence

Report these independently:

- package import succeeds;
- synthetic self-test score;
- catalog design coverage for the target platform;
- client restarted;
- MCP server connected;
- six tools visible.
