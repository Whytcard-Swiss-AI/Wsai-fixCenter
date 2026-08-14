---
name: wsai_fckdot-install
description: Install and connect the public wsai_fckdot MCP server to a compatible client on Windows, Linux, or macOS.
---

# Install wsai_fckdot

Use this skill when a user asks to install, update, connect, or validate wsai_fckdot.

## Safety boundary

- Never request, print, copy, or commit credentials.
- Never run a system probe during installation.
- Do not modify an existing MCP configuration until its exact path and format are known.
- Preserve existing servers and create a backup before an authorized configuration edit.
- Installation success and MCP client activation are separate checks.

## Procedure

1. Confirm Python 3.10 or newer and Git are available.
2. Clone `https://github.com/Whytcard-Swiss-AI/wsai_fckdot.git` into a user-approved directory, or update an existing clone with a normal fast-forward pull.
3. Create a project-local virtual environment.
4. Install with `python -m pip install -e .`.
5. Run `python -m wsai_fckdot self-test`; require `success_rate_percent: 100.0`.
6. Run `python -m wsai_fckdot coverage --platform <windows|linux|darwin>`; explain that design coverage is not runtime observation.
7. Add the MCP entry only after locating the client's real configuration format. Use the virtual environment's absolute Python executable and `-m wsai_fckdot serve`.
8. Restart the client and verify `tools/list` exposes ten tools.

## MCP entry template

```json
{
  "mcpServers": {
    "wsai_fckdot": {
      "command": "/absolute/path/to/.venv/python",
      "args": ["-m", "wsai_fckdot", "serve"],
      "cwd": "/absolute/path/to/wsai_fckdot"
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
- ten tools visible.
