from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fixcenter.privacy import contains_secret, redact_value

MANAGED_MARKER = "<!-- wsai-fixcenter:managed:v1 -->"
MANAGED_SCRIPT_MARKER = "# wsai-fixcenter:managed:v1"
CURSOR_HEADER = (
    "---\n"
    "description: Canonical project instructions managed by WSAI FixCenter\n"
    "alwaysApply: true\n"
    "---\n\n"
)
MAX_FILE_BYTES = 1_000_000
MAX_DIRECTORY_ENTRIES = 1_000


@dataclass(frozen=True)
class Adapter:
    id: str
    path: str
    purpose: str
    merge_behavior: str


ADAPTERS = (
    Adapter("agents", "AGENTS.md", "Shared agent instructions", "hierarchical"),
    Adapter(
        "cursor",
        ".cursor/rules/fixcenter.mdc",
        "Cursor project rules",
        "combined-with-user-rules",
    ),
    Adapter("claude", "CLAUDE.md", "Claude project instructions", "hierarchical"),
    Adapter("gemini", "GEMINI.md", "Gemini project instructions", "hierarchical"),
    Adapter(
        "copilot",
        ".github/copilot-instructions.md",
        "GitHub Copilot repository instructions",
        "combined-with-other-instructions",
    ),
)
ADAPTER_BY_ID = {item.id: item for item in ADAPTERS}

KNOWN_TOOL_SURFACES = {
    ".agent": "generic-agent",
    ".agents": "agents",
    ".aider": "aider",
    ".claude": "claude",
    ".codex": "codex",
    ".continue": "continue",
    ".copilot": "copilot",
    ".cursor": "cursor",
    ".gemini": "gemini",
    ".github": "github",
    ".kilocode": "kilocode",
    ".mcp": "mcp",
    ".roo": "roo-code",
    ".vscode": "vscode",
    ".windsurf": "windsurf",
    ".zed": "zed",
}

INSTRUCTION_SURFACES = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    ".cursor/rules/fixcenter.mdc",
    ".github/copilot-instructions.md",
)

CONFIGURATION_SURFACES = {
    ".codex/config.toml": "codex",
    ".cursor/mcp.json": "cursor-mcp",
    ".cursor/settings.json": "cursor",
    ".claude/settings.json": "claude",
    ".gemini/settings.json": "gemini",
    ".mcp.json": "mcp",
    ".vscode/mcp.json": "vscode-mcp",
    ".vscode/settings.json": "vscode",
}

ACCOUNT_ENV_NAMES = (
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "CODEX_HOME",
    "COPILOT_HOME",
    "CURSOR_API_KEY",
    "GOOGLE_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "OPENAI_API_KEY",
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_VARIABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_ENV_REFERENCE = re.compile(r"^env:[A-Za-z_][A-Za-z0-9_]{0,127}$")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


@dataclass
class SetupPlan:
    plan_id: str
    root: str
    active_profile: str
    tools: list[str]
    actions: list[dict[str, str]]
    can_apply: bool
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "plan_id": self.plan_id,
                "root": self.root,
                "active_profile": self.active_profile,
                "tools": self.tools,
                "actions": [
                    {
                        "path": item["path"],
                        "action": item["action"],
                        "reason": item["reason"],
                    }
                    for item in self.actions
                ],
                "can_apply": self.can_apply,
                "warnings": self.warnings,
                "privacy": "No credential values or instruction contents are returned.",
            }
        )


class SetupManager:
    """Consolidate agent setup without silently replacing user-owned files."""

    def __init__(
        self,
        *,
        home: str | Path | None = None,
        environ: dict[str, str] | set[str] | None = None,
    ) -> None:
        self._home = Path(home).resolve() if home else Path.home().resolve()
        self._environment_names = (
            set(environ) if environ is not None else set(os.environ)
        )

    @staticmethod
    def catalog() -> dict[str, Any]:
        return {
            "manifest_version": 1,
            "canonical_directory": ".fixcenter",
            "adapters": [
                {
                    "id": item.id,
                    "path": item.path,
                    "purpose": item.purpose,
                    "merge_behavior": item.merge_behavior,
                }
                for item in ADAPTERS
            ],
            "known_tool_surfaces": KNOWN_TOOL_SURFACES,
            "precedence": [
                "one-off invocation overrides",
                "active FixCenter profile variable references",
                "FixCenter canonical project instructions",
                "tool-specific project instructions not managed by FixCenter",
                "tool user/global configuration",
            ],
            "account_model": "Profiles store labels and env:VARIABLE references only; never credential values.",
        }

    def inventory(
        self,
        root: str,
        *,
        consent: bool,
        include_home: bool = False,
        include_unknown_names: bool = False,
    ) -> dict[str, Any]:
        if not consent:
            raise ValueError("consent=true is required to inspect setup metadata")
        workspace = self._resolve_root(root)
        workspace_scan = self._scan_directory(workspace, include_unknown_names)
        home_scan = (
            self._scan_directory(self._home, include_unknown_names)
            if include_home
            else None
        )
        instruction_files = []
        for relative in INSTRUCTION_SURFACES:
            target = self._safe_target(workspace, relative)
            if self._has_symlink_component(workspace, target):
                instruction_files.append(
                    {
                        "path": relative,
                        "managed": False,
                        "size_bytes": None,
                        "status": "blocked-symlink",
                    }
                )
            elif target.is_file():
                instruction_files.append(
                    {
                        "path": relative,
                        "managed": self._managed_file(target, relative),
                        "size_bytes": target.stat().st_size,
                        "status": "file",
                    }
                )
        configuration_files = []
        for relative, owner in CONFIGURATION_SURFACES.items():
            target = self._safe_target(workspace, relative)
            if self._has_symlink_component(workspace, target):
                configuration_files.append(
                    {
                        "path": relative,
                        "owner": owner,
                        "size_bytes": None,
                        "status": "blocked-symlink",
                    }
                )
            elif target.is_file():
                configuration_files.append(
                    {
                        "path": relative,
                        "owner": owner,
                        "size_bytes": target.stat().st_size,
                        "status": "file",
                    }
                )
        environment_references = sorted(
            name for name in ACCOUNT_ENV_NAMES if name in self._environment_names
        )
        findings = []
        unmanaged = [item for item in instruction_files if not item["managed"]]
        if len(instruction_files) > 1:
            findings.append(
                "Multiple instruction layers are active; tools may combine them differently."
            )
        if unmanaged:
            findings.append(
                "Unmanaged instruction files exist and will be preserved, not overwritten."
            )
        if len(configuration_files) > 1:
            findings.append(
                "Multiple tool configuration layers exist; account and MCP settings may diverge."
            )
        if workspace_scan["unknown_dot_directories"]:
            findings.append(
                "Unknown dot-directories were found; review them before consolidation."
            )
        if environment_references:
            findings.append(
                "Account-related environment variable names are present; values were not read."
            )
        return redact_value(
            {
                "root": str(workspace),
                "workspace": workspace_scan,
                "home": home_scan,
                "instruction_files": instruction_files,
                "configuration_files": configuration_files,
                "environment_variable_names": environment_references,
                "findings": findings,
                "content_read": "Only exact generated ownership headers were checked; symlinks were not followed, and instruction/configuration bodies and variable values were not returned.",
            }
        )

    def plan(self, root: str, manifest: dict[str, Any], *, consent: bool) -> SetupPlan:
        if not consent:
            raise ValueError("consent=true is required to compare setup files")
        workspace = self._resolve_root(root)
        normalized = self._validate_manifest(manifest)
        desired = self._render_files(normalized)
        actions: list[dict[str, str]] = []
        fingerprint = [f"root\0{workspace}"]
        for relative, content in sorted(desired.items()):
            target = self._safe_target(workspace, relative)
            desired_digest = self._digest(content.encode())
            if self._has_symlink_component(workspace, target):
                action, reason, current_digest = (
                    "blocked",
                    "A path component is a symbolic link.",
                    "symlink",
                )
            elif not target.exists():
                action, reason, current_digest = (
                    "create",
                    "No file exists at this adapter path.",
                    "missing",
                )
            elif not target.is_file():
                action, reason, current_digest = (
                    "blocked",
                    "The adapter path exists but is not a regular file.",
                    "not-file",
                )
            elif target.stat().st_size > MAX_FILE_BYTES:
                action, reason, current_digest = (
                    "blocked",
                    "The existing file exceeds the safe comparison limit.",
                    "oversize",
                )
            else:
                existing = target.read_bytes()
                current_digest = self._digest(existing)
                if existing == content.encode():
                    action, reason = "unchanged", "Already synchronized."
                elif self._is_managed(
                    existing.decode("utf-8", errors="replace"), relative
                ):
                    action, reason = "update", "Existing FixCenter-generated file."
                else:
                    action, reason = (
                        "blocked",
                        "Existing user-owned file will not be overwritten.",
                    )
            actions.append(
                {
                    "path": relative,
                    "action": action,
                    "reason": reason,
                    "_expected_digest": current_digest,
                }
            )
            fingerprint.append(
                f"{relative}\0{action}\0{current_digest}\0{desired_digest}"
            )
        retirement_candidates, retirement_issue = self._retirement_candidates(
            workspace, set(desired)
        )
        if retirement_issue:
            actions.append(
                {
                    "path": ".fixcenter/profiles",
                    "action": "blocked",
                    "reason": retirement_issue,
                    "_expected_digest": "scan-blocked",
                }
            )
            fingerprint.append(f".fixcenter/profiles\0blocked\0{retirement_issue}")
        for relative in retirement_candidates:
            target = self._safe_target(workspace, relative)
            if self._has_symlink_component(workspace, target):
                action, reason, current_digest = (
                    "blocked",
                    "A retired adapter path contains a symbolic link.",
                    "symlink",
                )
            elif target.stat().st_size > MAX_FILE_BYTES:
                action, reason, current_digest = (
                    "blocked",
                    "A retired adapter exceeds the safe comparison limit.",
                    "oversize",
                )
            else:
                existing = target.read_bytes()
                current_digest = self._digest(existing)
                if self._is_managed(
                    existing.decode("utf-8", errors="replace"), relative
                ):
                    action, reason = (
                        "retire",
                        "Generated adapter is no longer selected; move it to recoverable storage.",
                    )
                else:
                    action, reason = (
                        "blocked",
                        "Former adapter path is now user-owned and will not be moved.",
                    )
            actions.append(
                {
                    "path": relative,
                    "action": action,
                    "reason": reason,
                    "_expected_digest": current_digest,
                }
            )
            fingerprint.append(f"{relative}\0{action}\0{current_digest}\0retired")
        plan_id = hashlib.sha256("\n".join(fingerprint).encode()).hexdigest()[:24]
        blocked = [item for item in actions if item["action"] == "blocked"]
        warnings = (
            [
                "Resolve blocked paths manually or choose fewer adapters; FixCenter preserves user-owned files."
            ]
            if blocked
            else []
        )
        return SetupPlan(
            plan_id,
            str(workspace),
            normalized["active_profile"],
            normalized["tools"],
            actions,
            not blocked,
            warnings,
        )

    def apply(
        self,
        root: str,
        manifest: dict[str, Any],
        plan_id: str,
        *,
        consent: bool,
    ) -> dict[str, Any]:
        if not consent:
            raise ValueError("consent=true is required to write setup files")
        workspace = self._resolve_root(root, writable=True)
        if workspace == self._home:
            raise ValueError(
                "refusing to write directly to the user home; select a workspace"
            )
        normalized = self._validate_manifest(manifest)
        with self._workspace_lock(workspace):
            return self._apply_locked(workspace, normalized, plan_id)

    def _apply_locked(
        self, workspace: Path, normalized: dict[str, Any], plan_id: str
    ) -> dict[str, Any]:
        plan = self.plan(str(workspace), normalized, consent=True)
        if plan.plan_id != plan_id:
            raise ValueError("plan_id is stale or does not match the current setup")
        if not plan.can_apply:
            raise ValueError("the setup plan contains blocked user-owned paths")
        desired = self._render_files(normalized)
        changed = [
            item
            for item in plan.actions
            if item["action"] in {"create", "update", "retire"}
        ]
        created_files: dict[Path, str] = {}
        backup_root = workspace / ".fixcenter" / "backups" / plan.plan_id
        retired_root = workspace / ".fixcenter" / "retired" / plan.plan_id
        moved_files: dict[Path, Path] = {}
        for item in changed:
            if item["action"] not in {"update", "retire"}:
                continue
            storage_root = backup_root if item["action"] == "update" else retired_root
            stored = self._safe_target(storage_root, item["path"])
            if self._has_symlink_component(workspace, stored):
                raise ValueError(
                    "a setup backup or retirement path contains a symbolic link"
                )
            if stored.exists():
                raise ValueError(
                    "a setup backup or retirement file already exists for this plan"
                )
        try:
            for item in changed:
                target = self._safe_target(workspace, item["path"])
                if item["action"] == "create":
                    self._assert_create_state(workspace, target)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    content = desired[item["path"]]
                    self._atomic_create(target, content)
                    created_files[target] = self._digest(content.encode())
                    continue
                storage_root = (
                    backup_root if item["action"] == "update" else retired_root
                )
                stored = self._safe_target(storage_root, item["path"])
                stored.parent.mkdir(parents=True, exist_ok=True)
                self._move_no_replace(target, stored)
                moved_files[target] = stored
                self._read_expected_file(workspace, stored, item["_expected_digest"])
                if item["action"] == "retire":
                    continue
                content = desired[item["path"]]
                self._atomic_create(target, content)
                created_files[target] = self._digest(content.encode())
        except (OSError, ValueError):
            self._restore_transaction(workspace, created_files, moved_files)
            raise
        return redact_value(
            {
                "plan_id": plan.plan_id,
                "applied": True,
                "created": sum(item["action"] == "create" for item in changed),
                "updated": sum(item["action"] == "update" for item in changed),
                "retired": sum(item["action"] == "retire" for item in changed),
                "unchanged": sum(
                    item["action"] == "unchanged" for item in plan.actions
                ),
                "active_profile": normalized["active_profile"],
                "backup_directory": str(backup_root) if backup_root.exists() else None,
                "retired_directory": (
                    str(retired_root) if retired_root.exists() else None
                ),
                "next_steps": [
                    "Review the generated adapters.",
                    "Restart active agent sessions so they reload instructions.",
                    "Keep credential values in the referenced environment variables only.",
                ],
            }
        )

    @staticmethod
    def _validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(manifest, dict):
            raise TypeError("manifest must be an object")
        allowed = {"version", "active_profile", "profiles", "instructions", "tools"}
        unknown = sorted(set(manifest) - allowed)
        if unknown:
            raise ValueError(f"manifest contains unknown fields: {', '.join(unknown)}")
        if manifest.get("version") != 1:
            raise ValueError("manifest.version must be 1")
        active = manifest.get("active_profile")
        profiles = manifest.get("profiles")
        instructions = manifest.get("instructions")
        tools = manifest.get("tools")
        if not isinstance(active, str) or not _IDENTIFIER.fullmatch(active):
            raise ValueError("active_profile must be a safe identifier")
        if not isinstance(profiles, dict) or not profiles or len(profiles) > 20:
            raise ValueError("profiles must contain between 1 and 20 profiles")
        normalized_profiles: dict[str, dict[str, Any]] = {}
        folded_profile_names: set[str] = set()
        for name, profile in profiles.items():
            if not isinstance(name, str) or not SetupManager._portable_profile_name(
                name
            ):
                raise ValueError("profile names must be portable safe identifiers")
            folded_name = name.casefold()
            if folded_name in folded_profile_names:
                raise ValueError("profile names must be unique ignoring case")
            folded_profile_names.add(folded_name)
            if not isinstance(profile, dict):
                raise TypeError(f"profile '{name}' must be an object")
            extras = sorted(set(profile) - {"account_label", "variables"})
            if extras:
                raise ValueError(f"profile '{name}' contains unknown fields")
            label = profile.get("account_label", name)
            variables = profile.get("variables", {})
            if (
                not isinstance(label, str)
                or not _IDENTIFIER.fullmatch(label)
                or contains_secret(label)
            ):
                raise ValueError("account_label must be a secret-free identifier")
            if not isinstance(variables, dict) or len(variables) > 100:
                raise ValueError(
                    "profile variables must be an object with at most 100 entries"
                )
            normalized_variables = {}
            for variable, reference in variables.items():
                if not isinstance(variable, str) or not _VARIABLE.fullmatch(variable):
                    raise ValueError(
                        "variable names must be portable environment names"
                    )
                if not isinstance(reference, str) or not _ENV_REFERENCE.fullmatch(
                    reference
                ):
                    raise ValueError(
                        "variable bindings must use env:VARIABLE references, never values"
                    )
                normalized_variables[variable] = reference
            normalized_profiles[name] = {
                "account_label": label,
                "variables": normalized_variables,
            }
        target_names = {
            variable.casefold()
            for profile in normalized_profiles.values()
            for variable in profile["variables"]
        }
        source_names = {
            reference.removeprefix("env:").casefold()
            for profile in normalized_profiles.values()
            for reference in profile["variables"].values()
        }
        if target_names & source_names:
            raise ValueError(
                "profile source variables must not also be managed target variables"
            )
        target_spellings: dict[str, str] = {}
        for profile in normalized_profiles.values():
            for variable in profile["variables"]:
                folded = variable.casefold()
                if folded in target_spellings and target_spellings[folded] != variable:
                    raise ValueError(
                        "managed target variable names must use consistent casing"
                    )
                target_spellings[folded] = variable
        if active not in normalized_profiles:
            raise ValueError("active_profile must reference a declared profile")
        if (
            not isinstance(instructions, list)
            or not instructions
            or len(instructions) > 200
        ):
            raise ValueError("instructions must contain between 1 and 200 rules")
        normalized_instructions = []
        for instruction in instructions:
            if not isinstance(instruction, str):
                raise TypeError("each instruction must be a string")
            item = instruction.strip()
            if not item or len(item) > 5_000:
                raise ValueError(
                    "instructions must be non-empty and at most 5000 characters"
                )
            if MANAGED_MARKER in item or contains_secret(item):
                raise ValueError(
                    "instructions must not contain credentials or managed markers"
                )
            normalized_instructions.append(item)
        if (
            not isinstance(tools, list)
            or not tools
            or len(tools) > len(ADAPTERS)
            or any(not isinstance(item, str) for item in tools)
        ):
            raise ValueError("tools must be a non-empty adapter list")
        unknown_tools = sorted(set(tools) - ADAPTER_BY_ID.keys())
        if unknown_tools:
            raise ValueError(f"unknown setup adapters: {', '.join(unknown_tools)}")
        return {
            "version": 1,
            "active_profile": active,
            "profiles": normalized_profiles,
            "instructions": normalized_instructions,
            "tools": list(dict.fromkeys(tools)),
        }

    @staticmethod
    def _render_files(manifest: dict[str, Any]) -> dict[str, str]:
        stored = {"managed_by": "wsai-fixcenter", **manifest}
        files = {
            ".fixcenter/setup.json": json.dumps(
                stored, ensure_ascii=False, indent=2, sort_keys=True
            )
            + "\n",
            ".fixcenter/instructions.md": SetupManager._instruction_body(manifest),
        }
        body = SetupManager._instruction_body(manifest)
        for tool_id in manifest["tools"]:
            adapter = ADAPTER_BY_ID[tool_id]
            files[adapter.path] = (
                SetupManager._cursor_body(body) if tool_id == "cursor" else body
            )
        targets = sorted(
            {
                variable
                for profile in manifest["profiles"].values()
                for variable in profile["variables"]
            }
        )
        for name, profile in manifest["profiles"].items():
            files[f".fixcenter/profiles/{name}.ps1"] = SetupManager._powershell_profile(
                name, profile["variables"], targets
            )
            files[f".fixcenter/profiles/{name}.sh"] = SetupManager._shell_profile(
                name, profile["variables"], targets
            )
        return files

    @staticmethod
    def _instruction_body(manifest: dict[str, Any]) -> str:
        profile = manifest["profiles"][manifest["active_profile"]]
        rules = "\n".join(
            f"{index}. {rule}" for index, rule in enumerate(manifest["instructions"], 1)
        )
        bindings = profile["variables"]
        variables = (
            "\n".join(
                f"- `{name}` <- `{ref}`" for name, ref in sorted(bindings.items())
            )
            if bindings
            else "- No environment bindings declared."
        )
        return (
            f"{MANAGED_MARKER}\n"
            "# Managed project instructions\n\n"
            "Generated by WSAI FixCenter from `.fixcenter/setup.json`. "
            "Edit the canonical manifest and regenerate; do not place credentials here.\n\n"
            "## Rules\n\n"
            f"{rules}\n\n"
            "## Active account profile\n\n"
            f"- Profile: `{manifest['active_profile']}`\n"
            f"- Account label: `{profile['account_label']}`\n"
            f"{variables}\n"
        )

    @staticmethod
    def _cursor_body(body: str) -> str:
        return f"{CURSOR_HEADER}{body}"

    @staticmethod
    def _powershell_profile(
        name: str, bindings: dict[str, str], targets: list[str]
    ) -> str:
        lines = [
            MANAGED_SCRIPT_MARKER,
            f"# Activate the secret-free FixCenter profile: {name}",
            "# Dot-source this file so changes remain in the current shell.",
        ]
        sources = sorted(
            {reference.removeprefix("env:") for reference in bindings.values()}
        )
        lines.extend(
            f"if (-not (Test-Path Env:{source})) {{ throw 'Missing required environment variable: {source}' }}"
            for source in sources
        )
        lines.extend(
            f"Remove-Item Env:{variable} -ErrorAction SilentlyContinue"
            for variable in targets
        )
        for variable, reference in sorted(bindings.items()):
            source = reference.removeprefix("env:")
            lines.append(
                f"$env:{variable} = [Environment]::GetEnvironmentVariable('{source}', 'Process')"
            )
        lines.append(f"Write-Host 'FixCenter profile active: {name}'")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _shell_profile(name: str, bindings: dict[str, str], targets: list[str]) -> str:
        lines = [
            MANAGED_SCRIPT_MARKER,
            f"# Activate the secret-free FixCenter profile: {name}",
            "# Source this file so changes remain in the current shell.",
        ]
        sources = sorted(
            {reference.removeprefix("env:") for reference in bindings.values()}
        )
        lines.extend(
            f'if [ "${{{source}+x}}" != x ]; then echo "Missing required environment variable: {source}" >&2; return 1 2>/dev/null || exit 1; fi'
            for source in sources
        )
        lines.extend(f"unset {variable}" for variable in targets)
        for variable, reference in sorted(bindings.items()):
            source = reference.removeprefix("env:")
            lines.append(f'export {variable}="${{{source}}}"')
        lines.append(f'echo "FixCenter profile active: {name}"')
        return "\n".join(lines) + "\n"

    @staticmethod
    def _resolve_root(root: str, *, writable: bool = False) -> Path:
        if not isinstance(root, str) or not root.strip():
            raise ValueError("root must be a non-empty absolute path")
        candidate = Path(root)
        if not candidate.is_absolute():
            raise ValueError("root must be an absolute path")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ValueError("root must be an accessible existing directory") from exc
        if not resolved.is_dir():
            raise ValueError("root must be an existing directory")
        if writable and resolved == Path(resolved.anchor):
            raise ValueError("refusing to write setup files at a filesystem root")
        return resolved

    @staticmethod
    def _safe_target(root: Path, relative: str) -> Path:
        candidate = Path(relative)
        if (
            not relative
            or candidate.is_absolute()
            or candidate.drive
            or ".." in candidate.parts
        ):
            raise ValueError("adapter target escapes the selected root")
        return root.joinpath(*candidate.parts)

    @staticmethod
    def _has_symlink_component(root: Path, target: Path) -> bool:
        current = root
        for part in target.relative_to(root).parts:
            current /= part
            if current.is_symlink():
                return True
        return False

    @staticmethod
    def _managed_file(path: Path, relative: str | None = None) -> bool:
        if path.stat().st_size > MAX_FILE_BYTES:
            return False
        return SetupManager._is_managed(
            path.read_text(encoding="utf-8", errors="replace"), relative
        )

    @staticmethod
    def _is_managed(content: str, relative: str | None = None) -> bool:
        if content.startswith((f"{MANAGED_MARKER}\n", f"{MANAGED_SCRIPT_MARKER}\n")):
            return True
        if content.startswith(f"{CURSOR_HEADER}{MANAGED_MARKER}\n"):
            return True
        if relative != ".fixcenter/setup.json":
            return False
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return False
        return isinstance(parsed, dict) and parsed.get("managed_by") == "wsai-fixcenter"

    @staticmethod
    def _portable_profile_name(name: str) -> bool:
        if not _IDENTIFIER.fullmatch(name) or name.endswith((".", " ")):
            return False
        return name.split(".", 1)[0].upper() not in _WINDOWS_RESERVED_NAMES

    @staticmethod
    def _digest(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def _scan_directory(path: Path, include_unknown_names: bool) -> dict[str, Any]:
        known: dict[str, str] = {}
        unknown: list[str] = []
        try:
            entries = sorted(path.iterdir(), key=lambda item: item.name.lower())
        except OSError as exc:
            return {
                "known_tool_directories": {},
                "unknown_dot_directory_count": 0,
                "unknown_dot_directories": [],
                "scan_error": type(exc).__name__,
            }
        truncated = len(entries) > MAX_DIRECTORY_ENTRIES
        for item in entries[:MAX_DIRECTORY_ENTRIES]:
            if not item.name.startswith(".") or not item.is_dir():
                continue
            if item.name in KNOWN_TOOL_SURFACES:
                known[item.name] = KNOWN_TOOL_SURFACES[item.name]
            else:
                unknown.append(item.name)
        return {
            "known_tool_directories": known,
            "unknown_dot_directory_count": len(unknown),
            "unknown_dot_directories": unknown if include_unknown_names else [],
            "unknown_names_included": include_unknown_names,
            "truncated": truncated,
        }

    @staticmethod
    def _retirement_candidates(
        workspace: Path, desired: set[str]
    ) -> tuple[list[str], str | None]:
        candidates = {item.path for item in ADAPTERS}
        profile_directory = workspace / ".fixcenter" / "profiles"
        if profile_directory.is_dir() and not profile_directory.is_symlink():
            try:
                entries = sorted(
                    profile_directory.iterdir(), key=lambda item: item.name.casefold()
                )
            except OSError:
                return [], "Profile activators could not be inventoried safely."
            if len(entries) > MAX_DIRECTORY_ENTRIES:
                return [], "Profile activator inventory exceeded the safe entry limit."
            for item in entries:
                if (
                    not item.is_symlink()
                    and item.is_file()
                    and item.suffix in {".ps1", ".sh"}
                ):
                    candidates.add(item.relative_to(workspace).as_posix())
        managed = []
        for relative in sorted(candidates - desired):
            target = workspace / Path(relative)
            if (
                target.is_symlink()
                or not target.is_file()
                or target.stat().st_size > MAX_FILE_BYTES
            ):
                continue
            if SetupManager._managed_file(target, relative):
                managed.append(relative)
        return managed, None

    @staticmethod
    def _assert_create_state(workspace: Path, target: Path) -> None:
        if SetupManager._has_symlink_component(workspace, target):
            raise ValueError("setup changed after planning: symbolic link detected")
        if target.exists() or target.is_symlink():
            raise ValueError("setup changed after planning: create target now exists")

    @staticmethod
    def _read_expected_file(
        workspace: Path, target: Path, expected_digest: str
    ) -> tuple[bytes, tuple[int, int, int, int]]:
        if SetupManager._has_symlink_component(workspace, target):
            raise ValueError("setup changed after planning: symbolic link detected")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target, flags)
        except OSError as exc:
            raise ValueError(
                "setup changed after planning: target cannot be opened safely"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
                raise ValueError(
                    "setup changed after planning: target is not a safe regular file"
                )
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                content = stream.read(MAX_FILE_BYTES + 1)
        finally:
            os.close(descriptor)
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        SetupManager._assert_file_identity(target, identity)
        if SetupManager._digest(content) != expected_digest:
            raise ValueError(
                "setup changed after planning: file content no longer matches"
            )
        return content, identity

    @staticmethod
    def _assert_file_identity(
        target: Path, expected: tuple[int, int, int, int] | None
    ) -> None:
        try:
            metadata = target.lstat()
        except OSError as exc:
            raise ValueError(
                "setup changed after planning: file identity no longer matches"
            ) from exc
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        if target.is_symlink() or identity != expected:
            raise ValueError(
                "setup changed after planning: file identity no longer matches"
            )

    @staticmethod
    @contextmanager
    def _workspace_lock(workspace: Path):
        directory = SetupManager._safe_target(workspace, ".fixcenter")
        if SetupManager._has_symlink_component(workspace, directory):
            raise ValueError("the FixCenter directory contains a symbolic link")
        directory.mkdir(parents=True, exist_ok=True)
        lock = SetupManager._safe_target(workspace, ".fixcenter/apply.lock")
        if SetupManager._has_symlink_component(workspace, lock):
            raise ValueError("the FixCenter lock path contains a symbolic link")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(lock, flags, 0o600)
            metadata = os.fstat(descriptor)
            identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            )
            SetupManager._assert_file_identity(lock, identity)
            if metadata.st_size == 0:
                os.write(descriptor, b"0")
            SetupManager._lock_descriptor(descriptor)
        except (OSError, ValueError) as exc:
            if "descriptor" in locals():
                os.close(descriptor)
            raise ValueError(
                "another FixCenter setup application is in progress"
            ) from exc
        try:
            yield
        finally:
            SetupManager._unlock_descriptor(descriptor)
            os.close(descriptor)

    @staticmethod
    def _lock_descriptor(descriptor: int) -> None:  # pragma: no cover
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _unlock_descriptor(descriptor: int) -> None:  # pragma: no cover
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)

    @staticmethod
    def _atomic_create(path: Path, content: str) -> None:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.fixcenter-", dir=path.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, path, follow_symlinks=False)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        else:
            os.unlink(temporary)

    @staticmethod
    def _move_no_replace(source: Path, destination: Path) -> None:  # pragma: no cover
        """Atomically move one path while refusing to replace the destination."""
        if os.name == "nt":
            os.rename(source, destination)
            return

        import ctypes
        import errno
        import sys

        libc = ctypes.CDLL(None, use_errno=True)
        source_bytes = os.fsencode(source)
        destination_bytes = os.fsencode(destination)
        if sys.platform.startswith("linux"):
            rename = libc.renameat2
            rename.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            result = rename(-100, source_bytes, -100, destination_bytes, 1)
        elif sys.platform == "darwin":
            rename = libc.renamex_np
            rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            result = rename(source_bytes, destination_bytes, 4)
        else:
            raise OSError(
                errno.ENOTSUP,
                "exclusive atomic move is unsupported on this platform",
                str(destination),
            )
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(destination))

    @staticmethod
    def _restore_transaction(
        workspace: Path,
        created_files: dict[Path, str],
        moved_files: dict[Path, Path] | None = None,
    ) -> None:
        for target, expected_digest in reversed(list(created_files.items())):
            try:
                SetupManager._read_expected_file(workspace, target, expected_digest)
            except ValueError:
                continue
            target.unlink()
        for target, stored in reversed(list((moved_files or {}).items())):
            if target.exists() or target.is_symlink() or not stored.is_file():
                continue
            try:
                os.link(stored, target, follow_symlinks=False)
            except OSError:
                continue
            stored.unlink()
