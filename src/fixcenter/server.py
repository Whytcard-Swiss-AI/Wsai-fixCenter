from __future__ import annotations

import json
import logging
import sys
from typing import Any

from fixcenter.catalog import CONTROL_CATALOG
from fixcenter.collector import SafeCollector
from fixcenter.diagnostics.base import DEFAULT_DIAGNOSTICS
from fixcenter.engine import DiagnosticEngine
from fixcenter.evaluation import run_evaluation
from fixcenter.models import Problem
from fixcenter.privacy import redact

PROTOCOL = "2025-11-25"
MODERN_PROTOCOL = "2026-07-28"
LEGACY_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
SUPPORTED_PROTOCOLS = (*LEGACY_PROTOCOLS, MODERN_PROTOCOL)
PROBLEM_TYPES = [
    "hook",
    "plugin",
    "skill",
    "config",
    "system",
    "network",
    "runtime",
    "security",
    "integration",
    "codex",
    "unknown",
]
PLATFORMS = ["windows", "linux", "darwin"]
TOOLS = [
    {
        "name": "diagnose",
        "description": "Rank probable causes for a hook, plugin, skill, configuration, system, network or runtime problem.",
        "inputSchema": {
            "type": "object",
            "required": ["description"],
            "additionalProperties": False,
            "properties": {
                "description": {"type": "string", "minLength": 1, "maxLength": 20000},
                "problem_type": {"type": "string", "enum": PROBLEM_TYPES},
                "logs": {
                    "type": "array",
                    "maxItems": 200,
                    "items": {"type": "string", "maxLength": 20000},
                },
                "config": {"type": "object"},
                "components": {"type": "array", "items": {"type": "string"}},
                "environment": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                "workspace": {"type": ["string", "null"]},
                "observations": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {"type": "object"},
                },
            },
        },
    },
    {
        "name": "list_diagnostics",
        "description": "List registered diagnostic rules and supported problem types.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
    },
    {
        "name": "get_control_catalog",
        "description": "List the public, read-only PC control catalog. This never inspects the host.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "category": {"type": ["string", "null"]},
                "include_commands": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "audit_coverage",
        "description": "Measure design coverage for Windows, Linux or macOS without inspecting a machine.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"platform": {"type": "string", "enum": PLATFORMS}},
        },
    },
    {
        "name": "collect_context",
        "description": "Plan or explicitly execute allowlisted read-only probes with strict redaction. Execution requires execute=true and consent=true.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "control_ids": {"type": ["array", "null"], "items": {"type": "string"}},
                "platform": {"type": "string", "enum": PLATFORMS},
                "execute": {"type": "boolean", "default": False},
                "consent": {"type": "boolean", "default": False},
                "include_output": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "run_self_test",
        "description": "Run the built-in synthetic diagnostic evaluation. Uses no machine or user data.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
    },
]

_TOOL_TITLES = {
    "diagnose": "Diagnose a problem",
    "list_diagnostics": "List diagnostic rules",
    "get_control_catalog": "Browse PC controls",
    "audit_coverage": "Audit design coverage",
    "collect_context": "Plan or collect local context",
    "run_self_test": "Run synthetic self-test",
}
for _tool in TOOLS:
    _tool["title"] = _TOOL_TITLES[_tool["name"]]
    _tool["outputSchema"] = {"type": "object"}
    _tool["annotations"] = {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }


def response(
    request_id: Any,
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    payload["error" if error else "result"] = error if error is not None else result
    return payload


def _tool_result(data: Any) -> dict[str, Any]:
    return {
        "content": [
            {"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}
        ],
        "structuredContent": data,
    }


def _tool_error(message: str) -> dict[str, Any]:
    data = {"error": redact(message)}
    return {**_tool_result(data), "isError": True}


def _matches_type(value: Any, expected: str) -> bool:
    checks = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "boolean": lambda item: type(item) is bool,
        "null": lambda item: item is None,
    }
    return expected in checks and checks[expected](value)


def _validate_schema(
    value: Any, schema: dict[str, Any], path: str = "arguments"
) -> None:
    expected = schema.get("type")
    expected_types = (
        expected if isinstance(expected, list) else [expected] if expected else []
    )
    if expected_types and not any(
        _matches_type(value, item) for item in expected_types
    ):
        raise ValueError(f"{path} has an invalid type")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} must be one of: {', '.join(schema['enum'])}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ValueError(f"{path} is too short")
        if len(value) > schema.get("maxLength", len(value)):
            raise ValueError(f"{path} is too long")
    if isinstance(value, list):
        if len(value) > schema.get("maxItems", len(value)):
            raise ValueError(f"{path} contains too many items")
        if "items" in schema:
            for index, item in enumerate(value):
                _validate_schema(item, schema["items"], f"{path}[{index}]")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        missing = [key for key in schema.get("required", []) if key not in value]
        if missing:
            raise ValueError(f"{path} is missing required fields: {', '.join(missing)}")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - properties.keys())
            if unknown:
                raise ValueError(
                    f"{path} contains unknown fields: {', '.join(unknown)}"
                )
        for key, item in value.items():
            child_schema = properties.get(key)
            if child_schema is None and isinstance(
                schema.get("additionalProperties"), dict
            ):
                child_schema = schema["additionalProperties"]
            if child_schema is not None:
                _validate_schema(item, child_schema, f"{path}.{key}")


def _validate_tool_arguments(name: str, arguments: dict[str, Any]) -> None:
    tool = next((item for item in TOOLS if item["name"] == name), None)
    if tool is None:
        raise KeyError(name)
    _validate_schema(arguments, tool["inputSchema"])


def call_tool(
    name: str,
    arguments: dict[str, Any],
    engine: DiagnosticEngine,
    collector: SafeCollector,
) -> Any:
    _validate_tool_arguments(name, arguments)
    if name == "diagnose":
        return engine.diagnose(Problem(**arguments)).to_dict()
    if name == "list_diagnostics":
        items = [
            {"name": item.name, "supported_types": sorted(item.supported_types)}
            for item in DEFAULT_DIAGNOSTICS
        ]
        return {"total": len(items), "diagnostics": items}
    if name == "get_control_catalog":
        category = arguments.get("category")
        controls = [
            item
            for item in CONTROL_CATALOG
            if category is None or item.category == category
        ]
        return {
            "total": len(controls),
            "controls": [
                item.to_dict(bool(arguments.get("include_commands", False)))
                for item in controls
            ],
        }
    if name == "audit_coverage":
        return collector.design_coverage(arguments.get("platform"))
    if name == "collect_context":
        return collector.collect(
            arguments.get("control_ids"),
            execute=bool(arguments.get("execute", False)),
            consent=bool(arguments.get("consent", False)),
            include_output=bool(arguments.get("include_output", False)),
            platform_name=arguments.get("platform"),
        ).to_dict()
    if name == "run_self_test":
        return run_evaluation(engine)
    raise KeyError(name)


def handle(
    request: Any,
    engine: DiagnosticEngine,
    collector: SafeCollector | None = None,
) -> dict[str, Any] | None:
    if not isinstance(request, dict):
        return response(None, error={"code": -32600, "message": "Invalid Request"})
    if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        return response(
            request.get("id"), error={"code": -32600, "message": "Invalid Request"}
        )
    active_collector = collector or SafeCollector()
    method, request_id, params = (
        request.get("method"),
        request.get("id"),
        request.get("params", {}),
    )
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        protocol = requested if requested in LEGACY_PROTOCOLS else PROTOCOL
        return response(
            request_id,
            {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "wsai-fixcenter", "version": "0.2.0"},
            },
        )
    if method == "server/discover":
        return response(
            request_id,
            {
                "resultType": "complete",
                "supportedVersions": list(SUPPORTED_PROTOCOLS),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "wsai-fixcenter", "version": "0.2.0"},
                "instructions": "Diagnose supplied evidence first; plan collection before requesting explicit consent to execute read-only probes.",
                "ttlMs": 300_000,
                "cacheScope": "public",
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "wsai-fixcenter",
                        "version": "0.2.0",
                    }
                },
            },
        )
    if method == "ping":
        return response(request_id, {})
    if method == "tools/list":
        return response(
            request_id, {"tools": TOOLS, "ttlMs": 300_000, "cacheScope": "public"}
        )
    if method == "tools/call":
        if not isinstance(params, dict) or not isinstance(
            params.get("arguments", {}), dict
        ):
            return response(
                request_id,
                error={"code": -32602, "message": "params.arguments must be an object"},
            )
        name = params.get("name")
        try:
            data = call_tool(
                str(name), params.get("arguments", {}), engine, active_collector
            )
        except KeyError:
            return response(
                request_id, error={"code": -32601, "message": f"Unknown tool: {name}"}
            )
        except (TypeError, ValueError) as exc:
            return response(request_id, _tool_error(str(exc)))
        return response(request_id, _tool_result(data))
    return (
        response(
            request_id, error={"code": -32601, "message": f"Unknown method: {method}"}
        )
        if request_id is not None
        else None
    )


def serve() -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    engine, collector = DiagnosticEngine(), SafeCollector()
    for line in sys.stdin:
        try:
            request = json.loads(line)
            result = handle(request, engine, collector)
            if result is not None:
                sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError as exc:
            sys.stdout.write(
                json.dumps(
                    response(
                        None, error={"code": -32700, "message": f"Invalid JSON: {exc}"}
                    )
                )
                + "\n"
            )
            sys.stdout.flush()
        except Exception:
            logging.exception("Unhandled MCP request failure")
            sys.stdout.write(
                json.dumps(
                    response(None, error={"code": -32603, "message": "Internal error"})
                )
                + "\n"
            )
            sys.stdout.flush()


if (
    __name__ == "__main__"
):  # pragma: no cover - exercised through the package entry point
    serve()
