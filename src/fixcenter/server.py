from __future__ import annotations

import json
import logging
import sys
from typing import Any

from fixcenter.engine import DiagnosticEngine
from fixcenter.models import Problem

PROTOCOL = "2024-11-05"
TOOLS = [
    {"name": "diagnose", "description": "Diagnostiquer un problème de hook, plugin, skill ou configuration.", "inputSchema": {"type": "object", "required": ["description"], "properties": {
        "description": {"type": "string"}, "problem_type": {"type": "string", "enum": ["hook", "plugin", "skill", "config", "unknown"]},
        "logs": {"type": "array", "items": {"type": "string"}}, "config": {"type": "object"}, "components": {"type": "array", "items": {"type": "string"}},
        "environment": {"type": "object", "additionalProperties": {"type": "string"}}, "workspace": {"type": ["string", "null"]}}}},
    {"name": "list_diagnostics", "description": "Lister les diagnostics disponibles.", "inputSchema": {"type": "object", "properties": {}}},
]


def response(request_id: Any, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    payload["error" if error else "result"] = error or result
    return payload


def handle(request: dict[str, Any], engine: DiagnosticEngine) -> dict[str, Any] | None:
    method, request_id, params = request.get("method"), request.get("id"), request.get("params", {})
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return response(request_id, {"protocolVersion": PROTOCOL, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "wsai-fixcenter", "version": "0.1.0"}})
    if method == "tools/list":
        return response(request_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        if name == "list_diagnostics":
            from fixcenter.diagnostics.base import DEFAULT_DIAGNOSTICS
            data = [{"name": item.name, "supported_types": sorted(item.supported_types)} for item in DEFAULT_DIAGNOSTICS]
        elif name == "diagnose":
            try:
                report = engine.diagnose(Problem(**params.get("arguments", {})))
                data = report.to_dict()
            except (TypeError, ValueError) as exc:
                return response(request_id, error={"code": -32602, "message": str(exc)})
        else:
            return response(request_id, error={"code": -32601, "message": f"Unknown tool: {name}"})
        return response(request_id, {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}], "structuredContent": data})
    return response(request_id, error={"code": -32601, "message": f"Unknown method: {method}"}) if request_id is not None else None


def serve() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    engine = DiagnosticEngine()
    for line in sys.stdin:
        try:
            request = json.loads(line)
            result = handle(request, engine)
            if result is not None:
                sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError as exc:
            sys.stdout.write(json.dumps(response(None, error={"code": -32700, "message": f"Invalid JSON: {exc}"})) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    serve()
