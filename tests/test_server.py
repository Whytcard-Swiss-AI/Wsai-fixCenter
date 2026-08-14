import io
import json

import pytest

from wsai_fckdot.collector import SafeCollector
from wsai_fckdot.engine import DiagnosticEngine
from wsai_fckdot.server import (
    MODERN_PROTOCOL,
    PROTOCOL,
    SUPPORTED_PROTOCOLS,
    TOOLS,
    _validate_schema,
    call_tool,
    handle,
    response,
    serve,
)
from wsai_fckdot.setup_manager import SetupManager


def request(method, request_id=1, params=None):
    data = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        data["params"] = params
    return data


def test_response_shapes():
    assert response(1, {"ok": True})["result"] == {"ok": True}
    assert response(1, error={"code": 1})["error"] == {"code": 1}


def test_initialize_ping_notifications_and_tool_list():
    engine = DiagnosticEngine()
    assert handle(request("notifications/initialized", request_id=None), engine) is None
    initialized = handle(
        request("initialize", params={"protocolVersion": PROTOCOL}), engine
    )
    assert initialized["result"]["protocolVersion"] == PROTOCOL
    fallback = handle(request("initialize", params="bad"), engine)
    assert fallback["result"]["serverInfo"]["version"] == "1.0.0"
    assert handle(request("ping"), engine)["result"] == {}
    tool_list = handle(request("tools/list"), engine)["result"]
    assert len(tool_list["tools"]) == len(TOOLS) == 10
    assert tool_list["ttlMs"] == 300_000 and tool_list["cacheScope"] == "public"
    assert all(item["outputSchema"] == {"type": "object"} for item in TOOLS)
    assert (
        next(item for item in TOOLS if item["name"] == "apply_setup")["annotations"][
            "readOnlyHint"
        ]
        is False
    )
    assert (
        next(item for item in TOOLS if item["name"] == "apply_setup")["annotations"][
            "idempotentHint"
        ]
        is False
    )
    assert (
        next(item for item in TOOLS if item["name"] == "apply_setup")["annotations"][
            "destructiveHint"
        ]
        is True
    )
    discover = handle(
        request(
            "server/discover",
            params={
                "_meta": {"io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL}
            },
        ),
        engine,
    )["result"]
    assert discover["supportedVersions"] == list(SUPPORTED_PROTOCOLS)
    assert discover["resultType"] == "complete"


@pytest.mark.parametrize(
    "name,arguments,check",
    [
        (
            "diagnose",
            {"description": "Plugin not found", "problem_type": "plugin"},
            lambda d: d["findings"][0]["id"] == "component-missing",
        ),
        ("list_diagnostics", {}, lambda d: d["total"] == len(d["diagnostics"]) == 15),
        ("get_control_catalog", {}, lambda d: d["total"] == 38),
        (
            "get_control_catalog",
            {"category": "agents", "include_commands": True},
            lambda d: d["total"] == 9 and isinstance(d["controls"][0]["probes"], dict),
        ),
        (
            "audit_coverage",
            {"platform": "windows"},
            lambda d: d["design_coverage_percent"] == 100.0,
        ),
        (
            "collect_context",
            {"control_ids": ["os.identity"], "platform": "windows"},
            lambda d: d["observations"][0]["status"] == "planned",
        ),
        ("run_self_test", {}, lambda d: d["success_rate_percent"] == 100.0),
    ],
)
def test_all_tool_calls(name, arguments, check):
    result = handle(
        request("tools/call", params={"name": name, "arguments": arguments}),
        DiagnosticEngine(),
    )
    data = result["result"]["structuredContent"]
    assert check(data)
    assert json.loads(result["result"]["content"][0]["text"]) == data


def test_tool_errors_and_unknown_methods():
    engine = DiagnosticEngine()
    malformed = handle(
        request("tools/call", params={"name": "diagnose", "arguments": []}), engine
    )
    assert malformed["error"]["code"] == -32602
    invalid = handle(
        request(
            "tools/call", params={"name": "diagnose", "arguments": {"description": ""}}
        ),
        engine,
    )
    assert invalid["result"]["isError"] is True
    assert "too short" in invalid["result"]["structuredContent"]["error"]
    unknown = handle(
        request("tools/call", params={"name": "nope", "arguments": {}}), engine
    )
    assert unknown["error"]["code"] == -32601
    assert handle(request("unknown"), engine)["error"]["code"] == -32601
    assert handle({"jsonrpc": "2.0", "method": "unknown"}, engine) is None
    assert handle([], engine)["error"]["code"] == -32600
    assert (
        handle({"jsonrpc": "1.0", "id": 2, "method": "ping"}, engine)["error"]["code"]
        == -32600
    )
    assert handle({"jsonrpc": "2.0", "id": 2}, engine)["error"]["code"] == -32600
    with pytest.raises(KeyError):
        call_tool("nope", {}, engine, SafeCollector())
    TOOLS.append({"name": "unimplemented", "inputSchema": {"type": "object"}})
    try:
        with pytest.raises(KeyError):
            call_tool("unimplemented", {}, engine, SafeCollector())
    finally:
        TOOLS.pop()


def test_setup_tools_through_mcp(tmp_path):
    workspace, home = tmp_path / "workspace", tmp_path / "home"
    workspace.mkdir()
    home.mkdir()
    setup = SetupManager(home=home, environ={})
    engine = DiagnosticEngine()
    manifest = {
        "version": 1,
        "active_profile": "personal",
        "profiles": {"personal": {"variables": {}}},
        "instructions": ["Write tests."],
        "tools": ["agents"],
    }

    def setup_call(name, arguments):
        result = handle(
            request("tools/call", params={"name": name, "arguments": arguments}),
            engine,
            setup_manager=setup,
        )
        return result["result"]["structuredContent"]

    assert setup_call("get_setup_catalog", {})["manifest_version"] == 1
    inventory = setup_call("inspect_setup", {"root": str(workspace), "consent": True})
    assert inventory["workspace"]["known_tool_directories"] == {}
    plan = setup_call(
        "plan_setup",
        {"root": str(workspace), "manifest": manifest, "consent": True},
    )
    applied = setup_call(
        "apply_setup",
        {
            "root": str(workspace),
            "manifest": manifest,
            "plan_id": plan["plan_id"],
            "consent": True,
        },
    )
    assert applied["applied"] is True


def test_setup_filesystem_errors_are_sanitized(tmp_path):
    class BrokenSetup:
        def catalog(self):
            raise PermissionError(f"private path {tmp_path}")

    result = handle(
        request("tools/call", params={"name": "get_setup_catalog", "arguments": {}}),
        DiagnosticEngine(),
        setup_manager=BrokenSetup(),
    )["result"]
    assert result["isError"] is True
    assert "PermissionError" in result["structuredContent"]["error"]
    assert str(tmp_path) not in result["structuredContent"]["error"]


@pytest.mark.parametrize(
    "name,arguments,message",
    [
        ("diagnose", {}, "missing required"),
        ("diagnose", {"description": 3}, "invalid type"),
        ("diagnose", {"description": "x", "problem_type": "other"}, "must be one"),
        ("diagnose", {"description": "x", "extra": True}, "unknown fields"),
        ("diagnose", {"description": "x", "logs": [3]}, "invalid type"),
        ("diagnose", {"description": "x", "logs": ["x"] * 201}, "too many"),
        ("diagnose", {"description": "x" * 20_001}, "too long"),
        ("diagnose", {"description": "x", "environment": {"A": 3}}, "invalid type"),
        ("collect_context", {"execute": "false", "consent": "true"}, "invalid type"),
    ],
)
def test_schema_validation_rejects_untrusted_arguments(name, arguments, message):
    result = handle(
        request("tools/call", params={"name": name, "arguments": arguments}),
        DiagnosticEngine(),
    )
    assert result["result"]["isError"] is True
    assert message in result["result"]["structuredContent"]["error"]


def test_schema_validator_allows_unconstrained_collections():
    _validate_schema(["anything"], {"type": "array"})
    _validate_schema({"anything": "goes"}, {"type": "object"})


def test_serve_processes_valid_and_invalid_lines(monkeypatch):
    input_lines = "not-json\n[]\n" + json.dumps(request("ping")) + "\n"
    output = io.StringIO()
    monkeypatch.setattr("sys.stdin", io.StringIO(input_lines))
    monkeypatch.setattr("sys.stdout", output)
    serve()
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700
    assert lines[1]["error"]["code"] == -32600
    assert lines[2]["result"] == {}


def test_serve_suppresses_notification_responses(monkeypatch):
    output = io.StringIO()
    notification = request("notifications/initialized", request_id=None)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(notification) + "\n"))
    monkeypatch.setattr("sys.stdout", output)
    serve()
    assert output.getvalue() == ""


def test_serve_contains_unexpected_failures(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(request("ping")) + "\n"))
    monkeypatch.setattr("sys.stdout", output)
    monkeypatch.setattr(
        "wsai_fckdot.server.handle",
        lambda *_: (_ for _ in ()).throw(RuntimeError("secret")),
    )
    serve()
    result = json.loads(output.getvalue())
    assert result["error"] == {"code": -32603, "message": "Internal error"}
