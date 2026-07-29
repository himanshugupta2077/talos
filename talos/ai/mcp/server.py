"""
Module: talos.ai.mcp.server

Purpose:
    Minimal JSON-RPC MCP server over stdio.
    tools/list → ToolRegistry (ToolSpec descriptors only).
    tools/call → WorkflowEngine.external_tool_call (PolicyValidator + Executor).

    Never invokes handlers directly. Never shells out to talos CLI for tools.
    Network MCP is out of scope (stdio only).
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, Optional, TextIO

from talos.ai.tools.registry import ToolRegistry, default_registry
from talos.ai.workflow.engine import WorkflowEngine, WorkflowEngineError

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "talos-ai"
SERVER_VERSION = "0.1.0"


class McpServer:
    """
    In-process MCP handler bound to one WorkflowEngine + frozen session pin.
    """

    def __init__(
        self,
        engine: WorkflowEngine,
        *,
        session_id: Optional[str] = None,
        registry: Optional[ToolRegistry] = None,
    ) -> None:
        self.engine = engine
        self.session_id = session_id
        self._registry = registry
        self._initialized = False

    @property
    def registry(self) -> ToolRegistry:
        if self._registry is not None:
            return self._registry
        return self.engine.registry

    def handle_message(self, message: dict[str, Any]) -> Optional[dict[str, Any]]:
        """
        Purpose:
            Dispatch one JSON-RPC request/notification.
        Output:
            Response dict, or None for notifications.
        """
        if not isinstance(message, dict):
            return _error_response(None, -32600, "Invalid Request")

        method = message.get("method")
        msg_id = message.get("id", None)
        params = message.get("params") or {}
        if not isinstance(params, dict):
            params = {}

        # Notifications have no id (or explicit null in some clients).
        is_notification = "id" not in message

        if method == "notifications/initialized":
            self._initialized = True
            return None

        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
                "instructions": (
                    "Talos AI MCP (stdio). All tools run through WorkflowEngine "
                    "→ PolicyValidator → Executor. Session mode applies: "
                    "suggest-only and tools requiring approval return "
                    "needs_approval + plan_id/suggestion_id (approve via "
                    "talos ai approve). No network MCP. No config/API-key tools."
                ),
            }
            self._initialized = True
            return _result_response(msg_id, result)

        if method == "ping":
            return _result_response(msg_id, {})

        if method == "tools/list":
            tools = self._list_tools_mcp()
            return _result_response(msg_id, {"tools": tools})

        if method == "tools/call":
            raw_name = params.get("name")
            name = str(raw_name).strip() if raw_name is not None else ""
            arguments, args_error = _normalize_mcp_arguments(params.get("arguments"))
            if args_error is not None:
                return _result_response(
                    msg_id,
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(args_error, sort_keys=True),
                            }
                        ],
                        "isError": True,
                        "structuredContent": args_error,
                    },
                )
            if not name:
                return _result_response(
                    msg_id,
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {
                                        "status": "error",
                                        "code": "missing_tool_name",
                                        "message": "tools/call requires name",
                                    }
                                ),
                            }
                        ],
                        "isError": True,
                    },
                )
            try:
                payload = self.engine.external_tool_call(
                    name,
                    arguments,
                    session_id=self.session_id,
                    reason="mcp tools/call",
                )
            except WorkflowEngineError as exc:
                payload = {
                    "status": "error",
                    "code": "engine_error",
                    "message": str(exc),
                    "exit_code": exc.exit_code,
                }
            is_error = payload.get("status") in (
                "error",
                "rejected",
            )
            # needs_approval is not an MCP transport error — structured result.
            return _result_response(
                msg_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(payload, sort_keys=True, default=str),
                        }
                    ],
                    "isError": bool(is_error),
                    "structuredContent": payload,
                },
            )

        if is_notification:
            return None

        if method is None:
            return _error_response(msg_id, -32600, "Invalid Request: missing method")

        return _error_response(msg_id, -32601, f"Method not found: {method}")

    def _list_tools_mcp(self) -> list[dict[str, Any]]:
        """ToolSpec descriptors only (no policy authority knobs)."""
        out: list[dict[str, Any]] = []
        for desc in self.registry.list_tools():
            spec = desc.spec
            out.append(
                {
                    "name": spec.name,
                    "description": spec.description or spec.name,
                    "inputSchema": spec.input_schema
                    if isinstance(spec.input_schema, dict)
                    else {"type": "object", "properties": {}},
                }
            )
        return out


def run_stdio_server(
    engine: WorkflowEngine,
    *,
    session_id: Optional[str] = None,
    stdin: Optional[TextIO] = None,
    stdout: Optional[TextIO] = None,
) -> int:
    """
    Purpose:
        Serve MCP over stdio until EOF. Returns process exit code.
    """
    server = McpServer(engine, session_id=session_id)
    inn = stdin if stdin is not None else sys.stdin
    out = stdout if stdout is not None else sys.stdout

    # Ensure unbuffered-ish writes for clients.
    while True:
        line = inn.readline()
        if line == "":
            break
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            resp = _error_response(None, -32700, f"Parse error: {exc}")
            _write(out, resp)
            continue
        if not isinstance(message, dict):
            resp = _error_response(None, -32600, "Invalid Request")
            _write(out, resp)
            continue
        try:
            response = server.handle_message(message)
        except Exception as exc:  # noqa: BLE001 — keep MCP loop alive
            logger.exception("MCP handler crash")
            response = _error_response(
                message.get("id"),
                -32603,
                f"Internal error: {exc}",
            )
        if response is not None:
            _write(out, response)
    return 0


def _write(out: TextIO, response: dict[str, Any]) -> None:
    out.write(json.dumps(response, separators=(",", ":"), default=str))
    out.write("\n")
    out.flush()


def _result_response(msg_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error_response(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": code, "message": message},
    }


def _normalize_mcp_arguments(
    raw: Any,
) -> tuple[dict[str, Any], Optional[dict[str, Any]]]:
    """
    Purpose:
        Coerce MCP tools/call arguments to a dict.
        - None / missing → {}
        - dict → as-is
        - JSON object string → parsed dict
        - anything else → error payload (do not silently drop client args)
    """
    if raw is None:
        return {}, None
    if isinstance(raw, dict):
        return dict(raw), None
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}, None
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            err = {
                "status": "error",
                "code": "invalid_arguments",
                "message": f"arguments JSON string is not valid JSON: {exc}",
            }
            return {}, err
        if not isinstance(parsed, dict):
            err = {
                "status": "error",
                "code": "invalid_arguments",
                "message": (
                    "arguments JSON string must decode to an object "
                    f"(got {type(parsed).__name__})"
                ),
            }
            return {}, err
        return dict(parsed), None
    err = {
        "status": "error",
        "code": "invalid_arguments",
        "message": (
            "arguments must be a JSON object "
            f"(got {type(raw).__name__})"
        ),
    }
    return {}, err
