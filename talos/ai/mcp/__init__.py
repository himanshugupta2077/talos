"""
Module: talos.ai.mcp

Purpose:
    stdio MCP adapter over WorkflowEngine (Phase C / PR5).
    No network MCP. No handler shortcuts.
"""

from talos.ai.mcp.server import McpServer, run_stdio_server

__all__ = ["McpServer", "run_stdio_server"]
