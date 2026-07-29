"""
Package: talos.ai.tools

Purpose:
    Talos Tool Protocol (TTP): ToolSpec identity, ToolPolicy, ToolHandler,
    registry (list/get only — no public call()), schemas, and bindings.
"""

from talos.ai.tools.registry import ToolRegistry, default_registry

__all__ = ["ToolRegistry", "default_registry"]
