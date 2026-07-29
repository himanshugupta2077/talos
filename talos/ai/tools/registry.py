"""
Module: talos.ai.tools.registry

Purpose:
    ToolRegistry — list/get/describe only. **No public call() or execute().**
    The sole invoke path is PolicyValidator → Executor → ToolHandler.

Dependencies: talos.ai.tools.spec, policy_def, handler
Data flow:
    bindings.register → registry; PolicyValidator / CLI tools list → get_spec
Side effects: None beyond in-memory registration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from talos.ai.tools.handler import ToolHandler
from talos.ai.tools.policy_def import ToolPolicy
from talos.ai.tools.spec import ToolSpec


@dataclass(frozen=True)
class ToolDescriptor:
    """Operator / planner-facing tool description."""

    spec: ToolSpec
    policy_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        out = self.spec.to_descriptor()
        out["policy"] = self.policy_summary
        return out


class ToolRegistry:
    """
    Allowlist registry. Intentionally has no call()/execute() method.
    """

    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._policies: dict[str, ToolPolicy] = {}
        self._handlers: dict[str, ToolHandler] = {}

    def register(
        self,
        spec: ToolSpec,
        policy: ToolPolicy,
        handler: ToolHandler,
    ) -> None:
        """
        Purpose: Bind identity + policy + handler under spec.name.
        Raises: ValueError on duplicate name.
        """
        if not spec.name:
            raise ValueError("ToolSpec.name is required")
        if spec.name in self._specs:
            raise ValueError(f"Tool already registered: {spec.name}")
        self._specs[spec.name] = spec
        self._policies[spec.name] = policy
        self._handlers[spec.name] = handler

    def list_tools(self) -> list[ToolDescriptor]:
        """Return descriptors sorted by name."""
        names = sorted(self._specs.keys())
        return [
            ToolDescriptor(
                spec=self._specs[n],
                policy_summary=self._policies[n].summary(),
            )
            for n in names
        ]

    def get_spec(self, name: str) -> ToolSpec:
        if name not in self._specs:
            raise KeyError(f"Unknown tool: {name}")
        return self._specs[name]

    def get_policy(self, name: str) -> ToolPolicy:
        if name not in self._policies:
            raise KeyError(f"Unknown tool: {name}")
        return self._policies[name]

    def has_tool(self, name: str) -> bool:
        return name in self._specs

    def names(self) -> list[str]:
        return sorted(self._specs.keys())

    def _get_handler(self, name: str) -> ToolHandler:
        """
        Internal: resolve handler for Executor only.
        Not part of the public TTP surface — do not call from planners/CLI.
        """
        if name not in self._handlers:
            raise KeyError(f"Unknown tool: {name}")
        return self._handlers[name]


_DEFAULT: Optional[ToolRegistry] = None


def default_registry() -> ToolRegistry:
    """
    Purpose:
        Return the process-wide default registry, bootstrapping bindings once.
    Side effects:
        First call imports talos.ai.tools.bindings and registers all tools.
    """
    global _DEFAULT
    if _DEFAULT is None:
        reg = ToolRegistry()
        from talos.ai.tools.bindings import register_all_tools

        register_all_tools(reg)
        _DEFAULT = reg
    return _DEFAULT


def reset_default_registry_for_tests() -> None:
    """Clear the singleton so tests can re-bind a fresh registry."""
    global _DEFAULT
    _DEFAULT = None
