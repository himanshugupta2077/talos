"""
Module: talos.ai.tools.spec

Purpose:
    ToolSpec — protocol identity for a tool (safe to expose to planners / MCP).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class ToolSpec:
    """
    What a tool *is* (name, schemas, tags). Not an authority surface for
    timeouts, budgets, or approval policy.
    """

    name: str
    version: int
    description: str
    input_schema: dict[str, Any]
    output_schema: Optional[dict[str, Any]] = None
    tags: tuple[str, ...] = ()
    project_bound: bool = True

    def to_descriptor(self) -> dict[str, Any]:
        """JSON-friendly descriptor for tools list / planner packs."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "tags": list(self.tags),
            "project_bound": self.project_bound,
        }
