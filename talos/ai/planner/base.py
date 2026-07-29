"""
Module: talos.ai.planner.base

Purpose:
    Planner protocol and PlanRequest dataclass. Planners are pure-ish:
    must not open DB writes for session/approve/plans.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable

from talos.ai.models import ActionSuggestion, Capability
from talos.ai.tools.spec import ToolSpec


@dataclass(frozen=True)
class PlanRequest:
    """Context pack for one planner turn (built by WorkflowEngine)."""

    session_id: str
    goal: str
    mode: str
    granted_capabilities: frozenset[Capability]
    tool_descriptors: list[ToolSpec]
    notes_pack: dict[str, Any] = field(default_factory=dict)
    kb_hits: list[dict[str, Any]] = field(default_factory=list)
    ptt_frontier: list[dict[str, Any]] = field(default_factory=list)
    budgets_summary: dict[str, Any] = field(default_factory=dict)
    recent_observations: list[dict[str, Any]] = field(default_factory=list)
    max_suggestions: int = 5
    # Optional live inventory signals for offline heuristic (not sent to LLM).
    inventory_signals: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Planner(Protocol):
    """Interchangeable producer of immutable ActionSuggestions."""

    def plan(self, request: PlanRequest) -> list[ActionSuggestion]:
        """
        Pure-ish: must not write session/approve/plan tables.
        Engine persists returned suggestions.
        """
        ...
