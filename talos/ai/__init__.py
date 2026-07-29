"""
Module: talos.ai

Purpose:
    Policy-gated AI agent layer for Talos. Phase A ships the Workflow Engine
    foundation (sessions, project pin, budgets, audit), the Talos Tool Protocol
    (ToolSpec / ToolPolicy / ToolHandler), PolicyValidator → sealed
    ExecutionPlan, Executor, and READ + role/module context tools.

    Planner loop, notes store, MCP, LLM providers, and active HTTP tools
    land in later phases (see docs/design-talos-ai-layer.md).

Dependencies: talos.ai.models, talos.ai.workflow, talos.ai.tools
Data flow:
    CLI / tests → WorkflowEngine → PolicyValidator → Executor → ToolHandler
Side effects: None at import time (tool bindings register on first registry use).
"""

from talos.ai.models import (
    AutonomyMode,
    BudgetLimits,
    BudgetUsage,
    Capability,
    ProjectContext,
)

__all__ = [
    "AutonomyMode",
    "BudgetLimits",
    "BudgetUsage",
    "Capability",
    "ProjectContext",
]
