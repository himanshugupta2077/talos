"""
Module: talos.ai

Purpose:
    Policy-gated AI agent layer for Talos (authorized BB / client pentest).

    Phase A: Workflow Engine (sessions, pin, budgets, audit), TTP
    (ToolSpec / ToolPolicy / ToolHandler), PolicyValidator → sealed
    ExecutionPlan, Executor, READ + role/module context tools.

    Phase B: structured app notes, immutable suggestions + ExecutionPlans,
    PTT, observations, offline heuristic planner, suggest/approve/deny.

    Phase C: stdio MCP server + LLM providers (none/ollama/openai-compatible/
    anthropic) + operator config. No client-data redaction module
    (Key Decision 9 — authorized BB/pentest product).

    Later: HTTP send/replay, engines, KB, Control Panel (see design doc).

Dependencies: talos.ai.models, talos.ai.workflow, talos.ai.tools
Data flow:
    CLI / MCP / tests → WorkflowEngine → Planner / PolicyValidator → Executor
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
