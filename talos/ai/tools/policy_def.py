"""
Module: talos.ai.tools.policy_def

Purpose:
    ToolPolicy — how Talos treats a tool (capabilities, approval, budgets).
    Not exposed to models as negotiable authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from talos.ai.models import BudgetClass, Capability


@dataclass(frozen=True)
class ToolPolicy:
    """Policy knobs for one registered tool."""

    capabilities: frozenset[Capability]
    requires_approval: bool
    idempotent: bool = False
    timeout_s: Optional[float] = None
    max_result_bytes: int = 64_000
    budget_class: BudgetClass = BudgetClass.NONE

    def summary(self) -> dict:
        """Non-sensitive summary for operator UX (not planner authority)."""
        return {
            "capabilities": sorted(c.value for c in self.capabilities),
            "requires_approval": self.requires_approval,
            "idempotent": self.idempotent,
            "budget_class": self.budget_class.value,
        }
