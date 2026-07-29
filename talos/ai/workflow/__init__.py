"""
Package: talos.ai.workflow

Purpose:
    Workflow Engine — owns AI session lifecycle, project pin, budgets,
    and (later) PTT / suggestions / approvals. CLI talks only to this façade.

    Import WorkflowEngine from talos.ai.workflow.engine to avoid circular
    imports with policy/executor (this package __init__ stays lightweight).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from talos.ai.workflow.engine import WorkflowEngine

__all__ = ["WorkflowEngine"]


def __getattr__(name: str):
    if name == "WorkflowEngine":
        from talos.ai.workflow.engine import WorkflowEngine as _WorkflowEngine

        return _WorkflowEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
