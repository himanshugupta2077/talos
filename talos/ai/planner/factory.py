"""
Module: talos.ai.planner.factory

Purpose:
    Build the default Planner for WorkflowEngine from operator AI config.
"""

from __future__ import annotations

from typing import Optional

from talos.ai.llm.config import AiConfig, load_ai_config
from talos.ai.planner.base import Planner
from talos.ai.planner.heuristic import HeuristicPlanner
from talos.ai.planner.llm_planner import LLMPlanner
from talos.ai.tools.registry import ToolRegistry


def build_planner(
    config: Optional[AiConfig] = None,
    *,
    registry: Optional[ToolRegistry] = None,
) -> Planner:
    """
    Purpose:
        provider=none → HeuristicPlanner; else LLMPlanner (with heuristic fallback).
    """
    cfg = config if config is not None else load_ai_config()
    if cfg.normalized_provider() == "none":
        return HeuristicPlanner(registry)
    return LLMPlanner(config=cfg, registry=registry)
