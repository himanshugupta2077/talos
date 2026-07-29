"""
Module: talos.ai.llm.none

Purpose:
    provider=none — no cloud/local LLM. Signals planner to use heuristic.
"""

from __future__ import annotations

from typing import Any, Optional

from talos.ai.llm.base import ChatMessage, CompleteResult, ProviderError


class NoneProvider:
    """Explicit no-op provider; complete() always fails closed for LLM path."""

    name = "none"

    def complete(
        self,
        messages: list[ChatMessage],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> CompleteResult:
        del messages, tools, temperature, max_tokens
        return CompleteResult(
            text="",
            error="provider=none (use HeuristicPlanner or configure an LLM)",
            raw_usage={},
        )

    def complete_or_raise(self, *args: Any, **kwargs: Any) -> CompleteResult:
        raise ProviderError("provider=none — no LLM configured")
