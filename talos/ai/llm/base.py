"""
Module: talos.ai.llm.base

Purpose:
    Shared types and protocol for LLM providers used by LLMPlanner.
    Providers are pure-ish HTTP clients — no session/DB writes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class ChatMessage:
    """One chat turn for provider.complete."""

    role: Role
    content: str | dict[str, Any]
    tool_call_id: Optional[str] = None
    name: Optional[str] = None

    def text(self) -> str:
        if isinstance(self.content, str):
            return self.content
        try:
            import json

            return json.dumps(self.content, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return str(self.content)


@dataclass
class CompleteResult:
    """Normalized provider completion."""

    text: str
    raw_usage: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    model: Optional[str] = None

    @property
    def ok(self) -> bool:
        return not self.error


class ProviderError(Exception):
    """Provider transport / API failure (not a policy error)."""

    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


@runtime_checkable
class Provider(Protocol):
    """Swappable LLM backend."""

    name: str

    def complete(
        self,
        messages: list[ChatMessage],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> CompleteResult:
        """
        Purpose:
            Run one completion turn. Must not write Talos session tables.
        """
        ...


def estimate_tokens(text: str) -> int:
    """
    Purpose:
        Rough token estimate when the API omits usage (chars/4).
    """
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


def usage_total_tokens(raw_usage: dict[str, Any], *, fallback_chars: int = 0) -> int:
    """
    Purpose:
        Extract total tokens from provider usage, or estimate from char count.
    """
    if raw_usage:
        for key in ("total_tokens", "total", "input_tokens", "prompt_tokens"):
            if key in raw_usage and raw_usage[key] is not None:
                try:
                    total = int(raw_usage[key])
                    # Prefer explicit total; if only prompt, add completion if present.
                    if key in ("total_tokens", "total"):
                        return max(0, total)
                except (TypeError, ValueError):
                    pass
        prompt = 0
        completion = 0
        try:
            prompt = int(
                raw_usage.get("prompt_tokens")
                or raw_usage.get("input_tokens")
                or 0
            )
        except (TypeError, ValueError):
            prompt = 0
        try:
            completion = int(
                raw_usage.get("completion_tokens")
                or raw_usage.get("output_tokens")
                or 0
            )
        except (TypeError, ValueError):
            completion = 0
        if prompt or completion:
            return max(0, prompt + completion)
    if fallback_chars > 0:
        return estimate_tokens("x" * fallback_chars)
    return 0
