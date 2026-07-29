"""
Module: talos.ai.llm

Purpose:
    LLM provider abstraction for the AI planner layer (Phase C / PR6).
    Operator-configured only — never registered as tools.
    No client-data redaction module (Key Decision 9).

Public surface:
    load_ai_config, save_ai_config, AiConfig, build_provider, Provider, …
"""

from talos.ai.llm.base import (
    ChatMessage,
    CompleteResult,
    Provider,
    ProviderError,
    Role,
    estimate_tokens,
)
from talos.ai.llm.config import (
    AI_CONFIG_ENV_API_KEY,
    AiConfig,
    load_ai_config,
    save_ai_config,
    unset_ai_config_keys,
)
from talos.ai.llm.factory import build_provider

__all__ = [
    "AI_CONFIG_ENV_API_KEY",
    "AiConfig",
    "ChatMessage",
    "CompleteResult",
    "Provider",
    "ProviderError",
    "Role",
    "build_provider",
    "estimate_tokens",
    "load_ai_config",
    "save_ai_config",
    "unset_ai_config_keys",
]
