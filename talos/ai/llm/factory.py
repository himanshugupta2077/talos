"""
Module: talos.ai.llm.factory

Purpose:
    Build a Provider from AiConfig.
"""

from __future__ import annotations

from talos.ai.llm.anthropic import AnthropicProvider
from talos.ai.llm.base import Provider
from talos.ai.llm.config import AiConfig
from talos.ai.llm.none import NoneProvider
from talos.ai.llm.ollama import OllamaProvider
from talos.ai.llm.openai_compat import OpenAICompatProvider


def build_provider(config: AiConfig | None = None) -> Provider:
    """
    Purpose:
        Instantiate the configured LLM provider (default: none).
    """
    cfg = config or AiConfig()
    name = cfg.normalized_provider()
    if name == "none":
        return NoneProvider()
    if name == "ollama":
        return OllamaProvider(cfg)
    if name in ("openai-compatible", "openai"):
        return OpenAICompatProvider(cfg)
    if name == "anthropic":
        return AnthropicProvider(cfg)
    # Unknown → none (fail closed to offline heuristic path).
    return NoneProvider()
