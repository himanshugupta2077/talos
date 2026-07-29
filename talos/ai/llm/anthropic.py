"""
Module: talos.ai.llm.anthropic

Purpose:
    Anthropic Messages API adapter.
    No mandatory redaction gate (Key Decision 9).
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from talos.ai.llm.base import ChatMessage, CompleteResult, ProviderError, Role
from talos.ai.llm.config import AiConfig

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider:
    """Anthropic /v1/messages adapter."""

    name = "anthropic"

    def __init__(self, config: AiConfig) -> None:
        self._cfg = config
        base = (config.base_url or "").strip().rstrip("/")
        self._base_url = base or "https://api.anthropic.com"
        self._model = (config.model or "").strip() or "claude-3-5-haiku-latest"
        self._timeout = float(config.timeout_s or 60.0)
        self._api_key = config.resolve_api_key()

    def complete(
        self,
        messages: list[ChatMessage],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> CompleteResult:
        del tools  # JSON tool list is embedded in system prompt by LLMPlanner.
        if not self._api_key:
            raise ProviderError(
                "Anthropic provider needs an API key "
                f"(set {self._cfg.api_key_env or 'TALOS_AI_API_KEY'})"
            )

        system_parts: list[str] = []
        api_messages: list[dict[str, str]] = []
        for m in messages:
            role = m.role.value if isinstance(m.role, Role) else str(m.role)
            text = m.text()
            if role == Role.SYSTEM.value:
                system_parts.append(text)
                continue
            if role == Role.TOOL.value:
                role = Role.USER.value
                text = f"[tool result]\n{text}"
            if role == Role.ASSISTANT.value:
                api_messages.append({"role": "assistant", "content": text})
            else:
                api_messages.append({"role": "user", "content": text})

        # Anthropic requires alternating user/assistant; merge consecutive same roles.
        api_messages = _merge_consecutive(api_messages)
        if not api_messages:
            api_messages = [{"role": "user", "content": "(empty)"}]
        if api_messages[0]["role"] != "user":
            api_messages.insert(0, {"role": "user", "content": "(continue)"})

        payload: dict[str, Any] = {
            "model": self._model,
            "max_tokens": int(
                max_tokens if max_tokens is not None else self._cfg.max_tokens
            ),
            "temperature": (
                float(temperature)
                if temperature is not None
                else float(self._cfg.temperature)
            ),
            "messages": api_messages,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }
        url = f"{self._base_url}/v1/messages"
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"Anthropic timeout: {exc}", retryable=True
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"Anthropic HTTP error: {exc}", retryable=True
            ) from exc

        if resp.status_code == 401:
            raise ProviderError("Anthropic auth failed (401)", retryable=False)
        if resp.status_code == 429:
            raise ProviderError("Anthropic rate limited (429)", retryable=True)
        if resp.status_code >= 400:
            raise ProviderError(
                f"Anthropic HTTP {resp.status_code}: {resp.text[:500]}",
                retryable=resp.status_code >= 500,
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise ProviderError(f"Anthropic non-JSON: {exc}") from exc

        text_parts: list[str] = []
        for block in body.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(str(block.get("text") or ""))
        text = "\n".join(text_parts)

        usage_raw = body.get("usage") or {}
        raw_usage: dict[str, Any] = {}
        if usage_raw:
            try:
                inp = int(usage_raw.get("input_tokens") or 0)
                out = int(usage_raw.get("output_tokens") or 0)
                raw_usage = {
                    "prompt_tokens": inp,
                    "completion_tokens": out,
                    "total_tokens": inp + out,
                    "input_tokens": inp,
                    "output_tokens": out,
                }
            except (TypeError, ValueError):
                raw_usage = dict(usage_raw)

        return CompleteResult(
            text=text,
            raw_usage=raw_usage,
            model=str(body.get("model") or self._model),
        )


def _merge_consecutive(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    if not messages:
        return []
    out: list[dict[str, str]] = [dict(messages[0])]
    for m in messages[1:]:
        if m["role"] == out[-1]["role"]:
            out[-1]["content"] = out[-1]["content"] + "\n\n" + m["content"]
        else:
            out.append(dict(m))
    return out
