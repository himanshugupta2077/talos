"""
Module: talos.ai.llm.ollama

Purpose:
    Local Ollama chat API adapter (http://127.0.0.1:11434 by default).
    No mandatory redaction gate (Key Decision 9).
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from talos.ai.llm.base import ChatMessage, CompleteResult, ProviderError, Role
from talos.ai.llm.config import AiConfig


class OllamaProvider:
    """Ollama /api/chat adapter."""

    name = "ollama"

    def __init__(self, config: AiConfig) -> None:
        self._cfg = config
        base = (config.base_url or "").strip().rstrip("/")
        self._base_url = base or "http://127.0.0.1:11434"
        self._model = (config.model or "").strip() or "llama3.2"
        self._timeout = float(config.timeout_s or 60.0)

    def complete(
        self,
        messages: list[ChatMessage],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> CompleteResult:
        del tools  # Ollama tool calling varies; JSON instructions in system prompt.
        payload: dict[str, Any] = {
            "model": self._model,
            "stream": False,
            "messages": [_to_ollama_message(m) for m in messages],
            "options": {
                "temperature": (
                    float(temperature)
                    if temperature is not None
                    else float(self._cfg.temperature)
                ),
            },
        }
        if max_tokens is not None or self._cfg.max_tokens:
            payload["options"]["num_predict"] = int(
                max_tokens if max_tokens is not None else self._cfg.max_tokens
            )

        url = f"{self._base_url}/api/chat"
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"Ollama timeout talking to {url}: {exc}", retryable=True
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"Ollama unreachable at {url}: {exc}", retryable=True
            ) from exc

        if resp.status_code >= 400:
            retryable = resp.status_code >= 500 or resp.status_code == 429
            raise ProviderError(
                f"Ollama HTTP {resp.status_code}: {resp.text[:500]}",
                retryable=retryable,
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise ProviderError(f"Ollama returned non-JSON: {exc}") from exc

        msg = body.get("message") or {}
        text = msg.get("content") or ""
        raw_usage: dict[str, Any] = {}
        if "prompt_eval_count" in body or "eval_count" in body:
            prompt_t = int(body.get("prompt_eval_count") or 0)
            comp_t = int(body.get("eval_count") or 0)
            raw_usage = {
                "prompt_tokens": prompt_t,
                "completion_tokens": comp_t,
                "total_tokens": prompt_t + comp_t,
            }
        return CompleteResult(
            text=str(text),
            raw_usage=raw_usage,
            model=str(body.get("model") or self._model),
        )


def _to_ollama_message(msg: ChatMessage) -> dict[str, str]:
    role = msg.role.value if isinstance(msg.role, Role) else str(msg.role)
    if role == Role.TOOL.value:
        role = "user"
    return {"role": role, "content": msg.text()}
