"""
Module: talos.ai.llm.openai_compat

Purpose:
    OpenAI-compatible Chat Completions API (OpenAI, local proxies, etc.).
    No mandatory redaction gate (Key Decision 9).
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from talos.ai.llm.base import ChatMessage, CompleteResult, ProviderError, Role
from talos.ai.llm.config import AiConfig


class OpenAICompatProvider:
    """OpenAI-compatible /v1/chat/completions adapter."""

    name = "openai-compatible"

    def __init__(self, config: AiConfig) -> None:
        self._cfg = config
        base = (config.base_url or "").strip().rstrip("/")
        self._base_url = base or "https://api.openai.com/v1"
        self._model = (config.model or "").strip() or "gpt-4o-mini"
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
        if not self._api_key and "api.openai.com" in self._base_url:
            raise ProviderError(
                "OpenAI-compatible provider needs an API key "
                f"(set {self._cfg.api_key_env or 'TALOS_AI_API_KEY'} or "
                "talos ai config set api_key …)"
            )

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [_to_openai_message(m) for m in messages],
            "temperature": (
                float(temperature)
                if temperature is not None
                else float(self._cfg.temperature)
            ),
            "max_tokens": int(
                max_tokens if max_tokens is not None else self._cfg.max_tokens
            ),
        }
        if tools:
            # Map TTP tool descriptors to OpenAI function tools.
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        url = f"{self._base_url}/chat/completions"
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"OpenAI-compatible timeout: {exc}", retryable=True
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"OpenAI-compatible HTTP error: {exc}", retryable=True
            ) from exc

        if resp.status_code == 401:
            raise ProviderError("OpenAI-compatible auth failed (401)", retryable=False)
        if resp.status_code == 429:
            raise ProviderError("OpenAI-compatible rate limited (429)", retryable=True)
        if resp.status_code >= 400:
            raise ProviderError(
                f"OpenAI-compatible HTTP {resp.status_code}: {resp.text[:500]}",
                retryable=resp.status_code >= 500,
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise ProviderError(f"OpenAI-compatible non-JSON: {exc}") from exc

        choices = body.get("choices") or []
        if not choices:
            return CompleteResult(
                text="",
                error="empty choices from OpenAI-compatible API",
                raw_usage=dict(body.get("usage") or {}),
                model=str(body.get("model") or self._model),
            )

        message = choices[0].get("message") or {}
        text = message.get("content") or ""
        tool_calls: list[dict[str, Any]] = []
        for tc in message.get("tool_calls") or []:
            fn = tc.get("function") or {}
            args_raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except json.JSONDecodeError:
                args = {"_raw": args_raw}
            if not isinstance(args, dict):
                args = {"_raw": args}
            tool_calls.append(
                {
                    "id": tc.get("id"),
                    "name": fn.get("name") or "",
                    "arguments": args,
                }
            )

        usage = dict(body.get("usage") or {})
        return CompleteResult(
            text=str(text or ""),
            raw_usage=usage,
            tool_calls=tool_calls,
            model=str(body.get("model") or self._model),
        )


def _to_openai_message(msg: ChatMessage) -> dict[str, Any]:
    role = msg.role.value if isinstance(msg.role, Role) else str(msg.role)
    out: dict[str, Any] = {"role": role, "content": msg.text()}
    if msg.name:
        out["name"] = msg.name
    if msg.tool_call_id:
        out["tool_call_id"] = msg.tool_call_id
    return out
