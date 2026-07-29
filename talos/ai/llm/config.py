"""
Module: talos.ai.llm.config

Purpose:
    Operator-only AI LLM configuration (~/.talos/ai/config.yaml).
    Never registered as a tool. API keys prefer env TALOS_AI_API_KEY.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from talos.config import TalosConfig

AI_CONFIG_ENV_API_KEY = "TALOS_AI_API_KEY"
AI_CONFIG_REL = Path("ai") / "config.yaml"

VALID_PROVIDERS = frozenset(
    {"none", "ollama", "openai-compatible", "openai", "anthropic"}
)

# Keys operators may set via `talos ai config set`.
SETTABLE_KEYS = frozenset(
    {
        "provider",
        "model",
        "base_url",
        "api_key_env",
        "temperature",
        "max_tokens",
        "timeout_s",
        "fallback_to_heuristic",
        "api_key",  # discouraged; prefer env
    }
)


class AiConfigError(ValueError):
    """Invalid AI config value or I/O failure."""


@dataclass
class AiConfig:
    """
    Operator LLM settings. Default provider=none → HeuristicPlanner.
    """

    provider: str = "none"
    model: str = ""
    base_url: str = ""
    api_key_env: str = AI_CONFIG_ENV_API_KEY
    temperature: float = 0.2
    max_tokens: int = 2048
    timeout_s: float = 60.0
    fallback_to_heuristic: bool = True
    # Stored only if operator explicitly sets; never required.
    api_key: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def normalized_provider(self) -> str:
        p = (self.provider or "none").strip().lower()
        if p == "openai":
            return "openai-compatible"
        return p

    def resolve_api_key(self) -> Optional[str]:
        """
        Purpose:
            Resolve API key: explicit config → named env → TALOS_AI_API_KEY.
        """
        if (self.api_key or "").strip():
            return self.api_key.strip()
        env_name = (self.api_key_env or AI_CONFIG_ENV_API_KEY).strip()
        if env_name:
            val = os.environ.get(env_name, "").strip()
            if val:
                return val
        if env_name != AI_CONFIG_ENV_API_KEY:
            val = os.environ.get(AI_CONFIG_ENV_API_KEY, "").strip()
            if val:
                return val
        return None

    def to_public_dict(self, *, reveal_secrets: bool = False) -> dict[str, Any]:
        """Operator-facing dict; secrets redacted unless reveal_secrets."""
        out = {
            "provider": self.normalized_provider(),
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env or AI_CONFIG_ENV_API_KEY,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout_s": self.timeout_s,
            "fallback_to_heuristic": self.fallback_to_heuristic,
            "api_key_configured": bool(self.resolve_api_key()),
        }
        if reveal_secrets and self.api_key:
            out["api_key"] = self.api_key
        elif self.api_key:
            out["api_key"] = "***"
        else:
            out["api_key"] = ""
        if self.extra:
            out["extra"] = dict(self.extra)
        return out

    def to_storage_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "provider": self.normalized_provider(),
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env or AI_CONFIG_ENV_API_KEY,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout_s": self.timeout_s,
            "fallback_to_heuristic": self.fallback_to_heuristic,
        }
        if self.api_key:
            data["api_key"] = self.api_key
        if self.extra:
            data["extra"] = dict(self.extra)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "AiConfig":
        if not data:
            return cls()
        provider = str(data.get("provider") or "none").strip().lower()
        if provider == "openai":
            provider = "openai-compatible"
        if provider not in VALID_PROVIDERS and provider != "openai-compatible":
            # Allow unknown for forward-compat but normalize unknown → keep string
            pass
        extra = data.get("extra") if isinstance(data.get("extra"), dict) else {}
        known = {
            "provider",
            "model",
            "base_url",
            "api_key_env",
            "temperature",
            "max_tokens",
            "timeout_s",
            "fallback_to_heuristic",
            "api_key",
            "extra",
        }
        # Preserve unknown top-level keys in extra for forward compat.
        for k, v in data.items():
            if k not in known:
                extra[k] = v
        try:
            temperature = float(data.get("temperature", 0.2))
        except (TypeError, ValueError):
            temperature = 0.2
        try:
            max_tokens = int(data.get("max_tokens", 2048))
        except (TypeError, ValueError):
            max_tokens = 2048
        try:
            timeout_s = float(data.get("timeout_s", 60.0))
        except (TypeError, ValueError):
            timeout_s = 60.0
        fb = data.get("fallback_to_heuristic", True)
        if isinstance(fb, str):
            fb = fb.strip().lower() in ("1", "true", "yes", "on")
        return cls(
            provider=provider or "none",
            model=str(data.get("model") or ""),
            base_url=str(data.get("base_url") or ""),
            api_key_env=str(data.get("api_key_env") or AI_CONFIG_ENV_API_KEY),
            temperature=temperature,
            max_tokens=max(1, max_tokens),
            timeout_s=max(1.0, timeout_s),
            fallback_to_heuristic=bool(fb),
            api_key=str(data.get("api_key") or ""),
            extra=dict(extra or {}),
        )


def ai_config_path(data_dir: Path | None = None) -> Path:
    """Resolve ~/.talos/ai/config.yaml (or TALOS_DATA_DIR/ai/config.yaml)."""
    root = data_dir if data_dir is not None else TalosConfig.from_env().data_dir
    return Path(root) / AI_CONFIG_REL


def load_ai_config(data_dir: Path | None = None) -> AiConfig:
    """
    Purpose:
        Load operator AI config; missing file → defaults (provider=none).
    """
    path = ai_config_path(data_dir)
    if not path.exists():
        return AiConfig()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AiConfigError(f"Cannot read AI config {path}: {exc}") from exc
    if not text.strip():
        return AiConfig()
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AiConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if raw is None:
        return AiConfig()
    if not isinstance(raw, dict):
        raise AiConfigError(f"AI config must be a mapping: {path}")
    return AiConfig.from_dict(raw)


def save_ai_config(cfg: AiConfig, data_dir: Path | None = None) -> Path:
    """
    Purpose:
        Persist AI config atomically. Creates parent dirs.
    Output:
        Path written.
    """
    path = ai_config_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = cfg.to_storage_dict()
    dumped = yaml.safe_dump(
        payload,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
    )
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(dumped, encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise AiConfigError(f"Cannot write AI config {path}: {exc}") from exc
    return path


def apply_config_set(
    cfg: AiConfig,
    key: str,
    value: str,
) -> AiConfig:
    """
    Purpose:
        Apply one `talos ai config set KEY VALUE` mutation; returns new config.
    Raises:
        AiConfigError on unknown key or invalid value.
    """
    key = (key or "").strip().lower().replace("-", "_")
    if key not in SETTABLE_KEYS:
        raise AiConfigError(
            f"Unknown config key '{key}'. "
            f"Valid: {', '.join(sorted(SETTABLE_KEYS))}"
        )
    data = cfg.to_storage_dict()
    if key == "provider":
        p = (value or "").strip().lower()
        if p == "openai":
            p = "openai-compatible"
        if p not in VALID_PROVIDERS:
            raise AiConfigError(
                f"Invalid provider '{value}'. "
                f"Valid: none, ollama, openai-compatible, anthropic"
            )
        data["provider"] = p
    elif key == "temperature":
        try:
            data["temperature"] = float(value)
        except (TypeError, ValueError) as exc:
            raise AiConfigError(f"temperature must be a number: {value!r}") from exc
    elif key == "max_tokens":
        try:
            data["max_tokens"] = int(value)
        except (TypeError, ValueError) as exc:
            raise AiConfigError(f"max_tokens must be an integer: {value!r}") from exc
    elif key == "timeout_s":
        try:
            data["timeout_s"] = float(value)
        except (TypeError, ValueError) as exc:
            raise AiConfigError(f"timeout_s must be a number: {value!r}") from exc
    elif key == "fallback_to_heuristic":
        v = (value or "").strip().lower()
        if v in ("1", "true", "yes", "on"):
            data["fallback_to_heuristic"] = True
        elif v in ("0", "false", "no", "off"):
            data["fallback_to_heuristic"] = False
        else:
            raise AiConfigError(
                f"fallback_to_heuristic must be true/false: {value!r}"
            )
    else:
        data[key] = value
    return AiConfig.from_dict(data)


def unset_ai_config_keys(
    cfg: AiConfig,
    keys: list[str],
) -> AiConfig:
    """
    Purpose:
        Reset listed keys to defaults (or clear secrets).
    """
    data = cfg.to_storage_dict()
    defaults = AiConfig().to_storage_dict()
    for raw in keys:
        key = (raw or "").strip().lower().replace("-", "_")
        if key not in SETTABLE_KEYS:
            raise AiConfigError(f"Unknown config key '{key}'")
        if key == "api_key":
            data.pop("api_key", None)
        elif key in defaults:
            data[key] = defaults[key]
        else:
            data.pop(key, None)
    return AiConfig.from_dict(data)
