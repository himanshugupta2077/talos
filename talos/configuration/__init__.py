"""
Module: talos.configuration

Purpose:
    Layered configuration subsystem (CLI-022 + HTTP Manipulation Engine).
    Provides a single effective configuration object built from:

        Built-in defaults
            ↓
        Global configuration  (~/.talos/config.yaml)
            ↓
        Project configuration (project.yaml + legacy bridges)
            ↓
        CLI one-shot overrides

    Every runtime subsystem should consume EffectiveConfig (or a value from
    ConfigurationManager) rather than opening raw files / SQLite tables for
    settings that belong in the layered model.

    HTTP request/response mutation is owned by the HTTP Manipulation Engine
    (``http.enabled`` + ``http.rules``), applied by the proxy addon.

Public surface:
    ConfigurationManager, EffectiveConfig, load_effective_config,
    HTTPManipulationEngine, BUILTIN_DEFAULTS, ConfigError

Dependencies: submodules of this package
Data flow:
    CLI / proxy / scheduler / attack → ConfigurationManager → EffectiveConfig
Side effects: None at import time.
"""

from talos.configuration.defaults import BUILTIN_DEFAULTS, DEFAULT_DROP_HEADERS
from talos.configuration.http_engine import HTTPManipulationEngine
from talos.configuration.manager import (
    ConfigError,
    ConfigurationManager,
    load_effective_config,
)
from talos.configuration.model import (
    AttackConfigSection,
    CaptureConfigSection,
    EffectiveConfig,
    HttpConfigSection,
    ProxyConfigSection,
    SchedulerConfigSection,
    SourceInfo,
    ValueSource,
)

__all__ = [
    "BUILTIN_DEFAULTS",
    "DEFAULT_DROP_HEADERS",
    "AttackConfigSection",
    "CaptureConfigSection",
    "ConfigError",
    "ConfigurationManager",
    "EffectiveConfig",
    "HTTPManipulationEngine",
    "HttpConfigSection",
    "ProxyConfigSection",
    "SchedulerConfigSection",
    "SourceInfo",
    "ValueSource",
    "load_effective_config",
]
