"""
Module: talos.configuration.defaults

Purpose:
    Built-in default configuration for the layered configuration system.
    Lowest precedence layer — always present, never written to disk.

Dependencies: None
Data flow: ConfigurationManager seeds the merge from BUILTIN_DEFAULTS.
Side effects: None.
"""

from __future__ import annotations

# Default headers dropped from stored capture payloads (proxy noise).
# Mirrors talos/proxy/default_headers_drop.txt so new installs stay consistent.
DEFAULT_DROP_HEADERS: list[str] = [
    "Proxy-Connection",
    "Via",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Real-IP",
    "Forwarded",
    "Connection",
    "Keep-Alive",
    "Transfer-Encoding",
    "TE",
    "Trailer",
    "Upgrade",
]

# Full built-in tree. Nested dicts only; leaf types are bool/int/float/str/list/dict.
# http.rules is empty by default — no request/response manipulation until operators
# add rules via `talos config http` (global, project, or match-scoped).
BUILTIN_DEFAULTS: dict = {
    "proxy": {
        "upstream": {
            "enabled": False,
            "url": None,
        },
    },
    "capture": {
        "store_bodies": True,
        "max_body_size": 1 * 1024 * 1024,
        "drop_headers": list(DEFAULT_DROP_HEADERS),
    },
    "scheduler": {
        "min_delay": 2.0,
        "max_delay": 6.0,
        "max_queue_size": 200,
    },
    "attack": {
        "unauth_auto_run": False,
    },
    "http": {
        "enabled": True,
        "rules": [],
    },
}

# Top-level sections exposed as first-class CLI resources.
CONFIG_SECTIONS: tuple[str, ...] = (
    "proxy",
    "capture",
    "scheduler",
    "attack",
    "http",
)

# Dot-path keys that operators commonly get/set (for help and validation).
KNOWN_LEAF_PATHS: tuple[str, ...] = (
    "proxy.upstream.enabled",
    "proxy.upstream.url",
    "capture.store_bodies",
    "capture.max_body_size",
    "capture.drop_headers",
    "scheduler.min_delay",
    "scheduler.max_delay",
    "scheduler.max_queue_size",
    "attack.unauth_auto_run",
    "http.enabled",
    "http.rules",
)

# Machine-readable presentation + type metadata for Control Panel / automation.
# Validation and merge semantics remain in ConfigurationManager; this is schema
# only (types, defaults, labels). Consumed by `talos config schema --format json`.
SECTION_META: dict[str, dict] = {
    "proxy": {
        "label": "Proxy",
        "description": "Upstream proxy mode for mitmdump and outbound engines.",
    },
    "capture": {
        "label": "Capture",
        "description": "Traffic storage and drop headers for stored payloads.",
    },
    "scheduler": {
        "label": "Scheduler",
        "description": "Job rate limits and queue capacity.",
    },
    "attack": {
        "label": "Attack",
        "description": "Attack-engine toggles owned by layered configuration.",
    },
    "http": {
        "label": "HTTP",
        "description": (
            "HTTP Manipulation Engine — declarative rules that modify "
            "requests and responses (headers, body, status, cookies, URL)."
        ),
    },
}

# type values: bool | int | float | string | string_list | string_map | nullable_string | rule_list
SETTING_SCHEMA: tuple[dict, ...] = (
    {
        "key": "proxy.upstream.enabled",
        "section": "proxy",
        "label": "Upstream enabled",
        "type": "bool",
        "default": False,
        "description": "When true, traffic is forwarded through the upstream proxy URL.",
    },
    {
        "key": "proxy.upstream.url",
        "section": "proxy",
        "label": "Upstream URL",
        "type": "nullable_string",
        "default": None,
        "description": "Upstream proxy URL (e.g. http://127.0.0.1:8081). Null means Direct mode.",
    },
    {
        "key": "capture.store_bodies",
        "section": "capture",
        "label": "Store bodies",
        "type": "bool",
        "default": True,
        "description": "Whether request and response bodies are stored in capture.",
    },
    {
        "key": "capture.max_body_size",
        "section": "capture",
        "label": "Max body size",
        "type": "int",
        "default": 1 * 1024 * 1024,
        "minimum": 0,
        "unit": "bytes",
        "description": "Maximum stored body size in bytes before truncation.",
    },
    {
        "key": "capture.drop_headers",
        "section": "capture",
        "label": "Drop headers",
        "type": "string_list",
        "default": list(DEFAULT_DROP_HEADERS),
        "description": "Header names excluded from stored capture payloads (full list replaces lower layers).",
    },
    {
        "key": "scheduler.min_delay",
        "section": "scheduler",
        "label": "Min delay",
        "type": "float",
        "default": 2.0,
        "minimum": 0,
        "unit": "seconds",
        "description": "Minimum delay between scheduler jobs.",
    },
    {
        "key": "scheduler.max_delay",
        "section": "scheduler",
        "label": "Max delay",
        "type": "float",
        "default": 6.0,
        "minimum": 0,
        "unit": "seconds",
        "description": "Maximum delay between scheduler jobs.",
    },
    {
        "key": "scheduler.max_queue_size",
        "section": "scheduler",
        "label": "Max queue size",
        "type": "int",
        "default": 200,
        "minimum": 1,
        "description": "Maximum number of pending scheduler jobs.",
    },
    {
        "key": "attack.unauth_auto_run",
        "section": "attack",
        "label": "Unauth auto-run",
        "type": "bool",
        "default": False,
        "description": "When enabled, automatically enqueue unauth/auth-test work for eligible endpoints.",
    },
    {
        "key": "http.enabled",
        "section": "http",
        "label": "HTTP engine enabled",
        "type": "bool",
        "default": True,
        "description": "Master switch for the HTTP Manipulation Engine. When false, no rules run.",
    },
    {
        "key": "http.rules",
        "section": "http",
        "label": "HTTP rules",
        "type": "rule_list",
        "default": [],
        "description": (
            "Declarative request/response manipulation rules. Manage via "
            "`talos config http` (create, list, enable, actions, match). "
            "Rules from global and project layers are concatenated and sorted "
            "by priority. Empty by default — no traffic is modified."
        ),
    },
)


def build_config_schema() -> dict:
    """
    Purpose:
        Build the machine-readable configuration schema payload.
    Output:
        Dict suitable for `talos config schema --format json`.
    Side effects: None.
    """
    by_section: dict[str, list[dict]] = {s: [] for s in CONFIG_SECTIONS}
    for entry in SETTING_SCHEMA:
        section = entry["section"]
        if section not in by_section:
            by_section[section] = []
        # Copy so callers cannot mutate the module-level defaults.
        by_section[section].append(dict(entry))

    sections = []
    for section_id in CONFIG_SECTIONS:
        meta = SECTION_META.get(section_id, {})
        sections.append(
            {
                "id": section_id,
                "label": meta.get("label", section_id.capitalize()),
                "description": meta.get("description", ""),
                "settings": by_section.get(section_id, []),
            }
        )

    return {
        "precedence": [
            "defaults",
            "global",
            "legacy",
            "project",
            "cli",
        ],
        "sources": ["default", "global", "legacy", "project", "cli"],
        "sections": sections,
        "known_keys": list(KNOWN_LEAF_PATHS),
    }
