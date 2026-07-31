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
    "parameter_intel": {
        "cross_flow": {
            "enabled": False,  # master: index + scan (bake-in off until validated)
            "feed_iv": True,  # merge into profiles / scoring when enabled
            "active_sink_probe": False,  # P2
            "value_index_ttl_hours": 72,
            "value_index_max_per_host": 50_000,
            "value_index_max_sources_per_value": 8,
            "min_value_len": 6,
            "scan_hot_set_k": 2000,
            "scan_time_budget_ms": 20,  # hard abort; fail open
            "max_body_scan_bytes": 2_000_000,
            "canary_ttl_hours": 24,
        },
    },
    # URL Sink Discovery (talos.url_sink + IV url_sink_probes). Safe defaults on.
    "url_sink": {
        "passive": {
            "enabled": True,  # value/name classify + structure inventory
        },
        "html_js": {
            "enabled": True,  # response HTML/JS inventory (score-gated)
        },
        "iv_probes": {
            "enabled": True,  # benign canaries when passive warrants (IV types gate)
        },
        "score_threshold": 45,  # possible_network_resource / inventory gate
    },
}

# Top-level sections exposed as first-class CLI resources.
CONFIG_SECTIONS: tuple[str, ...] = (
    "proxy",
    "capture",
    "scheduler",
    "attack",
    "http",
    "parameter_intel",
    "url_sink",
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
    "parameter_intel.cross_flow.enabled",
    "parameter_intel.cross_flow.feed_iv",
    "parameter_intel.cross_flow.active_sink_probe",
    "parameter_intel.cross_flow.value_index_ttl_hours",
    "parameter_intel.cross_flow.value_index_max_per_host",
    "parameter_intel.cross_flow.value_index_max_sources_per_value",
    "parameter_intel.cross_flow.min_value_len",
    "parameter_intel.cross_flow.scan_hot_set_k",
    "parameter_intel.cross_flow.scan_time_budget_ms",
    "parameter_intel.cross_flow.max_body_scan_bytes",
    "parameter_intel.cross_flow.canary_ttl_hours",
    "url_sink.passive.enabled",
    "url_sink.html_js.enabled",
    "url_sink.iv_probes.enabled",
    "url_sink.score_threshold",
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
    "parameter_intel": {
        "label": "Parameter intelligence",
        "description": (
            "Passive parameter intelligence, including cross-flow / stored "
            "reflection indexing for XSS prioritization evidence."
        ),
    },
    "url_sink": {
        "label": "URL Sink Discovery",
        "description": (
            "Passive URL/hostname inventory (talos.url_sink) and optional IV "
            "benign canary probes (url_sink_probes). Kill-switches and score gate."
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
    {
        "key": "parameter_intel.cross_flow.enabled",
        "section": "parameter_intel",
        "label": "Cross-flow reflection enabled",
        "type": "bool",
        "default": False,
        "description": (
            "Master switch for passive cross-flow value indexing and sink "
            "scanning. Off by default until bake-in validates false-positive rate."
        ),
    },
    {
        "key": "parameter_intel.cross_flow.feed_iv",
        "section": "parameter_intel",
        "label": "Feed IV profiles",
        "type": "bool",
        "default": True,
        "description": (
            "When true, merge cross-flow reflection links into IV parameter "
            "profiles and candidate scoring."
        ),
    },
    {
        "key": "parameter_intel.cross_flow.active_sink_probe",
        "section": "parameter_intel",
        "label": "Active sink probes",
        "type": "bool",
        "default": False,
        "description": (
            "P2 (unimplemented): when true, would enqueue limited scheduler "
            "GETs of likely sinks after multiprobe canaries when same-request "
            "reflection is absent. Setting this has no runtime effect yet."
        ),
    },
    {
        "key": "parameter_intel.cross_flow.value_index_ttl_hours",
        "section": "parameter_intel",
        "label": "Value index TTL (hours)",
        "type": "int",
        "default": 72,
        "minimum": 1,
        "unit": "hours",
        "description": "How long organic indexed values remain matchable.",
    },
    {
        "key": "parameter_intel.cross_flow.value_index_max_per_host",
        "section": "parameter_intel",
        "label": "Max index rows per host",
        "type": "int",
        "default": 50_000,
        "minimum": 100,
        "description": "Hard cap on value_index rows per host; prune oldest non-canaries.",
    },
    {
        "key": "parameter_intel.cross_flow.value_index_max_sources_per_value",
        "section": "parameter_intel",
        "label": "Max sources per value",
        "type": "int",
        "default": 8,
        "minimum": 1,
        "description": (
            "Skip indexing a new source param when this many distinct sources "
            "already index the same value hash on the host."
        ),
    },
    {
        "key": "parameter_intel.cross_flow.min_value_len",
        "section": "parameter_intel",
        "label": "Min value length",
        "type": "int",
        "default": 6,
        "minimum": 4,
        "description": (
            "Floor length for non-canary index eligibility (Rules B/C/D). "
            "Canaries (Rule A) are exempt. Hard rejects still apply."
        ),
    },
    {
        "key": "parameter_intel.cross_flow.scan_hot_set_k",
        "section": "parameter_intel",
        "label": "Hot-set size K",
        "type": "int",
        "default": 2000,
        "minimum": 1,
        "description": "Max value_index rows scanned per response (canaries first).",
    },
    {
        "key": "parameter_intel.cross_flow.scan_time_budget_ms",
        "section": "parameter_intel",
        "label": "Scan time budget (ms)",
        "type": "int",
        "default": 20,
        "minimum": 1,
        "unit": "milliseconds",
        "description": "Hard abort mid-scan; fail open (skip remaining candidates).",
    },
    {
        "key": "parameter_intel.cross_flow.max_body_scan_bytes",
        "section": "parameter_intel",
        "label": "Max body scan bytes",
        "type": "int",
        "default": 2_000_000,
        "minimum": 1024,
        "unit": "bytes",
        "description": "Decode/scan cap for response bodies during sink matching.",
    },
    {
        "key": "parameter_intel.cross_flow.canary_ttl_hours",
        "section": "parameter_intel",
        "label": "Canary TTL (hours)",
        "type": "int",
        "default": 24,
        "minimum": 1,
        "unit": "hours",
        "description": "TTL for multiprobe canary rows in value_index.",
    },
    {
        "key": "url_sink.passive.enabled",
        "section": "url_sink",
        "label": "Passive URL sink enabled",
        "type": "bool",
        "default": True,
        "description": (
            "When true, FlowWorker composes url_features and expands structure "
            "discovery (encoded JSON / JWT claims) on captured parameters."
        ),
    },
    {
        "key": "url_sink.html_js.enabled",
        "section": "url_sink",
        "label": "HTML/JS inventory enabled",
        "type": "bool",
        "default": True,
        "description": (
            "When true, inventory HTML hidden fields and JS/bootstrap config "
            "URL keys from responses (location=response; score-gated)."
        ),
    },
    {
        "key": "url_sink.iv_probes.enabled",
        "section": "url_sink",
        "label": "IV URL sink probes enabled",
        "type": "bool",
        "default": True,
        "description": (
            "When true and types analysis is on, planner schedules benign "
            "url_sink canaries (talos-canary.invalid) when passive features warrant."
        ),
    },
    {
        "key": "url_sink.score_threshold",
        "section": "url_sink",
        "label": "Network-resource score threshold",
        "type": "int",
        "default": 45,
        "minimum": 0,
        "maximum": 100,
        "description": (
            "Minimum url_features.score for possible_network_resource inventory "
            "gates and IV canary warrant (default 45)."
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
