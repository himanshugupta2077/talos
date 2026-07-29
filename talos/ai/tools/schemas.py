"""
Module: talos.ai.tools.schemas

Purpose:
    JSON Schema bodies for Phase A–E tools + TOOL_PROTOCOL_VERSION.
    Lightweight validator for the schema subset used by TTP (no jsonschema dep).

Dependencies: copy, typing
Data flow:
    ToolSpec.input_schema ← here; PolicyValidator → validate_input
Side effects: None.
"""

from __future__ import annotations

import copy
from typing import Any, Optional

TOOL_PROTOCOL_VERSION = 1

# ------------------------------------------------------------------ #
# Schema definitions (Phase A READ + context)                          #
# ------------------------------------------------------------------ #

SCHEMA_ENDPOINT_LIST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "host": {"type": "string", "maxLength": 256},
        "method": {"type": "string", "maxLength": 16},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
        "qualified_only": {"type": "boolean", "default": False},
        "search": {"type": "string", "maxLength": 256},
    },
}

SCHEMA_ENDPOINT_SHOW: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["endpoint_id"],
    "properties": {
        "endpoint_id": {"type": "string", "minLength": 8, "maxLength": 64},
    },
}

SCHEMA_FLOW_SHOW: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["flow_id"],
    "properties": {
        "flow_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "include_bodies": {"type": "boolean", "default": False},
    },
}

SCHEMA_FLOW_DIFF: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["flow_a", "flow_b"],
    "properties": {
        "flow_a": {"type": "string", "minLength": 8, "maxLength": 64},
        "flow_b": {"type": "string", "minLength": 8, "maxLength": 64},
    },
}

SCHEMA_PARAM_INTELLIGENCE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["param_id"],
    "properties": {
        "param_id": {"type": "string", "minLength": 4, "maxLength": 128},
        "recompute": {"type": "boolean", "default": False},
    },
}

SCHEMA_IV_CANDIDATES: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "attack": {
            "type": "string",
            "enum": [
                "xss",
                "sqli",
                "open_redirect",
                "ssrf",
                "hpp",
                "header_injection",
                "path_traversal",
                "mass_assignment",
            ],
        },
        "min_score": {"type": "integer", "minimum": 0, "maximum": 100, "default": 0},
        "host": {"type": "string", "maxLength": 256},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
    },
}

SCHEMA_FINDING_LIST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string", "maxLength": 64},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
    },
}

SCHEMA_FINDING_SHOW: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["finding_id"],
    "properties": {
        "finding_id": {"type": "string", "minLength": 8, "maxLength": 64},
    },
}

SCHEMA_PASSIVE_LIST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
        "category": {"type": "string", "maxLength": 64},
        "suppressed": {"type": "boolean"},
    },
}

SCHEMA_ERROR_INTEL_LIST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
        "severity": {"type": "string", "maxLength": 32},
        "category": {"type": "string", "maxLength": 64},
    },
}

SCHEMA_ACCESS_COVERAGE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

SCHEMA_ROLE_LIST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

SCHEMA_ROLE_SHOW_ACTIVE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

SCHEMA_MODULE_LIST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

SCHEMA_MODULE_SHOW_ACTIVE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

SCHEMA_ROLE_SET_ACTIVE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name"],
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": "Existing role name (same as talos role set).",
        },
    },
}

SCHEMA_MODULE_SET_ACTIVE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name"],
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": "Existing module name (same as talos module set).",
        },
    },
}

SCHEMA_SCHEDULER_JOBS_LIST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string", "maxLength": 32},
        "job_type": {"type": "string", "maxLength": 64},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
    },
}

SCHEMA_SCHEDULER_JOBS_SHOW: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["job_id"],
    "properties": {
        "job_id": {"type": "string", "minLength": 4, "maxLength": 64},
    },
}

SCHEMA_INTRUDER_SUGGEST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["session_id"],
    "properties": {
        "session_id": {"type": "string", "minLength": 8, "maxLength": 64},
    },
}

# ------------------------------------------------------------------ #
# Phase B: notes + task tree                                           #
# ------------------------------------------------------------------ #

SCHEMA_NOTES_APP_GET: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

SCHEMA_NOTES_APP_PATCH: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["if_revision", "ops"],
    "properties": {
        "if_revision": {"type": "integer", "minimum": 0},
        "ops": {
            "type": "array",
            "maxItems": 50,
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["op", "path"],
                "properties": {
                    "op": {
                        "type": "string",
                        "enum": ["add", "replace", "remove"],
                    },
                    "path": {"type": "string", "minLength": 1, "maxLength": 256},
                    "value": {},  # any JSON — validated by notes store allowlist
                },
            },
        },
    },
}

SCHEMA_TASK_TREE_LIST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string", "maxLength": 32},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
    },
}

SCHEMA_TASK_TREE_UPSERT: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["title"],
    "properties": {
        "node_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "parent_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "title": {"type": "string", "minLength": 1, "maxLength": 500},
        "status": {
            "type": "string",
            "enum": ["pending", "in_progress", "blocked", "done", "cancelled"],
            "default": "pending",
        },
        "hypothesis": {"type": "string", "maxLength": 4000},
        "priority": {"type": "integer", "minimum": 0, "maximum": 1000, "default": 0},
        "suggested_tools": {
            "type": "array",
            "maxItems": 20,
            "items": {"type": "string", "maxLength": 128},
        },
        "evidence_refs": {"type": "object"},
    },
}

# ------------------------------------------------------------------ #
# Phase D: send / replay / engines                                     #
# ------------------------------------------------------------------ #

SCHEMA_SEND_ONCE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["parent_flow_id"],
    "properties": {
        "parent_flow_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "edits": {
            "type": "array",
            "maxItems": 20,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["op", "target"],
                "properties": {
                    "op": {"type": "string", "enum": ["set", "remove"]},
                    "target": {
                        "type": "string",
                        "enum": [
                            "query",
                            "header",
                            "cookie",
                            "body_json_path",
                            "path",
                            "host",
                            "url",
                        ],
                    },
                    "key": {"type": "string", "maxLength": 256},
                    "value": {"type": "string", "maxLength": 8192},
                },
            },
        },
        "reason": {"type": "string", "maxLength": 512},
    },
}

SCHEMA_REPLAY_FLOW: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["flow_id"],
    "properties": {
        "flow_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "reason": {"type": "string", "maxLength": 512},
    },
}

SCHEMA_IV_RUN: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "scope": {
            "type": "string",
            "enum": ["project", "host", "endpoint", "parameter"],
            "default": "endpoint",
        },
        "host": {"type": "string", "maxLength": 256},
        "endpoint_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "param_name": {"type": "string", "minLength": 1, "maxLength": 256},
        "phase_filter": {"type": "string", "maxLength": 64},
        "ignore_cache": {"type": "boolean", "default": False},
    },
}

SCHEMA_IV_SYNTHESIZE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["param_uuid"],
    "properties": {
        "param_uuid": {"type": "string", "minLength": 4, "maxLength": 128},
        "persist": {"type": "boolean", "default": True},
    },
}

SCHEMA_PASSIVE_RESCAN: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "flow_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "document_id": {"type": "string", "minLength": 4, "maxLength": 64},
        "all": {"type": "boolean", "default": False},
        "force": {"type": "boolean", "default": False},
    },
}

SCHEMA_ATTACK_UNAUTH_RUN: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "endpoint_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "flow_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "technique": {"type": "string", "maxLength": 64},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
    },
}

_BAC_MODULES = [
    "bac_session_swap",
    "bac_method_fuzz",
    "bac_content_type",
    "bac_url_fuzz",
    "bac_header_inject",
    "bac_host_fuzz",
    "bac_role_inject",
    "bac_parser_confuse",
]

SCHEMA_ATTACK_BAC_RUN: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["bac_module"],
    "properties": {
        "bac_module": {"type": "string", "enum": list(_BAC_MODULES)},
        "endpoint_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "flow_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "attacker_role": {"type": "string", "minLength": 1, "maxLength": 128},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
    },
}

SCHEMA_INTRUDER_SESSION_RUN: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["session_id"],
    "properties": {
        "session_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "segment": {"type": "integer", "minimum": 0, "maximum": 10000, "default": 0},
        "max_payloads": {
            "type": "integer",
            "minimum": 1,
            "maximum": 200,
            "default": 200,
        },
    },
}

# ------------------------------------------------------------------ #
# Phase E: minimal markdown KB + draft findings                        #
# ------------------------------------------------------------------ #

SCHEMA_KB_SEARCH: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "query": {"type": "string", "maxLength": 500, "default": ""},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
    },
}

SCHEMA_DRAFT_FINDING_LIST: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "status": {
            "type": "string",
            "enum": ["draft", "promoted", "rejected"],
        },
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
    },
}

SCHEMA_DRAFT_FINDING_SHOW: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["draft_id"],
    "properties": {
        "draft_id": {"type": "string", "minLength": 8, "maxLength": 64},
    },
}

SCHEMA_DRAFT_FINDING_CREATE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["title", "description", "endpoint_id"],
    "properties": {
        "title": {"type": "string", "minLength": 1, "maxLength": 200},
        "description": {"type": "string", "minLength": 1, "maxLength": 8000},
        "endpoint_id": {"type": "string", "minLength": 8, "maxLength": 64},
        "attack_type": {
            "type": "string",
            "enum": [
                "ai_draft",
                "bac",
                "auth_test",
                "unauth",
                "passive_secret",
                "intruder",
            ],
            "default": "ai_draft",
        },
        "vulnerability_class": {"type": "string", "maxLength": 128, "default": ""},
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
            "default": 0.5,
        },
        "cluster_key": {"type": "string", "maxLength": 256},
        "evidence_refs": {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "endpoint_ids": {
                    "type": "array",
                    "maxItems": 50,
                    "items": {"type": "string", "maxLength": 64},
                },
                "flow_ids": {
                    "type": "array",
                    "maxItems": 50,
                    "items": {"type": "string", "maxLength": 64},
                },
                "finding_ids": {
                    "type": "array",
                    "maxItems": 50,
                    "items": {"type": "string", "maxLength": 64},
                },
                "param_uuids": {
                    "type": "array",
                    "maxItems": 50,
                    "items": {"type": "string", "maxLength": 128},
                },
            },
        },
    },
}

# Keys that must never appear in tool args (project switch / override).
FORBIDDEN_ARG_KEYS: frozenset[str] = frozenset(
    {
        "project",
        "project_id",
        "project_override",
        "--project",
        "db_path",
        "data_dir",
        "projects_root",
    }
)


# ------------------------------------------------------------------ #
# Lightweight JSON Schema validator                                    #
# ------------------------------------------------------------------ #


def validate_input(
    instance: dict[str, Any],
    schema: dict[str, Any],
) -> tuple[bool, Optional[str], dict[str, Any]]:
    """
    Purpose:
        Validate and normalize tool arguments against a JSON Schema subset.
        Supports: type object, properties, required, additionalProperties,
        type (string/integer/boolean/array), enum, min/max, minLength/maxLength,
        default.
    Input:
        instance — raw arguments dict.
        schema   — ToolSpec.input_schema.
    Output:
        (ok, error_message_or_None, normalized_args_with_defaults).
    Side effects: None.
    """
    if not isinstance(instance, dict):
        return False, "arguments must be a JSON object", {}

    for key in instance:
        if key in FORBIDDEN_ARG_KEYS:
            return False, f"forbidden argument key: {key}", {}

    schema_type = schema.get("type", "object")
    if schema_type != "object":
        return False, "schema root must be type object", {}

    props: dict[str, Any] = schema.get("properties") or {}
    additional = schema.get("additionalProperties", True)
    required = list(schema.get("required") or [])

    if additional is False:
        unknown = [k for k in instance if k not in props]
        if unknown:
            return False, f"unknown properties: {', '.join(sorted(unknown))}", {}

    for key in required:
        if key not in instance:
            return False, f"missing required property: {key}", {}

    normalized: dict[str, Any] = copy.deepcopy(instance)

    # Apply defaults for missing optional properties.
    for key, prop_schema in props.items():
        if key not in normalized and "default" in prop_schema:
            normalized[key] = copy.deepcopy(prop_schema["default"])

    for key, value in list(normalized.items()):
        if key not in props:
            continue
        prop = props[key]
        ok, err = _validate_value(value, prop, path=key)
        if not ok:
            return False, err, {}

    return True, None, normalized


def _validate_value(
    value: Any,
    schema: dict[str, Any],
    *,
    path: str,
) -> tuple[bool, Optional[str]]:
    expected = schema.get("type")
    if expected == "string":
        if not isinstance(value, str):
            return False, f"{path}: expected string"
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            return False, f"{path}: shorter than minLength"
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            return False, f"{path}: longer than maxLength"
        if "enum" in schema and value not in schema["enum"]:
            return False, f"{path}: not in enum"
    elif expected == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return False, f"{path}: expected integer"
        if "minimum" in schema and value < int(schema["minimum"]):
            return False, f"{path}: below minimum"
        if "maximum" in schema and value > int(schema["maximum"]):
            return False, f"{path}: above maximum"
    elif expected == "number":
        # JSON number: int or float (not bool).
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False, f"{path}: expected number"
        if "minimum" in schema and float(value) < float(schema["minimum"]):
            return False, f"{path}: below minimum"
        if "maximum" in schema and float(value) > float(schema["maximum"]):
            return False, f"{path}: above maximum"
    elif expected == "boolean":
        if not isinstance(value, bool):
            return False, f"{path}: expected boolean"
    elif expected == "array":
        if not isinstance(value, list):
            return False, f"{path}: expected array"
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            return False, f"{path}: too many items"
        item_schema = schema.get("items")
        if item_schema:
            for idx, item in enumerate(value):
                ok, err = _validate_value(item, item_schema, path=f"{path}[{idx}]")
                if not ok:
                    return False, err
    elif expected == "object":
        if not isinstance(value, dict):
            return False, f"{path}: expected object"
        # Nested object properties when declared.
        props = schema.get("properties") or {}
        additional = schema.get("additionalProperties", True)
        if additional is False and props:
            unknown = [k for k in value if k not in props]
            if unknown:
                return False, f"{path}: unknown properties: {', '.join(sorted(unknown))}"
        required = list(schema.get("required") or [])
        for key in required:
            if key not in value:
                return False, f"{path}: missing required property: {key}"
        for key, child in value.items():
            if key not in props:
                continue
            ok, err = _validate_value(child, props[key], path=f"{path}.{key}")
            if not ok:
                return False, err
    elif expected is None:
        # Schema property with no type (any JSON) — accept.
        return True, None
    return True, None
