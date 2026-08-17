"""
Declarative description of the Talos CLI surface.

This powers the "Console" page: a full-coverage fallback for any command that
doesn't have a dedicated, human-friendly page yet. Each leaf command declares
its base argv tokens plus a list of typed arguments; the frontend renders a
form from this and posts the filled-in values back to /api/console/run, which
rebuilds a safe argv list (no shell involved — subprocess is always called
with a list, never shell=True).

Field kinds:
  "text"     — single string, rendered as positional or `--flag value`
  "number"   — numeric string
  "boolean"  — rendered as a bare flag when true, omitted when false
  "select"   — one of `options`
  "multi"    — repeated value; flag repeated once per entry, or repeated
               positionals when `flag` is None
"""

from __future__ import annotations

from typing import Any


def arg(
    name: str,
    label: str | None = None,
    flag: str | None = None,
    kind: str = "text",
    required: bool = False,
    help: str = "",
    options: list[str] | None = None,
    default: Any = None,
):
    return {
        "name": name,
        "label": label or name.replace("_", " "),
        "flag": flag,
        "kind": kind,
        "required": required,
        "help": help,
        "options": options or [],
        "default": default,
    }


def cmd(
    cmd_id: str,
    path: list[str],
    summary: str,
    args: list[dict] | None = None,
    background: bool = False,
    stdin_from: str | None = None,
):
    """
    stdin_from: optional arg name whose value is piped to process stdin and
    omitted from argv (for CLI commands that read free-form text from stdin).
    """
    return {
        "id": cmd_id,
        "path": path,
        "summary": summary,
        "args": args or [],
        "background": background,
        "stdin_from": stdin_from,
    }


PRIORITY_OPTIONS = ["LOW", "NORMAL", "HIGH", "CRITICAL"]
ACCESS_VALUES = ["ALLOW", "DENY", "UNKNOWN"]
IV_PHASES = [
    "baseline", "multiprobe", "identifier", "characters", "length",
    "types", "transformations", "reflection", "validation",
]
IV_BUDGET_TIERS = ["quick", "standard", "deep", "exhaustive"]
IV_ATTACKS = [
    "xss", "sqli", "open_redirect", "ssrf", "webhook_abuse", "oauth_redirect",
    "hpp", "header_injection", "path_traversal", "mass_assignment",
]

COMMAND_TREE: list[dict] = [
    {
        "group": "project",
        "label": "Project",
        "commands": [
            cmd("project.create", ["project", "create"], "Create a new project", [
                arg("name", required=True, help="Project id/name"),
                arg("description", flag="--description", help="Short description"),
                arg(
                    "scope",
                    flag="--scope",
                    kind="multi",
                    help="Basic Scope prefixes, e.g. example.com http://api.example.com:8000",
                ),
            ]),
            cmd("project.open", ["project", "open"], "Open (activate) a project", [
                arg("id", required=True),
            ]),
            cmd("project.close", ["project", "close"], "Close the active project"),
            cmd("project.delete", ["project", "delete"], "Delete a project", [
                arg("id", required=True),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("project.list", ["project", "list"], "List all projects"),
            cmd("project.scope.add", ["project", "scope", "add"], "Add one in-scope URL/host prefix", [
                arg("prefix", required=True, help="e.g. example.com or https://example.com:8443/admin/"),
            ]),
            cmd("project.scope.remove", ["project", "scope", "remove"], "Remove one in-scope prefix", [
                arg("prefix", required=True),
            ]),
            cmd("project.scope.list", ["project", "scope", "list"], "List in-scope prefixes"),
            cmd("project.scope.clear", ["project", "scope", "clear"], "Clear all in-scope prefixes", [
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("project.scope.import", ["project", "scope", "import"], "Import in-scope prefixes from a text file", [
                arg("file", required=True, help="UTF-8 text: one prefix per line"),
            ]),
            cmd("project.scope", ["project", "scope"], "Legacy: replace scope list for a project id", [
                arg("id", required=True),
                arg("patterns", kind="multi", help="Basic Scope prefixes to set as the full list"),
            ]),
            cmd("project.constraints", ["project", "constraints"], "Set capture constraints", [
                arg("id", required=True),
                arg("store_bodies", flag="--store-bodies", kind="select", options=["true", "false"]),
                arg("max_body_size", flag="--max-body-size", kind="number", help="Bytes"),
            ]),
            cmd("project.status", ["project", "status"], "Show active project status"),
            cmd("project.outscope.add", ["project", "outscope", "add"], "Add out-of-scope URL/host prefix", [
                arg("prefix", required=True),
            ]),
            cmd("project.outscope.list", ["project", "outscope", "list"], "List out-of-scope prefixes"),
            cmd("project.outscope.remove", ["project", "outscope", "remove"], "Remove out-of-scope prefix", [
                arg("prefix", required=True),
            ]),
            cmd("project.outscope.clear", ["project", "outscope", "clear"], "Clear out-of-scope list", [
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("project.outscope.import", ["project", "outscope", "import"], "Import out-of-scope prefixes from a text file", [
                arg("file", required=True),
            ]),
        ],
    },
    {
        "group": "proxy",
        "label": "Proxy",
        "commands": [
            cmd("proxy.start", ["proxy", "start"], "Start the intercepting proxy", [
                arg("listen_host", flag="--listen-host", default="127.0.0.1"),
                arg("port", flag="--port", kind="number", default="8080"),
            ], background=True),
            cmd("proxy.stop", ["proxy", "stop"], "Gracefully stop the managed proxy"),
            cmd("proxy.restart", ["proxy", "restart"], "Restart the managed proxy", [
                arg("listen_host", flag="--listen-host"),
                arg("port", flag="--port", kind="number"),
            ], background=True),
            cmd("proxy.kill", ["proxy", "kill"], "Stop managed proxy and free listen port", [
                arg("listen_host", flag="--listen-host"),
                arg("port", flag="--port", kind="number"),
                arg("force", flag="--force", kind="boolean", help="Kill any process on the port, not only mitmdump"),
            ]),
            cmd("proxy.status", ["proxy", "status"], "Show proxy runtime status"),
            cmd("proxy.config", ["proxy", "config"], "Show or update proxy transport", [
                arg("upstream", flag="--upstream", help="Upstream proxy URL"),
                arg("http1", flag="--http1", kind="boolean", help="Force HTTP/1.1"),
                arg("keep_alive", flag="--keep-alive", kind="boolean"),
            ]),
            cmd("proxy.auth.list", ["proxy", "auth", "list"], "List platform-auth profiles"),
            cmd("proxy.auth.add", ["proxy", "auth", "add"], "Add a platform-auth profile", [
                arg("name", flag="--name"),
                arg("host", flag="--host", required=True),
                arg("type", flag="--type", kind="select", options=["ntlmv2", "ntlm", "negotiate"], default="ntlmv2"),
                arg("username", flag="--username"),
                arg("password", flag="--password"),
                arg("domain", flag="--domain"),
                arg("domain_hostname", flag="--domain-hostname"),
                arg("disabled", flag="--disabled", kind="boolean"),
            ]),
            cmd("proxy.auth.edit", ["proxy", "auth", "edit"], "Edit a platform-auth profile", [
                arg("id", flag="--id"),
                arg("name", flag="--name"),
                arg("host", flag="--host"),
                arg("type", flag="--type", kind="select", options=["ntlmv2", "ntlm", "negotiate"]),
                arg("username", flag="--username"),
                arg("password", flag="--password"),
                arg("domain", flag="--domain"),
                arg("domain_hostname", flag="--domain-hostname"),
            ]),
            cmd("proxy.auth.use", ["proxy", "auth", "use"], "Switch to a profile for its host", [
                arg("id", flag="--id"),
                arg("host", flag="--host"),
            ]),
            cmd("proxy.auth.enable", ["proxy", "auth", "enable"], "Enable a profile or the master switch", [
                arg("id", flag="--id"),
                arg("host", flag="--host"),
            ]),
            cmd("proxy.auth.disable", ["proxy", "auth", "disable"], "Disable a profile or the master switch", [
                arg("id", flag="--id"),
                arg("host", flag="--host"),
            ]),
            cmd("proxy.auth.remove", ["proxy", "auth", "remove"], "Remove a platform-auth profile", [
                arg("id", flag="--id"),
                arg("host", flag="--host"),
            ]),
        ],
    },
    {
        "group": "ui",
        "label": "Inspection UI",
        "commands": [
            cmd("ui.start", ["ui"], "Start Talos's built-in read-only inspection UI", [
                arg("host", flag="--host", default="127.0.0.1"),
                arg("port", flag="--port", kind="number", default="8010"),
            ], background=True),
        ],
    },
    {
        "group": "role",
        "label": "Roles",
        "commands": [
            cmd("role.create", ["role", "create"], "Create a role", [arg("name", required=True)]),
            cmd("role.list", ["role", "list"], "List roles"),
            cmd("role.set", ["role", "set"], "Set the active role", [arg("name", required=True)]),
            cmd("role.unset", ["role", "unset"], "Unset the active role"),
        ],
    },
    {
        "group": "module",
        "label": "Modules",
        "commands": [
            cmd("module.create", ["module", "create"], "Create a module", [
                arg("name", required=True),
                arg("description", flag="--description"),
            ]),
            cmd("module.list", ["module", "list"], "List modules"),
            cmd("module.set", ["module", "set"], "Set the active module", [arg("name", required=True)]),
            cmd("module.unset", ["module", "unset"], "Unset the active module"),
        ],
    },
    {
        "group": "access",
        "label": "Access Model",
        "commands": [
            cmd("access.client.set", ["access", "client", "set"], "Set client-allowed access", [
                arg("role", required=True), arg("module", required=True),
                arg("value", kind="select", options=ACCESS_VALUES, required=True),
            ]),
            cmd("access.client.unset", ["access", "client", "unset"], "Unset client-allowed access", [
                arg("role", required=True), arg("module", required=True),
            ]),
            cmd("access.server.set", ["access", "server", "set"], "Set server-expected access", [
                arg("role", required=True), arg("module", required=True),
                arg("value", kind="select", options=ACCESS_VALUES, required=True),
            ]),
            cmd("access.server.unset", ["access", "server", "unset"], "Unset server-expected access", [
                arg("role", required=True), arg("module", required=True),
            ]),
            cmd("access.delete", ["access", "delete"], "Delete an access mapping", [
                arg("role", required=True), arg("module", required=True),
            ]),
            cmd("access.show", ["access", "show"], "Show the access matrix"),
            cmd("access.coverage", ["access", "coverage"], "Expected vs observed coverage"),
            cmd("access.signals", ["access", "signals"], "BAC/IDOR signal report"),
        ],
    },
    {
        "group": "auth",
        "label": "Auth (artifacts)",
        "commands": [
            cmd("auth.set", ["auth", "set"], "Declare auth artifact names", [
                arg("cookie", flag="--cookie", kind="multi"),
                arg("header", flag="--header", kind="multi"),
            ]),
            cmd("auth.unset", ["auth", "unset"], "Remove auth artifact names", [
                arg("cookie", flag="--cookie", kind="multi"),
                arg("header", flag="--header", kind="multi"),
            ]),
            cmd("auth.show", ["auth", "show"], "Show configured auth artifacts"),
            cmd("auth.clear", ["auth", "clear"], "Clear all auth artifacts", [
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("auth.test", ["auth", "test"], "Run an auth-bypass test", [
                arg("endpoint_id", required=True),
                arg("right_now", flag="--right-now", kind="boolean"),
            ]),
        ],
    },
    {
        "group": "auth-config",
        "label": "Auth Config (per-role)",
        "commands": [
            cmd("auth_config.set_provider", ["auth-config", "set-provider"], "Set role auth provider", [
                arg("role_id", required=True),
                arg("provider", kind="select", options=["auto", "manual"], required=True),
            ]),
            cmd("auth_config.show_provider", ["auth-config", "show-provider"], "Show role auth provider", [
                arg("role_id", required=True),
            ]),
            cmd("auth_config.add_flow", ["auth-config", "add-flow"], "Attach a login flow", [
                arg("role", required=True), arg("flow_id", required=True),
            ]),
            cmd("auth_config.remove_flow", ["auth-config", "remove-flow"], "Detach a login flow", [
                arg("role", required=True), arg("flow_id", required=True),
            ]),
            cmd("auth_config.list_flows", ["auth-config", "list-flows"], "List login flows for a role", [
                arg("role", required=True),
            ]),
            cmd("auth_config.show_extractor", ["auth-config", "show-extractor"], "Show extractor source", [
                arg("role", required=True), arg("flow_id", required=True),
            ]),
            cmd("auth_config.remove_extractor", ["auth-config", "remove-extractor"], "Remove extractor", [
                arg("role", required=True), arg("flow_id", required=True),
            ]),
            cmd("auth_config.test", ["auth-config", "test"], "Test one flow+extractor (no state stored)", [
                arg("role", required=True), arg("flow_id", required=True),
            ]),
            cmd("auth_config.validate", ["auth-config", "validate"], "Validate a role's session", [
                arg("role", required=True),
            ]),
            cmd("auth_config.refresh", ["auth-config", "refresh"], "Force a full auth refresh", [
                arg("role", required=True),
            ]),
            cmd("auth_config.status", ["auth-config", "status"], "Show role auth status", [
                arg("role", required=True),
            ]),
            cmd("auth_config.show", ["auth-config", "show"], "Show full role auth config", [
                arg("role", required=True),
            ]),
            cmd("auth_config.set_ttl", ["auth-config", "set-ttl"], "Set session TTL", [
                arg("role", required=True),
                arg("ttl", flag="--ttl", kind="number", required=True),
                arg("refresh_before", flag="--refresh-before", kind="number"),
            ]),
            cmd("auth_config.add_expiry_signal", ["auth-config", "add-expiry-signal"], "Add expiry signal", [
                arg("role", required=True),
                arg("body", flag="--body", kind="multi"),
                arg("status", flag="--status", kind="multi"),
            ]),
            cmd("auth_config.clear_expiry_signals", ["auth-config", "clear-expiry-signals"], "Clear expiry signals", [
                arg("role", required=True),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("auth_config.clear_session", ["auth-config", "clear-session"], "Clear manual session (recovery)", [
                arg("role", required=True),
            ]),
            cmd("auth_config.reset_health", ["auth-config", "reset-health"], "Reset health suspicion counter", [
                arg("role", required=True),
            ]),
            cmd("auth_config.add_control_flow", ["auth-config", "add-control-flow"], "Add a control (validation) flow", [
                arg("role", required=True), arg("flow_id", required=True),
            ]),
            cmd("auth_config.remove_control_flow", ["auth-config", "remove-control-flow"], "Remove a control flow", [
                arg("role", required=True), arg("flow_id", required=True),
            ]),
            cmd("auth_config.list_control_flows", ["auth-config", "list-control-flows"], "List control flows", [
                arg("role", required=True),
            ]),
        ],
    },
    {
        "group": "endpoint",
        "label": "Endpoints",
        "commands": [
            cmd("endpoint.list", ["endpoint", "list"], "List endpoints with resolved policy", [
                arg("method", flag="--method"),
                arg("host", flag="--host"),
                arg("search", flag="--search"),
                arg("role", flag="--role"),
                arg("priority", flag="--priority", kind="select", options=PRIORITY_OPTIONS),
                arg("qualified", flag="--qualified", kind="boolean"),
                arg("excluded", flag="--excluded", kind="boolean"),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.mark", ["endpoint", "mark"], "Apply a safety annotation (multi-ID)", [
                arg("endpoint_id", required=True),
                arg("tag", kind="select", options=["--logout", "--dangerous", "--safe"], required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.unmark", ["endpoint", "unmark"], "Remove a safety annotation (multi-ID)", [
                arg("endpoint_id", required=True),
                arg("tag", kind="select", options=["--logout", "--dangerous"], required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.show", ["endpoint", "show"], "Show endpoint detail", [
                arg("endpoint_id", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.policy", ["endpoint", "policy"], "Explain effective policy for an endpoint", [
                arg("endpoint_id", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.export", ["endpoint", "export"], "Export complete endpoint dossier", [arg("endpoint_id", required=True)]),
            cmd("endpoint.priority.set_endpoint", ["endpoint", "priority", "set", "endpoint"], "Set priority for endpoint(s) (multi-ID; level last)", [
                arg("endpoint_id", required=True),
                arg("priority", kind="select", options=PRIORITY_OPTIONS, required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.priority.set_path", ["endpoint", "priority", "set", "path"], "Set priority for a path pattern (legacy)", [
                arg("pattern", required=True),
                arg("priority", kind="select", options=PRIORITY_OPTIONS, required=True),
            ]),
            cmd("endpoint.priority.clear_endpoint", ["endpoint", "priority", "clear", "endpoint"], "Clear priority override (multi-ID)", [
                arg("endpoint_id", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.priority.clear_path", ["endpoint", "priority", "clear", "path"], "Clear path priority rule (legacy)", [
                arg("pattern", required=True),
            ]),
            cmd("endpoint.exclude.endpoint", ["endpoint", "exclude", "endpoint"], "Exclude endpoint(s) (multi-ID)", [
                arg("endpoint_id", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.exclude.path", ["endpoint", "exclude", "path"], "Exclude a path pattern (legacy)", [arg("pattern", required=True)]),
            cmd("endpoint.include.endpoint", ["endpoint", "include", "endpoint"], "Include endpoint(s) (multi-ID)", [
                arg("endpoint_id", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.include.path", ["endpoint", "include", "path"], "Include a path pattern (legacy)", [arg("pattern", required=True)]),
            cmd("endpoint.rules", ["endpoint", "rules"], "List path policy rules (alias for rule list)", [
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.rule.add", ["endpoint", "rule", "add"], "Create a path policy rule", [
                arg("pattern", required=True),
                arg("priority", flag="--priority", kind="select", options=PRIORITY_OPTIONS),
                arg("exclude", flag="--exclude", kind="boolean"),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.rule.update", ["endpoint", "rule", "update"], "Update a path policy rule", [
                arg("rule_id", required=True),
                arg("priority", flag="--priority", kind="select", options=PRIORITY_OPTIONS),
                arg("clear_priority", flag="--clear-priority", kind="boolean"),
                arg("exclude", flag="--exclude", kind="boolean"),
                arg("include", flag="--include", kind="boolean"),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.rule.delete", ["endpoint", "rule", "delete"], "Delete a path policy rule", [
                arg("rule_id", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.rule.list", ["endpoint", "rule", "list"], "List path policy rules", [
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.rule.show", ["endpoint", "rule", "show"], "Show one path policy rule", [
                arg("rule_id", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.rule.preview", ["endpoint", "rule", "preview"], "Preview path rule impact (same matcher as live policy)", [
                arg("pattern", required=True),
                arg("priority", flag="--priority", kind="select", options=PRIORITY_OPTIONS),
                arg("exclude", flag="--exclude", kind="boolean"),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.tags.add", ["endpoint", "tags", "add"], "Add tags to endpoint(s)", [
                arg("endpoint_id", required=True),
                arg("tag", flag="--tag", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.tags.remove", ["endpoint", "tags", "remove"], "Remove tags from endpoint(s)", [
                arg("endpoint_id", required=True),
                arg("tag", flag="--tag", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("endpoint.tags.clear", ["endpoint", "tags", "clear"], "Clear all tags from endpoint(s)", [
                arg("endpoint_id", required=True),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
        ],
    },
    {
        "group": "replay",
        "label": "Replay",
        "commands": [
            cmd("replay.flow", ["replay", "flow"], "Replay a specific flow", [
                arg("flow_id", required=True), arg("right_now", flag="--right-now", kind="boolean"),
            ]),
            cmd("replay.endpoint", ["replay", "endpoint"], "Replay an endpoint's best flow", [
                arg("endpoint_id", required=True), arg("right_now", flag="--right-now", kind="boolean"),
            ]),
        ],
    },
    {
        "group": "flow",
        "label": "Flows",
        "commands": [
            cmd("flow.show", ["flow", "show"], "Show a flow", [arg("flow_id", required=True)]),
            cmd("flow.export", ["flow", "export"], "Export flow(s)", [
                arg("flow_id", help="Single flow id (optional if using a filter below)"),
                arg("module", flag="--module", kind="select", options=["input_validation", "bac"]),
                arg("parameter", flag="--parameter"),
                arg("endpoint", flag="--endpoint"),
                arg("flows", flag="--flows", kind="multi"),
            ]),
        ],
    },
    {
        "group": "config",
        "label": "Configuration (layered)",
        "commands": [
            cmd("config.show", ["config", "show"], "Config file paths and layer summary", [
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("config.effective", ["config", "effective"], "Fully merged config with value sources", [
                arg("section", flag="--section", kind="select", options=["proxy", "capture", "scheduler", "attack", "http"]),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("config.get", ["config", "get"], "Get one value + inheritance source", [
                arg("key", required=True, help="Dotted key, e.g. scheduler.max_delay"),
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("config.set", ["config", "set"], "Set project override (or global)", [
                arg("key", required=True, help="Dotted key, e.g. proxy.upstream.url"),
                arg("value", required=True, help="Value (bool/int/float/string/JSON)"),
                arg("global_scope", flag="--global", kind="boolean", help="Write ~/.talos/config.yaml"),
            ]),
            cmd("config.unset", ["config", "unset"], "Remove override (inherit lower layer)", [
                arg("key", required=True),
                arg("global_scope", flag="--global", kind="boolean"),
            ]),
            cmd("config.edit", ["config", "edit"], "Open project.yaml (or global) in $EDITOR", [
                arg("global_scope", flag="--global", kind="boolean"),
            ]),
            cmd("config.schema", ["config", "schema"], "Machine-readable types and defaults", [
                arg("format", flag="--format", kind="select", options=["table", "json"], default="json"),
            ]),
            cmd("config.proxy.show", ["config", "proxy", "show"], "Show effective proxy section", [
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("config.capture.show", ["config", "capture", "show"], "Show effective capture section", [
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("config.scheduler.show", ["config", "scheduler", "show"], "Show effective scheduler section", [
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("config.attack.show", ["config", "attack", "show"], "Show effective attack section", [
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("config.http.list", ["config", "http", "list"], "List HTTP manipulation rules", [
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("config.http.create", ["config", "http", "create"], "Create an HTTP rule", [
                arg("name", flag="--name", required=True),
                arg("direction", flag="--direction", kind="select", options=["request", "response", "both"]),
                arg("action", flag="--action"),
                arg("match_host", flag="--match-host"),
                arg("match_path", flag="--match-path"),
            ]),
            cmd("config.http.show", ["config", "http", "show"], "Show effective http section", [
                arg("format", flag="--format", kind="select", options=["table", "json"]),
            ]),
            cmd("config.section.set", ["config", "scheduler", "set"], "Set a section-relative key (example: scheduler)", [
                arg("key", required=True, help="Relative key under the section, e.g. max_delay"),
                arg("value", required=True),
                arg("global_scope", flag="--global", kind="boolean"),
            ]),
            cmd("config.section.unset", ["config", "scheduler", "unset"], "Unset a section-relative key (example: scheduler)", [
                arg("key", required=True),
                arg("global_scope", flag="--global", kind="boolean"),
            ]),
        ],
    },
    {
        "group": "scheduler",
        "label": "Scheduler",
        "commands": [
            cmd("scheduler.status", ["scheduler", "status"], "Show process runtime + queue metrics"),
            cmd("scheduler.start", ["scheduler", "start"], "Start the managed scheduler process"),
            cmd("scheduler.stop", ["scheduler", "stop"], "Stop the managed scheduler process"),
            cmd("scheduler.config", ["scheduler", "config"], "View/set scheduler rate limits and IST testing windows", [
                arg("min_delay", flag="--min-delay", kind="number"),
                arg("max_delay", flag="--max-delay", kind="number"),
                arg("max_queue_size", flag="--max-queue-size", kind="number"),
                arg("testing_windows", flag="--testing-windows", kind="select", options=["on", "off"]),
                arg("window", flag="--window", help="IST HH:MM-HH:MM (repeat flag for several windows)"),
                arg("clear_windows", flag="--clear-windows", kind="boolean"),
            ]),
            cmd("scheduler.enqueue.flow", ["scheduler", "enqueue", "flow"], "Enqueue a flow replay job", [
                arg("flow_id", required=True),
                arg("priority", flag="--priority", kind="number"),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("scheduler.enqueue.endpoint", ["scheduler", "enqueue", "endpoint"], "Enqueue an endpoint job", [
                arg("endpoint_id", required=True),
                arg("type", flag="--type", kind="select", options=["replay", "auth-test"]),
                arg("priority", flag="--priority", kind="number"),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("scheduler.jobs.list", ["scheduler", "jobs", "list"], "List jobs with optional filters", [
                arg("status", flag="--status", kind="select", options=[
                    "pending", "running", "paused", "done", "failed", "skipped", "cancelled",
                ]),
                arg("type", flag="--type", help="Exact type or family prefix (replay, bac, iv, unauth)"),
                arg("limit", flag="--limit", kind="number"),
            ]),
            cmd("scheduler.jobs.show", ["scheduler", "jobs", "show"], "Show full job detail (UUID or unique prefix)", [
                arg("job_id", required=True, help="Job UUID or unique prefix"),
            ]),
            cmd("scheduler.cancel", ["scheduler", "cancel"], "Cancel one pending or paused job", [
                arg("job_id", required=True, help="Job UUID or unique prefix"),
            ]),
            cmd("scheduler.prune", ["scheduler", "prune"], "Delete terminal job history for one status", [
                arg("status", flag="--status", required=True, kind="select", options=[
                    "done", "failed", "skipped", "cancelled",
                ]),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("scheduler.clear", ["scheduler", "clear"], "Clear pending jobs", [
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("scheduler.pause", ["scheduler", "pause"], "Pause queue execution"),
            cmd("scheduler.resume", ["scheduler", "resume"], "Resume queue execution"),
        ],
    },
    {
        "group": "http",
        "label": "HTTP Rules",
        "commands": [
            cmd("http.list", ["config", "http", "list"], "List HTTP rules"),
            cmd("http.create", ["config", "http", "create"], "Create HTTP rule", [
                arg("name", flag="--name", required=True),
                arg("action", flag="--action", required=True),
                arg("direction", flag="--direction", kind="select", options=["request", "response", "both"]),
            ]),
            cmd("http.delete", ["config", "http", "delete"], "Delete HTTP rule", [
                arg("rule_id", required=True),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("http.enable", ["config", "http", "enable"], "Enable HTTP rule", [arg("rule_id", required=True)]),
            cmd("http.disable", ["config", "http", "disable"], "Disable HTTP rule", [arg("rule_id", required=True)]),
        ],
    },
    {
        "group": "attack.unauth",
        "label": "Attack — Unauth",
        "commands": [
            cmd("attack.unauth.run", ["attack", "unauth", "run"], "Run unauth attack recipes", [
                arg(
                    "technique",
                    flag="--technique",
                    kind="select",
                    options=[
                        "baseline",
                        "empty_auth",
                        "malformed_auth",
                        "auth_null",
                        "auth_whitespace",
                        "duplicate_empty_header",
                        "duplicate_malformed_header",
                    ],
                    help="Restrict to one Unauth technique (default: all recipes)",
                ),
                arg("flow", flag="--flow", kind="multi", help="Specific flow UUID(s); skips auto ranking"),
            ]),
            cmd("attack.unauth.config", ["attack", "unauth", "config"], "Show or set unauth auto-run", [
                arg(
                    "auto_run",
                    flag="--auto-run",
                    kind="select",
                    options=["on", "off"],
                    help="Enable (on) or disable (off) scheduler auto-enqueue of auth_test jobs",
                ),
            ]),
            cmd("attack.unauth.filter.init", ["attack", "unauth", "filter", "init"], "Create decision filter template"),
            cmd("attack.unauth.filter.show", ["attack", "unauth", "filter", "show"], "Show decision filter"),
            cmd("attack.unauth.filter.validate", ["attack", "unauth", "filter", "validate"], "Validate decision filter"),
            cmd(
                "attack.unauth.filter.apply",
                ["attack", "unauth", "filter", "apply"],
                "Re-apply decision filter to existing unauth results / findings",
                [
                    arg("dry_run", flag="--dry-run", kind="boolean", help="Preview without writing"),
                    arg("force", flag="--force", kind="boolean", help="Skip confirm; also reject CONFIRMED"),
                ],
            ),
        ],
    },
    {
        "group": "attack.auth-session",
        "label": "Attack — Auth-Session Testing",
        "commands": [
            cmd(
                "attack.auth-session.bind",
                ["attack", "auth-session", "bind"],
                "Bind an auth_config header/cookie to jwt auth type",
                [
                    arg(
                        "type",
                        flag="--type",
                        kind="select",
                        options=["jwt"],
                        default="jwt",
                        help="Auth type (v1: jwt only)",
                    ),
                    arg("header", flag="--header", help="Header name already in auth_config"),
                    arg("cookie", flag="--cookie", help="Cookie name already in auth_config"),
                    arg("role", flag="--role", help="Optional preferred role name or UUID"),
                    arg(
                        "config_json",
                        flag="--config-json",
                        help="Optional binding config JSON string",
                    ),
                ],
            ),
            cmd(
                "attack.auth-session.unbind",
                ["attack", "auth-session", "unbind"],
                "Remove a binding (--force deletes targets and results)",
                [
                    arg("header", flag="--header", help="Header field name"),
                    arg("cookie", flag="--cookie", help="Cookie field name"),
                    arg("id", flag="--id", help="Binding UUID"),
                    arg(
                        "force",
                        flag="--force",
                        kind="boolean",
                        help="Cascade-delete target flows, tests, and results",
                    ),
                ],
            ),
            cmd(
                "attack.auth-session.generate",
                ["attack", "auth-session", "generate"],
                "Create pending JWT mutation candidates (no HTTP)",
                [
                    arg("binding", flag="--binding", help="Limit to one binding UUID"),
                    arg("flow", flag="--flow", kind="multi", help="Explicit baseline flow UUID(s)"),
                    arg("endpoint", flag="--endpoint", help="One testable endpoint UUID"),
                    arg(
                        "module",
                        flag="--module",
                        help="Module name/UUID (mutex with endpoint)",
                    ),
                    arg("role", flag="--role", help="Prefer role-tagged flows"),
                    arg(
                        "test_id",
                        flag="--test-id",
                        kind="multi",
                        help="Repeatable: only these test_ids",
                    ),
                    arg(
                        "family",
                        flag="--family",
                        kind="multi",
                        help="Repeatable: signature, algorithm, claims, …",
                    ),
                    arg(
                        "force_refresh",
                        flag="--force-refresh",
                        kind="boolean",
                        help="Refresh pending/rejected metadata only",
                    ),
                    arg(
                        "include_unsafe_methods",
                        flag="--include-unsafe-methods",
                        kind="boolean",
                        help="Allow POST/PUT/PATCH/DELETE baselines",
                    ),
                ],
            ),
            cmd(
                "attack.auth-session.candidates.add",
                ["attack", "auth-session", "candidates", "add"],
                "Add a target flow and generate JWT tests for it",
                [
                    arg("flow", flag="--flow", help="Baseline flow UUID"),
                    arg("binding", flag="--binding", help="Binding UUID"),
                ],
            ),
            cmd(
                "attack.auth-session.candidates.remove",
                ["attack", "auth-session", "candidates", "remove"],
                "Remove a target flow and its JWT tests",
                [
                    arg("flow", flag="--flow", help="Baseline flow UUID"),
                    arg("binding", flag="--binding", help="Limit to one binding UUID"),
                ],
            ),
            cmd(
                "attack.auth-session.approve",
                ["attack", "auth-session", "approve"],
                "Approve candidates (pending|failed|done → approved)",
                [
                    arg(
                        "candidate_ids",
                        kind="multi",
                        help="Candidate UUIDs (positional; optional with bulk flags)",
                    ),
                    arg(
                        "all_pending",
                        flag="--all-pending",
                        kind="boolean",
                        help="Approve all pending in scope",
                    ),
                    arg(
                        "retry_failed",
                        flag="--retry-failed",
                        kind="boolean",
                        help="Re-approve failed candidates",
                    ),
                    arg("endpoint", flag="--endpoint", help="Scope to endpoint UUID"),
                    arg(
                        "test_id",
                        flag="--test-id",
                        kind="multi",
                        help="Repeatable test_id filter",
                    ),
                    arg(
                        "family",
                        flag="--family",
                        kind="multi",
                        help="Repeatable family filter",
                    ),
                ],
            ),
            cmd(
                "attack.auth-session.reject",
                ["attack", "auth-session", "reject"],
                "Reject pending candidates",
                [
                    arg(
                        "candidate_ids",
                        kind="multi",
                        help="Candidate UUIDs (positional; optional with --all-pending)",
                    ),
                    arg(
                        "all_pending",
                        flag="--all-pending",
                        kind="boolean",
                        help="Reject all pending in scope",
                    ),
                    arg("reason", flag="--reason", help="Optional reject reason"),
                    arg("endpoint", flag="--endpoint", help="Scope to endpoint UUID"),
                    arg(
                        "test_id",
                        flag="--test-id",
                        kind="multi",
                        help="Repeatable test_id filter",
                    ),
                    arg(
                        "family",
                        flag="--family",
                        kind="multi",
                        help="Repeatable family filter",
                    ),
                ],
            ),
            cmd(
                "attack.auth-session.unapprove",
                ["attack", "auth-session", "unapprove"],
                "Move approved candidates back to pending",
                [
                    arg(
                        "candidate_ids",
                        kind="multi",
                        help="Candidate UUIDs (positional; optional with --all-approved)",
                    ),
                    arg(
                        "all_approved",
                        flag="--all-approved",
                        kind="boolean",
                        help="Unapprove all approved in scope",
                    ),
                    arg("endpoint", flag="--endpoint", help="Scope to endpoint UUID"),
                    arg(
                        "test_id",
                        flag="--test-id",
                        kind="multi",
                        help="Repeatable test_id filter",
                    ),
                    arg(
                        "family",
                        flag="--family",
                        kind="multi",
                        help="Repeatable family filter",
                    ),
                ],
            ),
            cmd(
                "attack.auth-session.run",
                ["attack", "auth-session", "run"],
                "Enqueue JWT tests for selected target flows (or --right-now)",
                [
                    arg(
                        "candidate",
                        flag="--candidate",
                        kind="multi",
                        help="Repeatable candidate UUIDs",
                    ),
                    arg("endpoint", flag="--endpoint", help="Scope to endpoint UUID"),
                    arg(
                        "test_id",
                        flag="--test-id",
                        kind="multi",
                        help="Repeatable test_id filter",
                    ),
                    arg(
                        "family",
                        flag="--family",
                        kind="multi",
                        help="Repeatable family filter",
                    ),
                    arg("binding", flag="--binding", help="Limit to one binding UUID"),
                    arg(
                        "jwt",
                        flag="--jwt",
                        help="Custom JWT for every selected flow (default: latest captured)",
                    ),
                    arg(
                        "right_now",
                        flag="--right-now",
                        kind="boolean",
                        help="Execute immediately (bypass scheduler queue)",
                    ),
                ],
            ),
            cmd(
                "attack.auth-session.filter.init",
                ["attack", "auth-session", "filter", "init"],
                "Write default auth-session-decision-filter.yaml if missing",
                [],
            ),
            cmd(
                "attack.auth-session.filter.show",
                ["attack", "auth-session", "filter", "show"],
                "Print decision filter YAML",
                [],
            ),
            cmd(
                "attack.auth-session.filter.validate",
                ["attack", "auth-session", "filter", "validate"],
                "Validate decision filter structure",
                [],
            ),
            cmd(
                "attack.auth-session.suite.list",
                ["attack", "auth-session", "suite", "list"],
                "List JWT suite catalog test_ids",
                [
                    arg(
                        "type",
                        flag="--type",
                        kind="select",
                        options=["jwt"],
                        default="jwt",
                        help="Auth type (v1: jwt)",
                    ),
                    arg("alg", flag="--alg", help="Expand algorithm degradation for this alg"),
                    arg(
                        "family",
                        flag="--family",
                        kind="multi",
                        help="Repeatable family filter",
                    ),
                ],
            ),
        ],
    },
    {
        "group": "attack.bac",
        "label": "Attack — BAC",
        "commands": [
            cmd(f"attack.bac.{tech}", ["attack", "bac", tech], f"Run BAC {tech.replace('-', ' ')}", [
                arg("role", flag="--role", help="Attacker role name or UUID"),
                arg("module", flag="--module", help="Module scope (name or UUID); mutex with endpoint"),
                arg("endpoint", flag="--endpoint", help="Endpoint UUID scope; mutex with module / flow"),
                arg("flow", flag="--flow", kind="multi", help="Specific flow UUID(s); mutex with endpoint / module"),
                arg("auto_generate", flag="--auto-generate", kind="boolean", help="Auto-generate missing session tokens"),
            ])
            for tech in [
                "session-swap", "method-fuzz", "content-type", "url-fuzz",
                "header-inject", "host-fuzz", "role-inject", "parser-confuse",
            ]
        ] + [
            cmd("attack.bac.filter.init", ["attack", "bac", "filter", "init"], "Create BAC decision filter template"),
            cmd("attack.bac.filter.show", ["attack", "bac", "filter", "show"], "Show BAC decision filter"),
            cmd("attack.bac.filter.validate", ["attack", "bac", "filter", "validate"], "Validate BAC decision filter"),
            cmd(
                "attack.bac.filter.apply",
                ["attack", "bac", "filter", "apply"],
                "Re-apply decision filter to existing BAC results / findings",
                [
                    arg("dry_run", flag="--dry-run", kind="boolean", help="Preview without writing"),
                    arg("force", flag="--force", kind="boolean", help="Skip confirm; also reject CONFIRMED"),
                ],
            ),
        ],
    },
    {
        "group": "attack.cors",
        "label": "Attack — CORS",
        "commands": [
            cmd("attack.cors.candidates", ["attack", "cors", "candidates"], "List in-scope 200 OK CORS baselines", [
                arg("limit", flag="--limit", kind="number", default="5", help="Max candidates (default 5)"),
                arg("endpoint", flag="--endpoint", help="Endpoint UUID"),
                arg("host", flag="--host", help="Host filter"),
                arg("flow", flag="--flow", kind="multi", help="Specific flow UUID(s); skips auto ranking"),
            ]),
            cmd("attack.cors.techniques", ["attack", "cors", "techniques"], "List CORS Origin techniques"),
            cmd("attack.cors.run", ["attack", "cors", "run"], "Enqueue CORS probes (unique flow per technique)", [
                arg(
                    "technique",
                    flag="--technique",
                    kind="select",
                    options=[
                        "baseline_origin",
                        "arbitrary_https",
                        "arbitrary_http",
                        "attacker_subdomain",
                        "subdomain_of_target",
                        "prefix_bypass",
                        "suffix_bypass",
                        "trusted_plus",
                        "unescaped_dot",
                        "encoded_dot",
                        "underscore",
                        "null_origin",
                        "wildcard_origin",
                        "localhost",
                        "loopback",
                        "scheme_downgrade",
                        "port_443",
                        "port_80",
                        "port_8080",
                        "preflight",
                    ],
                    help="Restrict to one Origin technique (default: all)",
                ),
                arg("limit", flag="--limit", kind="number", default="5", help="Max candidates (default 5)"),
                arg("endpoint", flag="--endpoint", help="Endpoint UUID"),
                arg("host", flag="--host", help="Host filter"),
                arg("flow", flag="--flow", kind="multi", help="Specific flow UUID(s); skips auto ranking"),
                arg("right_now", flag="--right-now", kind="boolean", help="Execute immediately"),
            ]),
            cmd("attack.cors.results.list", ["attack", "cors", "results", "list"], "List CORS probe results"),
            cmd("attack.cors.status", ["attack", "cors", "status"], "CORS verdict and job tallies"),
        ],
    },
    {
        "group": "input-validation",
        "label": "Input Validation Engine",
        "commands": [
            cmd("iv.config", ["input-validation", "config"], "View/set IV engine config", [
                arg("enable", flag="--enable", kind="boolean"),
                arg("disable", flag="--disable", kind="boolean"),
                arg("workers", flag="--workers", kind="number"),
                arg("analysis_off", flag="--analysis-off", kind="select", options=IV_PHASES),
                arg("analysis_on", flag="--analysis-on", kind="select", options=IV_PHASES),
                arg("probe_strategy", flag="--probe-strategy", kind="select", options=IV_BUDGET_TIERS,
                    help="Planner budget tier (alias: --budget)"),
                arg("max_requests", flag="--max-requests-per-param", kind="number",
                    help="Hard HTTP cap per parameter (0 = tier default)"),
                arg("include_auth", flag="--include-auth-artifacts", kind="boolean"),
            ]),
            cmd("iv.run", ["input-validation", "run"], "Schedule IV jobs (adaptive planner)", [
                arg("host", flag="--host"), arg("endpoint", flag="--endpoint"),
                arg("flow", flag="--flow", kind="multi", help="Scope to endpoints of these flows"),
                arg("parameter", flag="--parameter"),
                arg("budget", flag="--budget", kind="select", options=IV_BUDGET_TIERS,
                    help="Set planner budget tier then schedule"),
                arg("ignore_cache", flag="--ignore-cache", kind="boolean"),
                arg("include_auth", flag="--include-auth-artifacts", kind="boolean"),
            ]),
            cmd("iv.status", ["input-validation", "status"], "Show IV progress, budget, confidence"),
            cmd("iv.resume", ["input-validation", "resume"], "Resume unfinished IV analyses", [
                arg("host", flag="--host"), arg("endpoint", flag="--endpoint"),
                arg("flow", flag="--flow", kind="multi"),
                arg("parameter", flag="--parameter"),
            ]),
            cmd("iv.synthesize", ["input-validation", "synthesize"], "Offline profiles from existing probes", [
                arg("host", flag="--host"),
                arg("param_uuid", flag="--param-uuid"),
                arg("dry_run", flag="--dry-run", kind="boolean"),
            ]),
            cmd("iv.candidates", ["input-validation", "candidates"],
                "List attack candidates (prioritization only, not vulns)", [
                arg("attack", flag="--attack", kind="select", options=IV_ATTACKS),
                arg("min_score", flag="--min-score", kind="number"),
                arg("host", flag="--host"),
                arg("capability", flag="--capability"),
            ]),
            cmd("iv.reflections", ["input-validation", "reflections"],
                "List raw cross-flow / stored reflection links (data-flow evidence)", [
                arg("param_uuid", flag="--param-uuid"),
                arg("host", flag="--host"),
                arg("source_endpoint", flag="--source-endpoint"),
                arg("sink_endpoint", flag="--sink-endpoint"),
                arg("limit", flag="--limit", kind="number"),
                arg("include_values", flag="--include-values", kind="boolean"),
            ]),
            cmd("iv.clear_cache", ["input-validation", "clear-cache"], "Reset IV probes, profiles, and cache", [
                arg("host", flag="--host"), arg("endpoint", flag="--endpoint"), arg("parameter", flag="--parameter"),
            ]),
            cmd("iv.exclude.endpoint", ["input-validation", "exclude", "endpoint"], "Exclude endpoint from IV", [arg("endpoint_id", required=True)]),
            cmd("iv.exclude.host", ["input-validation", "exclude", "host"], "Exclude host from IV", [arg("host", required=True)]),
            cmd("iv.include.endpoint", ["input-validation", "include", "endpoint"], "Include endpoint in IV", [arg("endpoint_id", required=True)]),
            cmd("iv.include.host", ["input-validation", "include", "host"], "Include host in IV", [arg("host", required=True)]),
            cmd("iv.show", ["input-validation", "show"], "Show parameter profile + candidates", [arg("parameter_uuid", required=True)]),
            cmd("iv.show.endpoint", ["input-validation", "show"], "Show endpoint intelligence", [
                arg("endpoint", flag="--endpoint", required=True),
            ]),
            cmd("iv.show.host", ["input-validation", "show"], "Show application/host intelligence", [
                arg("host", flag="--host", required=True),
            ]),
            cmd("iv.export.parameter", ["input-validation", "export", "parameter"], "Export one parameter (md/json)", [
                arg("parameter_uuid", required=True),
                arg("format", flag="--format", kind="select", options=["markdown", "json"]),
            ]),
            cmd("iv.export.host", ["input-validation", "export", "host"], "Export host-level IV (md/json)", [
                arg("host", required=True),
                arg("format", flag="--format", kind="select", options=["markdown", "json"]),
            ]),
            cmd("iv.export.csv", ["input-validation", "export", "csv"], "Export all probe results as CSV"),
        ] + [
            cmd(f"iv.phase.{phase}", ["input-validation", phase], f"Run IV phase: {phase}", [
                arg("host", flag="--host"), arg("endpoint", flag="--endpoint"),
                arg("flow", flag="--flow", kind="multi"),
                arg("parameter", flag="--parameter"),
                arg("ignore_cache", flag="--ignore-cache", kind="boolean"),
            ])
            for phase in IV_PHASES
        ],
    },
    {
        "group": "passive",
        "label": "Secret Detection (Passive)",
        "commands": [
            cmd("passive.status", ["passive", "status"], "Document / detection / finding counts"),
            cmd("passive.config.show", ["passive", "config", "show"], "Show passive_scan_config"),
            cmd("passive.config.set", ["passive", "config", "set"], "Update one config field", [
                arg("key", required=True, help="e.g. enabled, auto_finding_threshold, scan_javascript"),
                arg("value", required=True, help="true/false, int, or threshold name"),
            ]),
            cmd("passive.rules.list", ["passive", "rules", "list"], "List loaded detector rules"),
            cmd("passive.documents.list", ["passive", "documents", "list"], "Source documents inventory", [
                arg("status", flag="--status", help="pending|scanned|error|too_large|skipped"),
                arg("kind", flag="--kind", help="html|javascript|json|xml|text|css|sourcemap"),
                arg("limit", flag="--limit", kind="number", default="50"),
            ]),
            cmd("passive.documents.show", ["passive", "documents", "show"], "Show one source document", [
                arg("document_id", required=True),
            ]),
            cmd("passive.detections.list", ["passive", "detections", "list"], "List passive detections (redacted)", [
                arg("type", flag="--type", help="secret_type or detector_id"),
                arg("confidence", flag="--confidence", kind="select", options=[
                    "CONFIRMED_PATTERN", "HIGH", "MEDIUM", "OBSERVATION_ONLY",
                ]),
                arg("category", flag="--category", kind="select", options=[
                    "secret", "infrastructure_disclosure", "sensitive_info",
                ]),
                arg("document", flag="--document", help="Filter by document id"),
                arg("suppressed", flag="--suppressed", kind="boolean", help="Only suppressed"),
                arg("has_finding", flag="--has-finding", kind="boolean", help="Only with finding link"),
                arg("limit", flag="--limit", kind="number", default="50"),
            ]),
            cmd("passive.detections.show", ["passive", "detections", "show"], "Show one detection (redacted)", [
                arg("detection_id", required=True),
            ]),
            cmd("passive.rescan.all", ["passive", "rescan"], "Rescan outdated documents", [
                arg("all", flag="--all", kind="boolean", required=True, default=True),
                arg("force", flag="--force", kind="boolean", help="Even if already at SCANNER_VERSION"),
            ]),
            cmd("passive.rescan.document", ["passive", "rescan"], "Rescan one document", [
                arg("document", flag="--document", required=True),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("passive.rescan.flow", ["passive", "rescan"], "Rescan body from a flow", [
                arg("flow", flag="--flow", required=True),
                arg("force", flag="--force", kind="boolean"),
            ]),
        ],
    },
    {
        "group": "error-intel",
        "label": "Error Intelligence (Passive)",
        "commands": [
            cmd("error-intel.status", ["error-intel", "status"],
                "Cluster / observation counts by severity"),
            cmd("error-intel.config.show", ["error-intel", "config", "show"],
                "Show error_intel_config"),
            cmd("error-intel.config.set", ["error-intel", "config", "set"],
                "Update one config field", [
                arg("key", required=True,
                    help="enabled, store_generic_http_errors, max_body_scan, …"),
                arg("value", required=True, help="true/false or int"),
            ]),
            cmd("error-intel.errors.list", ["error-intel", "errors", "list"],
                "List error clusters", [
                arg("category", flag="--category",
                    help="stack_trace|database|framework|…"),
                arg("severity", flag="--severity",
                    kind="select",
                    options=["low", "medium", "high", "critical"]),
                arg("limit", flag="--limit", kind="number", default="50"),
            ]),
            cmd("error-intel.errors.show", ["error-intel", "errors", "show"],
                "Show one error cluster", [
                arg("error_id", required=True),
            ]),
            cmd("error-intel.observations.list",
                ["error-intel", "observations", "list"],
                "List observations (flow / param / attack)", [
                arg("error", flag="--error", help="Filter by error cluster id"),
                arg("flow", flag="--flow"),
                arg("endpoint", flag="--endpoint"),
                arg("parameter", flag="--parameter"),
                arg("attack", flag="--attack",
                    kind="select",
                    options=["proxy", "replay", "iv", "bac", "unauth", "unknown"]),
                arg("limit", flag="--limit", kind="number", default="50"),
            ]),
            cmd("error-intel.rescan.all", ["error-intel", "rescan"],
                "Rescan recent error-like flows", [
                arg("all", flag="--all", kind="boolean", required=True, default=True),
                arg("force", flag="--force", kind="boolean",
                    help="Re-process even at current ERROR_INTEL_VERSION"),
                arg("outdated", flag="--outdated", kind="boolean",
                    help="Only missing or older scanner_version sightings"),
                arg("limit", flag="--limit", kind="number", default="200"),
            ]),
            cmd("error-intel.rescan.flow", ["error-intel", "rescan"],
                "Rescan one flow body", [
                arg("flow", flag="--flow", required=True),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("error-intel.rollup.parameter",
                ["error-intel", "rollup", "parameter"],
                "Parameter × error rollup", [
                arg("parameter", flag="--parameter"),
                arg("limit", flag="--limit", kind="number", default="50"),
            ]),
            cmd("error-intel.rollup.endpoint",
                ["error-intel", "rollup", "endpoint"],
                "Endpoint × error rollup", [
                arg("endpoint", flag="--endpoint"),
                arg("limit", flag="--limit", kind="number", default="50"),
            ]),
        ],
    },
    {
        "group": "finding",
        "label": "Findings",
        "commands": [
            cmd("finding.list", ["finding", "list"], "List findings (default PRIMARY)", [
                arg("status", flag="--status", kind="select", options=["TRIAGING", "CONFIRMED", "REJECTED", "DUPLICATE"]),
                arg("linked", flag="--linked", kind="boolean", help="List LINKED findings only"),
                arg("all", flag="--all", kind="boolean", help="List PRIMARY and LINKED"),
            ]),
            cmd("finding.show", ["finding", "show"], "Show finding detail", [arg("uuid", required=True)]),
            cmd("finding.confirm", ["finding", "confirm"], "Confirm a finding", [
                arg("uuid", required=True),
                arg("linked", flag="--linked", kind="boolean", help="Also update currently LINKED children (PRIMARY only)"),
                arg("force", flag="--force", kind="boolean", help="Skip confirm when --linked overwrites mixed statuses"),
            ]),
            cmd("finding.reject", ["finding", "reject"], "Reject a finding", [
                arg("uuid", required=True),
                arg("linked", flag="--linked", kind="boolean"),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("finding.reopen", ["finding", "reopen"], "Reopen a finding", [
                arg("uuid", required=True),
                arg("linked", flag="--linked", kind="boolean"),
                arg("force", flag="--force", kind="boolean"),
            ]),
            cmd("finding.duplicate", ["finding", "duplicate"], "Mark as duplicate", [
                arg("uuid", required=True), arg("of", flag="--of", required=True),
            ]),
            cmd(
                "finding.note.set",
                ["finding", "note", "set"],
                "Set analyst notes (text piped to stdin)",
                [
                    arg("uuid", required=True),
                    arg("notes", required=True, help="Free-form notes (sent on stdin)"),
                ],
                stdin_from="notes",
            ),
            cmd("finding.note.clear", ["finding", "note", "clear"], "Clear analyst notes", [
                arg("uuid", required=True),
            ]),
            cmd("finding.group.create", ["finding", "group", "create"], "Create a finding group", [arg("name", required=True)]),
            cmd("finding.group.add", ["finding", "group", "add"], "Add finding to group", [
                arg("group", required=True), arg("finding", required=True),
            ]),
            cmd("finding.group.remove_member", ["finding", "group", "remove"], "Remove finding from group", [
                arg("group", required=True), arg("finding", required=True),
            ]),
            cmd("finding.group.delete", ["finding", "group", "remove"], "Delete a group", [
                arg("group", required=True),
                arg("remove_findings", flag="--remove-findings", kind="boolean"),
            ]),
            cmd("finding.group.list", ["finding", "group", "list"], "List groups"),
            cmd("finding.report", ["finding", "report"], "Generate a report", [
                arg("uuid", help="Finding UUID (omit if using --group)"),
                arg("group", flag="--group"),
            ]),
        ],
    },
]


def find_command(cmd_id: str) -> dict | None:
    for group in COMMAND_TREE:
        for c in group["commands"]:
            if c["id"] == cmd_id:
                return c
    return None


def build_argv(command: dict, values: dict[str, Any]) -> list[str]:
    """Turn a command spec + submitted values into a safe argv list (no shell).

    Args named in command['stdin_from'] are omitted from argv (piped separately).
    """
    argv = list(command["path"])
    positionals: list[str] = []
    flagged: list[str] = []
    stdin_from = command.get("stdin_from")

    for spec in command["args"]:
        if stdin_from and spec["name"] == stdin_from:
            continue
        val = values.get(spec["name"])
        if val is None or val == "" or val == []:
            continue
        flag = spec["flag"]
        if spec["kind"] == "boolean":
            if flag and (val is True or str(val).lower() == "true"):
                flagged.append(flag)
            continue
        if spec["kind"] == "multi":
            items = val if isinstance(val, list) else [val]
            for item in items:
                item = str(item)
                if not item:
                    continue
                if flag:
                    flagged.append(flag)
                    flagged.append(item)
                else:
                    positionals.append(item)
            continue
        # text / number / select
        value_str = str(val)
        if flag:
            flagged.append(flag)
            flagged.append(value_str)
        else:
            positionals.append(value_str)

    return argv + positionals + flagged


def stdin_text_for(command: dict, values: dict[str, Any]) -> str | None:
    """Return stdin payload when command declares stdin_from, else None."""
    key = command.get("stdin_from")
    if not key:
        return None
    val = values.get(key)
    if val is None:
        return None
    return str(val)
