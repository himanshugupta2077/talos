"""
Module: talos.ai.tools.bindings

Purpose:
    Single registration site pairing ToolSpec + ToolPolicy + ToolHandler.
    Audit this file to answer "what can the AI run?"

Dependencies: talos.ai.tools.*, handlers
Data flow:
    default_registry() → register_all_tools(registry)
Side effects: mutates the provided ToolRegistry.
"""

from __future__ import annotations

from talos.ai.models import BudgetClass, Capability
from talos.ai.tools.handler import CallableHandler
from talos.ai.tools.handlers import context as context_handlers
from talos.ai.tools.handlers import engines as engine_handlers
from talos.ai.tools.handlers import inventory as inventory_handlers
from talos.ai.tools.handlers import notes_kb as notes_kb_handlers
from talos.ai.tools.handlers import replay_send as replay_send_handlers
from talos.ai.tools.policy_def import ToolPolicy
from talos.ai.tools.registry import ToolRegistry
from talos.ai.tools import schemas as S
from talos.ai.tools.spec import ToolSpec


def _read_policy(*caps: Capability) -> ToolPolicy:
    return ToolPolicy(
        capabilities=frozenset(caps),
        requires_approval=True,
        idempotent=True,
        budget_class=BudgetClass.NONE,
    )


def _context_write_policy() -> ToolPolicy:
    return ToolPolicy(
        capabilities=frozenset({Capability.MODIFY_CONTEXT}),
        requires_approval=True,
        idempotent=True,
        budget_class=BudgetClass.WRITE,
    )


def _write_policy(*caps: Capability) -> ToolPolicy:
    return ToolPolicy(
        capabilities=frozenset(caps),
        requires_approval=True,
        idempotent=True,
        budget_class=BudgetClass.WRITE,
    )


def _http_policy(*caps: Capability, idempotent: bool = False) -> ToolPolicy:
    return ToolPolicy(
        capabilities=frozenset(caps),
        requires_approval=True,
        idempotent=idempotent,
        budget_class=BudgetClass.HTTP_EXECUTED,
    )


def _enqueue_policy(*caps: Capability) -> ToolPolicy:
    return ToolPolicy(
        capabilities=frozenset(caps),
        requires_approval=True,
        idempotent=True,
        budget_class=BudgetClass.JOB_ENQUEUED,
    )


def _intruder_policy() -> ToolPolicy:
    return ToolPolicy(
        capabilities=frozenset({Capability.ENQUEUE_INTRUDER}),
        requires_approval=True,
        idempotent=False,
        budget_class=BudgetClass.INTRUDER_PAYLOAD,
    )


def register_all_tools(registry: ToolRegistry) -> None:
    """
    Purpose:
        Register Phase A–D tools (READ + notes/PTT + HTTP send/replay +
        engine enqueue).
    Input:
        registry — empty or partially filled ToolRegistry.
    Side effects:
        registry.register for each tool; raises on duplicate names.
    """
    # ---- Endpoints ----
    registry.register(
        ToolSpec(
            name="endpoint.list",
            version=1,
            description="List endpoints in the pinned project with optional filters.",
            input_schema=S.SCHEMA_ENDPOINT_LIST,
            tags=("inventory", "read"),
        ),
        _read_policy(Capability.READ_ENDPOINTS),
        CallableHandler(inventory_handlers.handle_endpoint_list),
    )
    registry.register(
        ToolSpec(
            name="endpoint.show",
            version=1,
            description="Show one endpoint by id with effective policy fields.",
            input_schema=S.SCHEMA_ENDPOINT_SHOW,
            tags=("inventory", "read"),
        ),
        _read_policy(Capability.READ_ENDPOINTS),
        CallableHandler(inventory_handlers.handle_endpoint_show),
    )

    # ---- Flows ----
    registry.register(
        ToolSpec(
            name="flow.show",
            version=1,
            description="Show flow metadata (optional truncated body excerpts).",
            input_schema=S.SCHEMA_FLOW_SHOW,
            tags=("inventory", "read"),
        ),
        _read_policy(Capability.READ_FLOWS),
        CallableHandler(inventory_handlers.handle_flow_show),
    )
    registry.register(
        ToolSpec(
            name="flow.diff",
            version=1,
            description="Compare two flows (status / body length / JSON keys).",
            input_schema=S.SCHEMA_FLOW_DIFF,
            tags=("inventory", "read"),
        ),
        _read_policy(Capability.READ_FLOWS),
        CallableHandler(inventory_handlers.handle_flow_diff),
    )

    # ---- IV / param intel ----
    registry.register(
        ToolSpec(
            name="param.intelligence",
            version=1,
            description="Parameter intelligence profile (capabilities + candidates).",
            input_schema=S.SCHEMA_PARAM_INTELLIGENCE,
            tags=("intel", "read"),
        ),
        _read_policy(Capability.READ_INTEL),
        CallableHandler(inventory_handlers.handle_param_intelligence),
    )
    registry.register(
        ToolSpec(
            name="iv.candidates",
            version=1,
            description="List IV attack candidates from stored param profiles.",
            input_schema=S.SCHEMA_IV_CANDIDATES,
            tags=("intel", "read"),
        ),
        _read_policy(Capability.READ_INTEL),
        CallableHandler(inventory_handlers.handle_iv_candidates),
    )

    # ---- Findings ----
    registry.register(
        ToolSpec(
            name="finding.list",
            version=1,
            description="List findings for the pinned project.",
            input_schema=S.SCHEMA_FINDING_LIST,
            tags=("findings", "read"),
        ),
        _read_policy(Capability.READ_FINDINGS),
        CallableHandler(inventory_handlers.handle_finding_list),
    )
    registry.register(
        ToolSpec(
            name="finding.show",
            version=1,
            description="Show one finding and its evidence rows.",
            input_schema=S.SCHEMA_FINDING_SHOW,
            tags=("findings", "read"),
        ),
        _read_policy(Capability.READ_FINDINGS),
        CallableHandler(inventory_handlers.handle_finding_show),
    )

    # ---- Passive / error intel / access ----
    registry.register(
        ToolSpec(
            name="passive.detections.list",
            version=1,
            description="List passive source-intelligence detections.",
            input_schema=S.SCHEMA_PASSIVE_LIST,
            tags=("intel", "read"),
        ),
        _read_policy(Capability.READ_INTEL),
        CallableHandler(inventory_handlers.handle_passive_detections_list),
    )
    registry.register(
        ToolSpec(
            name="error_intel.list",
            version=1,
            description="List Error Intelligence clusters.",
            input_schema=S.SCHEMA_ERROR_INTEL_LIST,
            tags=("intel", "read"),
        ),
        _read_policy(Capability.READ_INTEL),
        CallableHandler(inventory_handlers.handle_error_intel_list),
    )
    registry.register(
        ToolSpec(
            name="access.coverage",
            version=1,
            description="Access matrix coverage (expected vs observed).",
            input_schema=S.SCHEMA_ACCESS_COVERAGE,
            tags=("intel", "read", "context"),
        ),
        _read_policy(Capability.READ_INTEL),
        CallableHandler(inventory_handlers.handle_access_coverage),
    )

    # ---- Scheduler ----
    registry.register(
        ToolSpec(
            name="scheduler.jobs.list",
            version=1,
            description="List scheduler jobs (poll engine progress).",
            input_schema=S.SCHEMA_SCHEDULER_JOBS_LIST,
            tags=("scheduler", "read"),
        ),
        _read_policy(Capability.READ_SCHEDULER),
        CallableHandler(inventory_handlers.handle_scheduler_jobs_list),
    )
    registry.register(
        ToolSpec(
            name="scheduler.jobs.show",
            version=1,
            description="Show one scheduler job by id or unique prefix.",
            input_schema=S.SCHEMA_SCHEDULER_JOBS_SHOW,
            tags=("scheduler", "read"),
        ),
        _read_policy(Capability.READ_SCHEDULER),
        CallableHandler(inventory_handlers.handle_scheduler_jobs_show),
    )

    # ---- Intruder suggest (deterministic offline) ----
    registry.register(
        ToolSpec(
            name="intruder.suggest",
            version=1,
            description="Deterministic offline Intruder configuration suggestions.",
            input_schema=S.SCHEMA_INTRUDER_SUGGEST,
            tags=("intel", "read", "intruder"),
        ),
        _read_policy(Capability.READ_INTEL),
        CallableHandler(inventory_handlers.handle_intruder_suggest),
    )

    # ---- Role / module context ----
    registry.register(
        ToolSpec(
            name="role.list",
            version=1,
            description="List project roles.",
            input_schema=S.SCHEMA_ROLE_LIST,
            tags=("context", "read"),
        ),
        _read_policy(Capability.READ_CONTEXT),
        CallableHandler(context_handlers.handle_role_list),
    )
    registry.register(
        ToolSpec(
            name="role.show_active",
            version=1,
            description="Show the currently active role name.",
            input_schema=S.SCHEMA_ROLE_SHOW_ACTIVE,
            tags=("context", "read"),
        ),
        _read_policy(Capability.READ_CONTEXT),
        CallableHandler(context_handlers.handle_role_show_active),
    )
    registry.register(
        ToolSpec(
            name="module.list",
            version=1,
            description="List project modules.",
            input_schema=S.SCHEMA_MODULE_LIST,
            tags=("context", "read"),
        ),
        _read_policy(Capability.READ_CONTEXT),
        CallableHandler(context_handlers.handle_module_list),
    )
    registry.register(
        ToolSpec(
            name="module.show_active",
            version=1,
            description="Show the currently active module name.",
            input_schema=S.SCHEMA_MODULE_SHOW_ACTIVE,
            tags=("context", "read"),
        ),
        _read_policy(Capability.READ_CONTEXT),
        CallableHandler(context_handlers.handle_module_show_active),
    )
    registry.register(
        ToolSpec(
            name="role.set_active",
            version=1,
            description="Set the active role to an existing name (no create).",
            input_schema=S.SCHEMA_ROLE_SET_ACTIVE,
            tags=("context", "write"),
        ),
        _context_write_policy(),
        CallableHandler(context_handlers.handle_role_set_active),
    )
    registry.register(
        ToolSpec(
            name="module.set_active",
            version=1,
            description="Set the active module to an existing name (no create).",
            input_schema=S.SCHEMA_MODULE_SET_ACTIVE,
            tags=("context", "write"),
        ),
        _context_write_policy(),
        CallableHandler(context_handlers.handle_module_set_active),
    )

    # ---- App notes (Phase B) ----
    registry.register(
        ToolSpec(
            name="notes.app.get",
            version=1,
            description="Get structured AI app notes for the pinned project.",
            input_schema=S.SCHEMA_NOTES_APP_GET,
            tags=("notes", "read"),
        ),
        _read_policy(Capability.READ_NOTES),
        CallableHandler(notes_kb_handlers.handle_notes_app_get),
    )
    registry.register(
        ToolSpec(
            name="notes.app.patch",
            version=1,
            description="Patch AI app notes via allowlisted JSON-patch paths.",
            input_schema=S.SCHEMA_NOTES_APP_PATCH,
            tags=("notes", "write"),
        ),
        _write_policy(Capability.MODIFY_NOTES),
        CallableHandler(notes_kb_handlers.handle_notes_app_patch),
    )

    # ---- PTT (Phase B) ----
    registry.register(
        ToolSpec(
            name="task_tree.list",
            version=1,
            description="List Pentesting Task Tree nodes for this AI session.",
            input_schema=S.SCHEMA_TASK_TREE_LIST,
            tags=("ptt", "read"),
        ),
        _read_policy(Capability.READ_NOTES),
        CallableHandler(notes_kb_handlers.handle_task_tree_list),
    )
    registry.register(
        ToolSpec(
            name="task_tree.upsert",
            version=1,
            description="Create or update a PTT node for this AI session.",
            input_schema=S.SCHEMA_TASK_TREE_UPSERT,
            tags=("ptt", "write"),
        ),
        _write_policy(Capability.MODIFY_TASK_TREE),
        CallableHandler(notes_kb_handlers.handle_task_tree_upsert),
    )

    # ---- Phase D: send / replay ----
    registry.register(
        ToolSpec(
            name="send.once",
            version=1,
            description=(
                "Send a forked request once from a parent flow (source=ai_send). "
                "Max 20 edits; live scope + annotation matrix enforced."
            ),
            input_schema=S.SCHEMA_SEND_ONCE,
            tags=("http", "send"),
        ),
        _http_policy(Capability.SEND_REQUEST, idempotent=False),
        CallableHandler(replay_send_handlers.handle_send_once),
    )
    registry.register(
        ToolSpec(
            name="replay.flow",
            version=1,
            description=(
                "Enqueue a replay_flow scheduler job for an existing flow "
                "(enqueue only; poll via scheduler.jobs.*)."
            ),
            input_schema=S.SCHEMA_REPLAY_FLOW,
            tags=("http", "replay", "enqueue"),
        ),
        _enqueue_policy(Capability.REPLAY_FLOW),
        CallableHandler(replay_send_handlers.handle_replay_flow),
    )

    # ---- Phase D: engines ----
    registry.register(
        ToolSpec(
            name="iv.run",
            version=1,
            description=(
                "Enqueue Input Validation jobs (project/host/endpoint/parameter). "
                "Enqueue only — poll scheduler.jobs.*"
            ),
            input_schema=S.SCHEMA_IV_RUN,
            tags=("engine", "iv", "enqueue"),
        ),
        _enqueue_policy(Capability.ENQUEUE_IV),
        CallableHandler(engine_handlers.handle_iv_run),
    )
    registry.register(
        ToolSpec(
            name="iv.synthesize",
            version=1,
            description=(
                "Synthesize parameter intelligence from existing IV probes "
                "(local DB only; no HTTP)."
            ),
            input_schema=S.SCHEMA_IV_SYNTHESIZE,
            tags=("intel", "iv", "read"),
        ),
        _read_policy(Capability.READ_INTEL),
        CallableHandler(engine_handlers.handle_iv_synthesize),
    )
    registry.register(
        ToolSpec(
            name="passive.rescan",
            version=1,
            description=(
                "Re-run passive detectors on stored response bodies "
                "(flow_id | document_id | all)."
            ),
            input_schema=S.SCHEMA_PASSIVE_RESCAN,
            tags=("engine", "passive", "enqueue"),
        ),
        _enqueue_policy(Capability.ENQUEUE_PASSIVE),
        CallableHandler(engine_handlers.handle_passive_rescan),
    )
    registry.register(
        ToolSpec(
            name="attack.unauth.run",
            version=1,
            description=(
                "Enqueue unauth_attack jobs for a flow/endpoint (or limited scan). "
                "Enqueue only."
            ),
            input_schema=S.SCHEMA_ATTACK_UNAUTH_RUN,
            tags=("engine", "unauth", "enqueue"),
        ),
        _enqueue_policy(Capability.ENQUEUE_ATTACK),
        CallableHandler(engine_handlers.handle_attack_unauth_run),
    )
    registry.register(
        ToolSpec(
            name="attack.bac.run",
            version=1,
            description=(
                "Enqueue BAC jobs for a bac_module (session_swap, method_fuzz, …). "
                "Enqueue only; requires attacker role."
            ),
            input_schema=S.SCHEMA_ATTACK_BAC_RUN,
            tags=("engine", "bac", "enqueue"),
        ),
        _enqueue_policy(Capability.ENQUEUE_ATTACK),
        CallableHandler(engine_handlers.handle_attack_bac_run),
    )
    registry.register(
        ToolSpec(
            name="intruder.session.run",
            version=1,
            description=(
                "Enqueue one segment for a pre-created Intruder session "
                "(session_id required; no session create)."
            ),
            input_schema=S.SCHEMA_INTRUDER_SESSION_RUN,
            tags=("engine", "intruder", "enqueue"),
        ),
        _intruder_policy(),
        CallableHandler(engine_handlers.handle_intruder_session_run),
    )
