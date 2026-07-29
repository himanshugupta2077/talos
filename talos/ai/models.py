"""
Module: talos.ai.models

Purpose:
    Shared dataclasses and enums for the AI layer: capabilities, autonomy
    modes, budget counters, project pin context, immutable suggestions, and
    sealed execution plans.

Dependencies: dataclasses, enum, typing
Data flow:
    Workflow Engine / Policy / Executor import types from here.
Side effects: None (pure types + pure grant map).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


# ------------------------------------------------------------------ #
# Capabilities (primary authorization primitive)                       #
# ------------------------------------------------------------------ #


class Capability(str, Enum):
    """
    Capability tokens granted by autonomy mode. A tool may run only when
    the session's granted set is a superset of ToolPolicy.capabilities.
    """

    READ_ENDPOINTS = "read_endpoints"
    READ_FLOWS = "read_flows"
    READ_FINDINGS = "read_findings"
    READ_INTEL = "read_intel"
    READ_SCHEDULER = "read_scheduler"
    READ_NOTES = "read_notes"
    READ_KB = "read_kb"
    READ_CONTEXT = "read_context"
    MODIFY_NOTES = "modify_notes"
    MODIFY_KB_PROJECT = "modify_kb_project"
    MODIFY_TASK_TREE = "modify_task_tree"
    MODIFY_CONTEXT = "modify_context"
    DRAFT_FINDING = "draft_finding"
    REPLAY_FLOW = "replay_flow"
    SEND_REQUEST = "send_request"
    ENQUEUE_IV = "enqueue_iv"
    ENQUEUE_PASSIVE = "enqueue_passive"
    ENQUEUE_ATTACK = "enqueue_attack"
    ENQUEUE_INTRUDER = "enqueue_intruder"


# All capabilities that AI modes may grant in v1 (never promote/confirm/config).
ALL_AI_CAPABILITIES: frozenset[Capability] = frozenset(Capability)

READ_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.READ_ENDPOINTS,
        Capability.READ_FLOWS,
        Capability.READ_FINDINGS,
        Capability.READ_INTEL,
        Capability.READ_SCHEDULER,
        Capability.READ_NOTES,
        Capability.READ_KB,
        Capability.READ_CONTEXT,
    }
)

_AUTO_LOW_CAPS: frozenset[Capability] = READ_CAPABILITIES | frozenset(
    {
        Capability.MODIFY_NOTES,
        Capability.MODIFY_KB_PROJECT,
        Capability.MODIFY_TASK_TREE,
        Capability.MODIFY_CONTEXT,
        Capability.DRAFT_FINDING,
    }
)

_AUTO_BUDGET_CAPS: frozenset[Capability] = _AUTO_LOW_CAPS | frozenset(
    {Capability.REPLAY_FLOW}
)

_AUTO_AGGRESSIVE_CAPS: frozenset[Capability] = _AUTO_BUDGET_CAPS | frozenset(
    {
        Capability.SEND_REQUEST,
        Capability.ENQUEUE_IV,
        Capability.ENQUEUE_PASSIVE,
        Capability.ENQUEUE_ATTACK,
        Capability.ENQUEUE_INTRUDER,
    }
)


class AutonomyMode(str, Enum):
    """Runtime autonomy modes. Install default is suggest-only."""

    SUGGEST_ONLY = "suggest-only"
    STEP = "step"
    AUTO_LOW = "auto-low"
    AUTO_BUDGET = "auto-budget"
    AUTO_AGGRESSIVE = "auto-aggressive"


DEFAULT_AUTONOMY_MODE = AutonomyMode.SUGGEST_ONLY

GA_MODES: frozenset[AutonomyMode] = frozenset(
    {AutonomyMode.SUGGEST_ONLY, AutonomyMode.STEP}
)

EXPERIMENTAL_MODES: frozenset[AutonomyMode] = frozenset(
    {
        AutonomyMode.AUTO_LOW,
        AutonomyMode.AUTO_BUDGET,
        AutonomyMode.AUTO_AGGRESSIVE,
    }
)


def grants_for_mode(mode: AutonomyMode | str) -> frozenset[Capability]:
    """
    Purpose:
        Map an autonomy mode to the capability set authorized for execution.
    Input:
        mode — AutonomyMode or its string value.
    Output:
        Frozenset of capabilities. suggest-only returns empty (execute hard-off).
    Side effects: None.
    """
    if isinstance(mode, str):
        mode = AutonomyMode(mode)
    if mode == AutonomyMode.SUGGEST_ONLY:
        return frozenset()
    if mode == AutonomyMode.STEP:
        return ALL_AI_CAPABILITIES
    if mode == AutonomyMode.AUTO_LOW:
        return _AUTO_LOW_CAPS
    if mode == AutonomyMode.AUTO_BUDGET:
        return _AUTO_BUDGET_CAPS
    if mode == AutonomyMode.AUTO_AGGRESSIVE:
        return _AUTO_AGGRESSIVE_CAPS
    raise ValueError(f"Unknown autonomy mode: {mode!r}")


def parse_mode(value: str) -> AutonomyMode:
    """
    Purpose: Parse a CLI/config mode string into AutonomyMode.
    Raises: ValueError when the string is not a known mode.
    """
    cleaned = (value or "").strip().lower()
    for mode in AutonomyMode:
        if mode.value == cleaned:
            return mode
    valid = ", ".join(m.value for m in AutonomyMode)
    raise ValueError(f"Unknown mode '{value}'. Valid: {valid}")


# ------------------------------------------------------------------ #
# Budgets                                                              #
# ------------------------------------------------------------------ #


@dataclass
class BudgetLimits:
    """Hard caps for one AI session (defaults from design doc)."""

    max_steps: int = 50
    max_tool_calls: int = 100
    max_http_executed: int = 100
    max_jobs_enqueued: int = 50
    max_intruder_payloads: int = 200
    max_llm_tokens: int = 500_000
    max_wall_clock_s: int = 7200

    def to_dict(self) -> dict[str, int]:
        return {
            "max_steps": self.max_steps,
            "max_tool_calls": self.max_tool_calls,
            "max_http_executed": self.max_http_executed,
            "max_jobs_enqueued": self.max_jobs_enqueued,
            "max_intruder_payloads": self.max_intruder_payloads,
            "max_llm_tokens": self.max_llm_tokens,
            "max_wall_clock_s": self.max_wall_clock_s,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BudgetLimits":
        if not data:
            return cls()
        return cls(
            max_steps=int(data.get("max_steps", 50)),
            max_tool_calls=int(data.get("max_tool_calls", 100)),
            max_http_executed=int(data.get("max_http_executed", 100)),
            max_jobs_enqueued=int(data.get("max_jobs_enqueued", 50)),
            max_intruder_payloads=int(data.get("max_intruder_payloads", 200)),
            max_llm_tokens=int(data.get("max_llm_tokens", 500_000)),
            max_wall_clock_s=int(data.get("max_wall_clock_s", 7200)),
        )


@dataclass
class BudgetUsage:
    """Cumulative usage counters for one AI session."""

    steps: int = 0
    tool_calls: int = 0
    http_executed: int = 0
    jobs_enqueued: int = 0
    intruder_payloads: int = 0
    llm_tokens: int = 0
    wall_clock_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "http_executed": self.http_executed,
            "jobs_enqueued": self.jobs_enqueued,
            "intruder_payloads": self.intruder_payloads,
            "llm_tokens": self.llm_tokens,
            "wall_clock_s": self.wall_clock_s,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BudgetUsage":
        if not data:
            return cls()
        return cls(
            steps=int(data.get("steps", 0)),
            tool_calls=int(data.get("tool_calls", 0)),
            http_executed=int(data.get("http_executed", 0)),
            jobs_enqueued=int(data.get("jobs_enqueued", 0)),
            intruder_payloads=int(data.get("intruder_payloads", 0)),
            llm_tokens=int(data.get("llm_tokens", 0)),
            wall_clock_s=float(data.get("wall_clock_s", 0.0)),
        )

    def reset(self) -> None:
        """Zero all counters in place (operator reset-budget)."""
        self.steps = 0
        self.tool_calls = 0
        self.http_executed = 0
        self.jobs_enqueued = 0
        self.intruder_payloads = 0
        self.llm_tokens = 0
        self.wall_clock_s = 0.0


class BudgetClass(str, Enum):
    """Which budget counter a tool hits (from ToolPolicy)."""

    NONE = "none"
    LLM = "llm"
    HTTP_EXECUTED = "http_executed"
    JOB_ENQUEUED = "job_enqueued"
    INTRUDER_PAYLOAD = "intruder_payload"
    WRITE = "write"


# ------------------------------------------------------------------ #
# Session / pin                                                        #
# ------------------------------------------------------------------ #


class SessionStatus(str, Enum):
    ACTIVE = "active"
    STOPPED = "stopped"
    HALTED_BUDGET = "halted_budget"
    COMPLETED = "completed"


@dataclass(frozen=True)
class ProjectContext:
    """
    Frozen project pin for the lifetime of an AI session.
    Handlers must use db_path / project_id from this context only.
    """

    project_id: str
    db_path: Path
    data_dir: Path
    session_id: str
    started_at: str


@dataclass
class AgentSession:
    """
    In-memory view of an ai_sessions row with derived capability grants.
    """

    session_id: str
    project_id: str
    goal: str
    mode: AutonomyMode
    status: SessionStatus
    pinned_project_id: str
    data_dir: Path
    db_path: Path
    budgets: BudgetLimits
    usage: BudgetUsage
    created_at: str
    updated_at: str
    scope_snapshot_json: Optional[str] = None

    @property
    def granted_capabilities(self) -> frozenset[Capability]:
        return grants_for_mode(self.mode)

    def project_context(self) -> ProjectContext:
        return ProjectContext(
            project_id=self.pinned_project_id,
            db_path=self.db_path,
            data_dir=self.data_dir,
            session_id=self.session_id,
            started_at=self.created_at,
        )


# ------------------------------------------------------------------ #
# Suggestion / plan / observation (in-memory for Phase A)              #
# ------------------------------------------------------------------ #


@dataclass(frozen=True)
class ActionSuggestion:
    """
    Immutable model/heuristic proposal. Never mutate arguments after create.
    Phase A uses in-memory instances; Phase B persists to ai_suggestions.
    """

    suggestion_id: str
    session_id: str
    tool_name: str
    arguments: dict[str, Any]
    reason: Optional[str] = None
    cli_preview: Optional[str] = None
    created_at: str = ""
    display_risk: Optional[str] = None


@dataclass(frozen=True)
class ExecutionPlan:
    """
    Sealed plan produced only by PolicyValidator. Executor verifies
    capability_token is single-use and issued by the validator.
    """

    plan_id: str
    suggestion_id: str
    session_id: str
    tool_name: str
    arguments: dict[str, Any]
    required_capabilities: frozenset[Capability]
    project_id: str
    capability_token: str
    policy_meta: dict[str, Any] = field(default_factory=dict)
    idempotent: bool = False
    created_at: str = ""
    requires_approval: bool = True


@dataclass(frozen=True)
class PolicyReject:
    """Policy validation failure — no ExecutionPlan is minted."""

    code: str
    message: str
    tool_name: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class HandlerResult:
    """Return value from ToolHandler.execute."""

    success: bool
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    citations: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class Observation:
    """What happened after Executor ran a plan (append-only semantics)."""

    observation_id: str
    session_id: str
    suggestion_id: str
    plan_id: str
    tool_name: str
    result_summary: str
    citations: dict[str, Any]
    untrusted: bool = True
    raw_ref: Optional[str] = None
    created_at: str = ""
    success: bool = True
    data: dict[str, Any] = field(default_factory=dict)


def display_risk_for_capabilities(caps: frozenset[Capability]) -> str:
    """
    Purpose:
        Derive optional UX risk label from required capabilities.
        Not used for authorization — display only.
    """
    if caps & {
        Capability.ENQUEUE_ATTACK,
        Capability.ENQUEUE_INTRUDER,
        Capability.ENQUEUE_IV,
        Capability.ENQUEUE_PASSIVE,
    }:
        return "attack"
    if caps & {Capability.SEND_REQUEST, Capability.REPLAY_FLOW}:
        return "http"
    if caps & {
        Capability.MODIFY_NOTES,
        Capability.MODIFY_KB_PROJECT,
        Capability.MODIFY_TASK_TREE,
        Capability.MODIFY_CONTEXT,
        Capability.DRAFT_FINDING,
    }:
        return "write"
    return "read"
