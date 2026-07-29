"""
Module: talos.ai.policy

Purpose:
    PolicyValidator — sole constructor of sealed ExecutionPlans.
    Validation order: allowlist → schema → pin → capabilities → mode
    approval → budgets (HTTP/annotation checks reserved for later phases).

Dependencies: hashlib, secrets, uuid, talos.ai.models, tools, workflow.budgets
Data flow:
    ActionSuggestion + AgentSession → validate → ExecutionPlan | PolicyReject
Side effects:
    Registers capability tokens in-process for single-use Executor checks.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Union

from talos.ai.models import (
    ActionSuggestion,
    AgentSession,
    AutonomyMode,
    Capability,
    ExecutionPlan,
    PolicyReject,
    READ_CAPABILITIES,
    SessionStatus,
    display_risk_for_capabilities,
)
from talos.ai.tools.registry import ToolRegistry, default_registry
from talos.ai.tools.schemas import validate_input
from talos.ai.workflow.budgets import first_exceeded, would_exceed_after


# Process-local single-use capability tokens: plan_id → sha256 hex of token.
_ISSUED_TOKENS: dict[str, str] = {}
_CONSUMED_TOKENS: set[str] = set()


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_capability_token(plan_id: str) -> str:
    """
    Purpose: Create a single-use capability token bound to plan_id.
    Output: raw token (only Executor should receive this via the plan object).
    """
    token = secrets.token_urlsafe(32)
    _ISSUED_TOKENS[plan_id] = _hash_token(token)
    return token


def verify_and_consume_token(plan_id: str, token: str) -> bool:
    """
    Purpose:
        Verify token matches the issued hash and mark it consumed (single-use).
    Output:
        True if valid and not previously consumed.
    """
    if plan_id in _CONSUMED_TOKENS:
        return False
    expected = _ISSUED_TOKENS.get(plan_id)
    if expected is None:
        return False
    if _hash_token(token) != expected:
        return False
    _CONSUMED_TOKENS.add(plan_id)
    return True


def reset_token_store_for_tests() -> None:
    """Clear in-process token maps (unit tests only)."""
    _ISSUED_TOKENS.clear()
    _CONSUMED_TOKENS.clear()


class PolicyValidator:
    """
    Validates an immutable ActionSuggestion against session grants and
    tool policy; mints a sealed ExecutionPlan on success.
    """

    def __init__(self, registry: Optional[ToolRegistry] = None) -> None:
        self._registry = registry

    @property
    def registry(self) -> ToolRegistry:
        return self._registry if self._registry is not None else default_registry()

    def validate(
        self,
        suggestion: ActionSuggestion,
        session: AgentSession,
        *,
        live: bool = True,
        auto_reads: bool = False,
    ) -> Union[ExecutionPlan, PolicyReject]:
        """
        Purpose:
            Run the full validation ladder and either reject or seal a plan.
        Input:
            suggestion — immutable proposal.
            session    — active (or authorized) agent session with grants.
            live       — reserved for live scope/annotation re-check (HTTP tools).
            auto_reads — when True and mode is step, mark READ-only tools
                         as not requiring human approval (still sealed).
        Output:
            ExecutionPlan or PolicyReject.
        Side effects:
            Issues a capability token into the process token store.
        """
        del live  # HTTP live scope lands in Phase D.

        if session.status != SessionStatus.ACTIVE:
            return PolicyReject(
                code="session_not_active",
                message=f"Session status is {session.status.value}; cannot validate.",
                tool_name=suggestion.tool_name,
            )

        if session.mode == AutonomyMode.SUGGEST_ONLY:
            return PolicyReject(
                code="suggest_only",
                message=(
                    "Mode is suggest-only: execution is disabled. "
                    "Run 'talos ai mode set step' to allow approved execution."
                ),
                tool_name=suggestion.tool_name,
            )

        tool_name = (suggestion.tool_name or "").strip()
        if not tool_name or not self.registry.has_tool(tool_name):
            return PolicyReject(
                code="unknown_tool",
                message=f"Tool not in allowlist: {tool_name!r}",
                tool_name=tool_name or None,
            )

        try:
            spec = self.registry.get_spec(tool_name)
            policy = self.registry.get_policy(tool_name)
        except KeyError:
            return PolicyReject(
                code="unknown_tool",
                message=f"Tool not in allowlist: {tool_name!r}",
                tool_name=tool_name,
            )

        ok, err, normalized = validate_input(
            dict(suggestion.arguments or {}),
            spec.input_schema,
        )
        if not ok:
            return PolicyReject(
                code="schema_invalid",
                message=err or "arguments failed schema validation",
                tool_name=tool_name,
                details={"arguments": suggestion.arguments},
            )

        # Pin: arguments must not attempt project switch (already in schema).
        # Session pin is authoritative.
        if session.pinned_project_id != session.project_id:
            return PolicyReject(
                code="pin_mismatch",
                message="Session pin does not match project_id.",
                tool_name=tool_name,
            )

        missing = policy.capabilities - session.granted_capabilities
        if missing:
            return PolicyReject(
                code="capability_denied",
                message=(
                    "Session lacks required capabilities: "
                    + ", ".join(sorted(c.value for c in missing))
                ),
                tool_name=tool_name,
                details={
                    "required": sorted(c.value for c in policy.capabilities),
                    "granted": sorted(c.value for c in session.granted_capabilities),
                },
            )

        exceeded = first_exceeded(
            session.budgets, session.usage, started_at_iso=session.created_at
        )
        if exceeded:
            return PolicyReject(
                code="budget_exceeded",
                message=f"Budget already exceeded: {exceeded}",
                tool_name=tool_name,
            )

        would = would_exceed_after(
            session.budgets,
            session.usage,
            policy.budget_class,
            started_at_iso=session.created_at,
        )
        if would:
            return PolicyReject(
                code="budget_would_exceed",
                message=f"Executing this tool would exceed budget: {would}",
                tool_name=tool_name,
            )

        requires_approval = self._requires_approval(
            session, policy.capabilities, policy.requires_approval, auto_reads=auto_reads
        )

        plan_id = str(uuid.uuid4())
        token = issue_capability_token(plan_id)
        plan = ExecutionPlan(
            plan_id=plan_id,
            suggestion_id=suggestion.suggestion_id,
            session_id=session.session_id,
            tool_name=tool_name,
            arguments=normalized,
            required_capabilities=policy.capabilities,
            project_id=session.pinned_project_id,
            capability_token=token,
            policy_meta={
                "mode": session.mode.value,
                "display_risk": display_risk_for_capabilities(policy.capabilities),
                "budget_class": policy.budget_class.value,
                "auto_reads": auto_reads,
            },
            idempotent=policy.idempotent,
            created_at=_now_iso(),
            requires_approval=requires_approval,
        )
        return plan

    def _requires_approval(
        self,
        session: AgentSession,
        required: frozenset[Capability],
        tool_requires: bool,
        *,
        auto_reads: bool,
    ) -> bool:
        """
        Mode approval rules:
          step: always require approval unless auto_reads and caps ⊆ READ_*
          auto-*: auto when required ⊆ granted AND tool allows (tool_requires
                  is still True for most tools — auto mode means auto-authorize
                  after validate for eligible caps).
        """
        if session.mode == AutonomyMode.STEP:
            if auto_reads and required and required <= READ_CAPABILITIES:
                return False
            return True

        if session.mode in (
            AutonomyMode.AUTO_LOW,
            AutonomyMode.AUTO_BUDGET,
            AutonomyMode.AUTO_AGGRESSIVE,
        ):
            # Auto-authorize when all required caps are in the mode grant set.
            if required <= session.granted_capabilities:
                return False
            return True

        return tool_requires
