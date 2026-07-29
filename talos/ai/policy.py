"""
Module: talos.ai.policy

Purpose:
    PolicyValidator — sole constructor of sealed ExecutionPlans.
    Validation order: allowlist → schema → pin → capabilities → mode
    approval → live scope → annotations → budgets → sealed plan.

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
from pathlib import Path
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
from talos.ai.tools import scope_policy as sp
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

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        *,
        manager: Any = None,
    ) -> None:
        self._registry = registry
        self._manager = manager

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
        human_approved: bool = False,
    ) -> Union[ExecutionPlan, PolicyReject]:
        """
        Purpose:
            Run the full validation ladder and either reject or seal a plan.
        Input:
            suggestion — immutable proposal.
            session    — active (or authorized) agent session with grants.
            live       — when True, re-check live scope/annotations (HTTP tools).
            auto_reads — when True and mode is step, mark READ-only tools
                         as not requiring human approval (still sealed).
            human_approved — True on operator approve path; allows dangerous
                         targets and sets ai_force_dangerous in policy_meta.
        Output:
            ExecutionPlan or PolicyReject.
        Side effects:
            Issues a capability token into the process token store.
        """
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

        policy_meta: dict[str, Any] = {
            "mode": session.mode.value,
            "display_risk": display_risk_for_capabilities(policy.capabilities),
            "budget_class": policy.budget_class.value,
            "auto_reads": auto_reads,
            "human_approved": bool(human_approved),
            "ai_force_dangerous": False,
            "annotations": [],
        }

        # ---- Live scope + annotation matrix (Phase D) ----
        if live:
            scope_ann = self._check_scope_and_annotations(
                tool_name,
                normalized,
                session,
                human_approved=human_approved,
            )
            if isinstance(scope_ann, PolicyReject):
                return scope_ann
            policy_meta.update(scope_ann)

        annotations = set(policy_meta.get("annotations") or [])
        is_dangerous = "dangerous" in annotations

        requires_approval = self._requires_approval(
            session,
            policy.capabilities,
            policy.requires_approval,
            auto_reads=auto_reads,
            force_human_for_dangerous=is_dangerous and not human_approved,
        )

        plan_id = str(uuid.uuid4())
        token = issue_capability_token(plan_id)
        return ExecutionPlan(
            plan_id=plan_id,
            suggestion_id=suggestion.suggestion_id,
            session_id=session.session_id,
            tool_name=tool_name,
            arguments=normalized,
            required_capabilities=policy.capabilities,
            project_id=session.pinned_project_id,
            capability_token=token,
            policy_meta=policy_meta,
            idempotent=policy.idempotent,
            created_at=_now_iso(),
            requires_approval=requires_approval,
        )

    def _check_scope_and_annotations(
        self,
        tool_name: str,
        args: dict[str, Any],
        session: AgentSession,
        *,
        human_approved: bool,
    ) -> Union[dict[str, Any], PolicyReject]:
        """
        Resolve target flow/endpoint, apply annotation matrix and live scope.
        Returns policy_meta fragment or PolicyReject.
        """
        needs_scope = tool_name in sp.HTTP_SCOPE_TOOLS
        needs_ann = tool_name in sp.ANNOTATION_TOOLS
        if not needs_scope and not needs_ann:
            return {}

        meta: dict[str, Any] = {
            "annotations": [],
            "ai_force_dangerous": False,
        }

        flow: Optional[dict[str, Any]] = None
        endpoint_id: Optional[str] = None
        effective_url: Optional[str] = None

        if tool_name == "send.once":
            parent_id = str(args.get("parent_flow_id") or "").strip()
            flow = sp.resolve_flow_target(
                session.db_path, parent_flow_id=parent_id
            )
            if flow is None:
                return PolicyReject(
                    code="flow_not_found",
                    message=f"Parent flow not found: {parent_id}",
                    tool_name=tool_name,
                )
            endpoint_id = flow.get("endpoint_id")
            base_url = str(flow.get("url") or "")
            edits = args.get("edits") or []
            effective_url = sp.apply_send_edits_to_url(
                base_url, edits if isinstance(edits, list) else []
            )
            meta["parent_flow_id"] = parent_id
            meta["effective_url"] = effective_url
        elif tool_name == "replay.flow":
            flow_id = str(args.get("flow_id") or "").strip()
            flow = sp.resolve_flow_target(session.db_path, flow_id=flow_id)
            if flow is None:
                return PolicyReject(
                    code="flow_not_found",
                    message=f"Flow not found: {flow_id}",
                    tool_name=tool_name,
                )
            endpoint_id = flow.get("endpoint_id")
            effective_url = str(flow.get("url") or "")
            meta["flow_id"] = flow_id
            meta["effective_url"] = effective_url
        elif tool_name in ("iv.run", "attack.unauth.run", "attack.bac.run"):
            # Prefer explicit endpoint; fall back to flow when provided.
            endpoint_id = (
                str(args["endpoint_id"]).strip()
                if args.get("endpoint_id")
                else None
            )
            flow_id = str(args["flow_id"]).strip() if args.get("flow_id") else None
            if flow_id:
                flow = sp.resolve_flow_target(session.db_path, flow_id=flow_id)
                if flow is None:
                    return PolicyReject(
                        code="flow_not_found",
                        message=f"Flow not found: {flow_id}",
                        tool_name=tool_name,
                    )
                endpoint_id = endpoint_id or flow.get("endpoint_id")
                effective_url = str(flow.get("url") or "")
            if endpoint_id and not effective_url:
                ep = replay_db_get_endpoint(session.db_path, endpoint_id)
                if ep is not None:
                    # Best-effort URL for scope (host+path).
                    host = ep.get("host") or ""
                    path = ep.get("normalized_path") or ep.get("path") or ""
                    if host.startswith("http"):
                        effective_url = f"{host.rstrip('/')}{path}"
                    elif host:
                        effective_url = f"https://{host}{path}"
        elif tool_name == "intruder.session.run":
            session_id = str(args.get("session_id") or "").strip()
            try:
                from talos.intruder import db as intruder_db

                isess = intruder_db.get_session(session.db_path, session_id)
            except Exception:  # noqa: BLE001
                isess = None
            if isess is None:
                return PolicyReject(
                    code="intruder_session_not_found",
                    message=f"Intruder session not found: {session_id}",
                    tool_name=tool_name,
                )
            endpoint_id = isess.get("endpoint_id")
            base_flow = isess.get("base_flow_id")
            if base_flow:
                flow = sp.resolve_flow_target(
                    session.db_path, flow_id=str(base_flow)
                )
                if flow is not None:
                    endpoint_id = endpoint_id or flow.get("endpoint_id")
                    effective_url = str(flow.get("url") or "")
        elif tool_name == "passive.rescan":
            flow_id = str(args["flow_id"]).strip() if args.get("flow_id") else None
            if flow_id:
                flow = sp.resolve_flow_target(session.db_path, flow_id=flow_id)
                if flow is not None:
                    endpoint_id = flow.get("endpoint_id")
                    effective_url = str(flow.get("url") or "")

        # Annotation matrix
        tags = sp.annotations_for_endpoint(session.db_path, endpoint_id)
        meta["annotations"] = sorted(tags)
        meta["endpoint_id"] = endpoint_id

        if "logout" in tags:
            return PolicyReject(
                code="annotation_logout",
                message=(
                    "Endpoint is annotated logout — AI send/replay/enqueue "
                    "is always rejected."
                ),
                tool_name=tool_name,
                details={"endpoint_id": endpoint_id, "annotations": sorted(tags)},
            )

        if "dangerous" in tags:
            if human_approved:
                meta["ai_force_dangerous"] = True
            else:
                # Do not hard-reject: force human approval even in auto-*.
                meta["ai_force_dangerous"] = False
                meta["dangerous_requires_approval"] = True

        # Live (+ snapshot) scope for HTTP-producing tools — fail closed.
        if needs_scope:
            url_text = (effective_url or "").strip()
            if not url_text:
                return PolicyReject(
                    code="scope_denied",
                    message=(
                        "HTTP tool has no resolvable effective URL; "
                        "refusing (fail closed)."
                    ),
                    tool_name=tool_name,
                    details={
                        "effective_url": effective_url,
                        "decision": "missing_url",
                    },
                )
            live_in, live_out = self._load_live_scope(session)
            snap = sp.parse_scope_snapshot(session.scope_snapshot_json)
            allowed, code, scope_meta = sp.check_url_allowed(
                url_text,
                live_in_scope=live_in,
                live_outscope=live_out,
                scope_snapshot=snap,
            )
            meta["scope"] = scope_meta
            meta["effective_url"] = url_text
            if not allowed:
                return PolicyReject(
                    code=code or "scope_denied",
                    message=(
                        f"Effective URL not in project scope: {url_text}"
                    ),
                    tool_name=tool_name,
                    details=scope_meta,
                )

        return meta

    def _load_live_scope(
        self, session: AgentSession
    ) -> tuple[list[str], list[str]]:
        if self._manager is not None:
            try:
                return sp.load_live_scope(
                    self._manager, session.pinned_project_id, session.db_path
                )
            except Exception:  # noqa: BLE001 — fail closed below
                pass
        # Fallback: empty in-scope deny-all when manager unavailable.
        from talos.projects.outscope import load_prefix_set

        return [], list(load_prefix_set(session.db_path))

    def _requires_approval(
        self,
        session: AgentSession,
        required: frozenset[Capability],
        tool_requires: bool,
        *,
        auto_reads: bool,
        force_human_for_dangerous: bool = False,
    ) -> bool:
        """
        Mode approval rules:
          step: always require approval unless auto_reads and caps ⊆ READ_*
          auto-*: auto when required ⊆ granted
          dangerous targets: always require human approval (even auto-*)
        """
        if force_human_for_dangerous:
            return True

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


def replay_db_get_endpoint(db_path: Path, endpoint_id: str) -> Optional[dict]:
    """Thin wrapper so policy tests can monkeypatch endpoint lookup."""
    from talos.replay import db as replay_db

    return replay_db.get_endpoint_by_id(db_path, endpoint_id)
