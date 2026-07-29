"""
Module: talos.ai.planner.heuristic

Purpose:
    Offline provider=none planner. Emits READ/recon ActionSuggestions from
    inventory signals, notes pack, PTT frontier, and goal keywords.
    Never writes session tables.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from talos.ai.models import ActionSuggestion, display_risk_for_capabilities, Capability
from talos.ai.planner.base import PlanRequest
from talos.ai.tools.registry import ToolRegistry, default_registry


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class HeuristicPlanner:
    """
    Deterministic recon planner for labs / offline use.
    Proposes inventory and notes tools only (Phase B surface).
    """

    def __init__(self, registry: Optional[ToolRegistry] = None) -> None:
        self._registry = registry

    @property
    def registry(self) -> ToolRegistry:
        return self._registry if self._registry is not None else default_registry()

    def plan(self, request: PlanRequest) -> list[ActionSuggestion]:
        max_n = max(1, min(int(request.max_suggestions or 5), 10))
        available = {s.name for s in request.tool_descriptors}
        if not available:
            available = set(self.registry.names())

        suggestions: list[ActionSuggestion] = []
        seen_tools: set[str] = set()
        signals = request.inventory_signals or {}
        goal = (request.goal or "").lower()
        notes = request.notes_pack or {}
        frontier = request.ptt_frontier or []
        recent_tools = {
            (o.get("tool") or o.get("tool_name") or "")
            for o in (request.recent_observations or [])
        }

        def _add(
            tool_name: str,
            arguments: dict[str, Any],
            reason: str,
            *,
            cli_preview: Optional[str] = None,
        ) -> None:
            if len(suggestions) >= max_n:
                return
            if tool_name not in available:
                return
            # Prefer diversity: skip if same tool already proposed this turn
            # unless arguments differ meaningfully and we still have room.
            key = tool_name
            if key in seen_tools and tool_name in {
                "endpoint.list",
                "notes.app.get",
                "task_tree.list",
            }:
                return
            seen_tools.add(key)
            display_risk = "read"
            try:
                policy = self.registry.get_policy(tool_name)
                display_risk = display_risk_for_capabilities(policy.capabilities)
            except KeyError:
                pass
            preview = cli_preview or f"# {tool_name} {arguments!r}"
            suggestions.append(
                ActionSuggestion(
                    suggestion_id=str(uuid.uuid4()),
                    session_id=request.session_id,
                    tool_name=tool_name,
                    arguments=dict(arguments),
                    reason=reason,
                    cli_preview=preview,
                    created_at=_now_iso(),
                    display_risk=display_risk,
                )
            )

        # 1) Always ground in inventory early if not recently observed.
        endpoint_count = int(signals.get("endpoint_count") or 0)
        if "endpoint.list" not in recent_tools or endpoint_count == 0:
            _add(
                "endpoint.list",
                {"limit": 50, "qualified_only": False},
                "Map captured endpoints for the engagement goal.",
                cli_preview="talos endpoint list",
            )

        # 2) Role/module context for multi-user testing setup.
        if "role" in goal or "bac" in goal or "access" in goal or "auth" in goal:
            _add(
                "role.list",
                {},
                "List roles to understand multi-user access surface.",
                cli_preview="talos role list",
            )
            _add(
                "role.show_active",
                {},
                "Show active role before access coverage checks.",
                cli_preview="talos role show",
            )

        # 3) Access coverage when endpoints exist.
        if endpoint_count > 0 or "coverage" in goal or "access" in goal:
            _add(
                "access.coverage",
                {},
                "Summarize expected vs observed access matrix coverage.",
                cli_preview="talos access coverage",
            )

        # 4) IV candidates when intel signals or goal mentions injection.
        iv_count = int(signals.get("iv_candidate_count") or 0)
        if (
            iv_count > 0
            or any(k in goal for k in ("iv", "xss", "sqli", "inject", "input"))
        ):
            _add(
                "iv.candidates",
                {"limit": 25, "min_score": 0},
                "List input-validation attack candidates from param profiles.",
                cli_preview="talos iv candidates",
            )

        # 5) Passive detections.
        passive_count = int(signals.get("passive_detection_count") or 0)
        if passive_count > 0 or "passive" in goal or "secret" in goal:
            _add(
                "passive.detections.list",
                {"limit": 50},
                "Review passive source-intelligence detections.",
                cli_preview="talos passive detections list",
            )

        # 6) Findings list for triage context.
        finding_count = int(signals.get("finding_count") or 0)
        if finding_count > 0 or "finding" in goal or "triage" in goal:
            _add(
                "finding.list",
                {"limit": 50},
                "List findings for triage context.",
                cli_preview="talos finding list",
            )

        # 7) Error intel clusters.
        if int(signals.get("error_cluster_count") or 0) > 0 or "error" in goal:
            _add(
                "error_intel.list",
                {"limit": 50},
                "List Error Intelligence clusters for stack/tech hints.",
                cli_preview="talos error-intel list",
            )

        # 8) Notes — always useful for memory continuity.
        if not notes.get("excluded"):
            _add(
                "notes.app.get",
                {},
                "Load structured app notes for engagement memory.",
                cli_preview="talos ai notes show",
            )
        else:
            _add(
                "notes.app.get",
                {},
                "Notes marked tainted/excluded from pack — operator should review.",
                cli_preview="talos ai notes show",
            )

        # 9) PTT frontier tools.
        if frontier:
            for node in frontier[:3]:
                tools = node.get("suggested_tools") or []
                for t in tools:
                    if t in available:
                        _add(
                            str(t),
                            {},
                            f"PTT node '{node.get('title')}' suggests tool {t}.",
                        )
            _add(
                "task_tree.list",
                {},
                "List open PTT nodes to track recon progress.",
                cli_preview="talos ai pending",  # operator surface; tool is internal
            )
        else:
            # Seed a default recon node via task_tree.upsert when empty + goal set.
            if request.goal and "task_tree.upsert" in available:
                _add(
                    "task_tree.upsert",
                    {
                        "title": f"Recon: {(request.goal or 'engagement')[:120]}",
                        "status": "pending",
                        "priority": 10,
                        "suggested_tools": ["endpoint.list", "access.coverage"],
                    },
                    "Seed PTT with a recon task from the session goal.",
                )

        # 10) Scheduler / open jobs if any.
        if int(signals.get("open_job_count") or 0) > 0:
            _add(
                "scheduler.jobs.list",
                {"limit": 50},
                "Poll open scheduler jobs for engine progress.",
                cli_preview="talos scheduler list",
            )

        # Fill remaining slots with safe defaults.
        defaults = [
            (
                "module.list",
                {},
                "List modules for multi-module coverage.",
                "talos module list",
            ),
            (
                "module.show_active",
                {},
                "Show active module.",
                "talos module show",
            ),
        ]
        for tool_name, args, reason, preview in defaults:
            if len(suggestions) >= max_n:
                break
            _add(tool_name, args, reason, cli_preview=preview)

        return suggestions[:max_n]
