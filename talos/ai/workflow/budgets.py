"""
Module: talos.ai.workflow.budgets

Purpose:
    Budget accounting helpers for AI sessions — check limits, increment
    counters, detect wall-clock overrun.

Dependencies: talos.ai.models
Data flow:
    PolicyValidator / Executor → check / reserve → BudgetUsage mutation
Side effects: None (callers persist usage_json on the session row).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from talos.ai.models import BudgetClass, BudgetLimits, BudgetUsage


def wall_clock_seconds(started_at_iso: str, now: Optional[datetime] = None) -> float:
    """
    Purpose:
        Seconds elapsed since session start (ISO-8601, assume UTC if naive).
    """
    now = now or datetime.now(timezone.utc)
    text = (started_at_iso or "").strip()
    if not text:
        return 0.0
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        started = datetime.fromisoformat(text)
    except ValueError:
        return 0.0
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    delta = now - started
    return max(0.0, delta.total_seconds())


def refresh_wall_clock(usage: BudgetUsage, started_at_iso: str) -> BudgetUsage:
    """Update wall_clock_s from session start; returns the same usage object."""
    usage.wall_clock_s = wall_clock_seconds(started_at_iso)
    return usage


def first_exceeded(
    limits: BudgetLimits,
    usage: BudgetUsage,
    *,
    started_at_iso: str | None = None,
) -> Optional[str]:
    """
    Purpose:
        Return the name of the first budget limit that is exceeded, or None.
    Input:
        limits / usage — session budgets.
        started_at_iso — when set, wall_clock is recomputed before check.
    Output:
        Counter name string (e.g. 'max_tool_calls') or None.
    """
    if started_at_iso:
        refresh_wall_clock(usage, started_at_iso)

    # Use >= so a counter that has already hit its cap blocks further work.
    # Wall clock compares whole seconds (floor) against the limit.
    checks = [
        ("max_steps", usage.steps, limits.max_steps),
        ("max_tool_calls", usage.tool_calls, limits.max_tool_calls),
        ("max_http_executed", usage.http_executed, limits.max_http_executed),
        ("max_jobs_enqueued", usage.jobs_enqueued, limits.max_jobs_enqueued),
        ("max_intruder_payloads", usage.intruder_payloads, limits.max_intruder_payloads),
        ("max_llm_tokens", usage.llm_tokens, limits.max_llm_tokens),
        ("max_wall_clock_s", int(usage.wall_clock_s), limits.max_wall_clock_s),
    ]
    for name, current, limit in checks:
        if limit <= 0:
            # Non-positive limits are treated as immediately exhausted (fail-closed).
            return name
        if current >= limit:
            return name
    return None


def would_exceed_after(
    limits: BudgetLimits,
    usage: BudgetUsage,
    budget_class: BudgetClass,
    *,
    amount: int = 1,
    started_at_iso: str | None = None,
) -> Optional[str]:
    """
    Purpose:
        Predict whether incrementing a budget class would cross a limit.
    Output:
        Limit name if exceeded after increment, else None.
    """
    if started_at_iso:
        refresh_wall_clock(usage, started_at_iso)
    # Wall clock is always checked even when the tool is free.
    exceeded = first_exceeded(limits, usage)
    if exceeded:
        return exceeded

    if budget_class == BudgetClass.HTTP_EXECUTED:
        if usage.http_executed + amount > limits.max_http_executed:
            return "max_http_executed"
    elif budget_class == BudgetClass.JOB_ENQUEUED:
        if usage.jobs_enqueued + amount > limits.max_jobs_enqueued:
            return "max_jobs_enqueued"
    elif budget_class == BudgetClass.INTRUDER_PAYLOAD:
        if usage.intruder_payloads + amount > limits.max_intruder_payloads:
            return "max_intruder_payloads"
    # tool_calls always increments on execute attempt (checked separately).
    if usage.tool_calls + 1 > limits.max_tool_calls:
        return "max_tool_calls"
    return None


def apply_tool_call(
    usage: BudgetUsage,
    budget_class: BudgetClass,
    *,
    amount: int = 1,
) -> None:
    """
    Purpose:
        Record one executor attempt (+ optional class-specific counter).
    Side effects: mutates usage in place.
    """
    usage.tool_calls += 1
    if budget_class == BudgetClass.HTTP_EXECUTED:
        usage.http_executed += amount
    elif budget_class == BudgetClass.JOB_ENQUEUED:
        usage.jobs_enqueued += amount
    elif budget_class == BudgetClass.INTRUDER_PAYLOAD:
        usage.intruder_payloads += amount
