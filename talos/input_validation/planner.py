"""
Module: talos.input_validation.planner

Purpose:
    Event-driven **Input Validation planner** (Modules 5–8 hooks).

    Deterministic state machine that decides the next probe action(s) for a
    parameter from observations, budget tier, and uncertainty — replacing the
    legacy "enqueue entire ~70-probe matrix up front" control plane.

    This module is pure decision logic: no HTTP, no SQLite, no scheduler.
    The engine builds PlanContext from DB state and turns PlanAction tokens
    into scheduler jobs (or inline synthesize).

State machine (high level)::

    INIT → ENSURE_BASELINE → MULTIPROBE → EVALUATE
    EVALUATE → CHAR_DRILLDOWN | LENGTH_SEARCH | TYPE_CONFIRM |
               PARSER_PROBES | SEMANTIC_RULES | FINALIZE
    FINALIZE → SYNTHESIZE → DONE

Any step is skipped when the analysis toggle is off, budget is exhausted, or
confidence is already high enough for the current tier.

Budget tiers (same names as ``probe_strategy`` / profile ``budget_tier``):

    quick       ~5–8 HTTP / param (aggressive early stop)
    standard    ~10–18 HTTP / param (default; multiprobe-first)
    deep        ~25–40 HTTP / param (canaries + class drill-down + length)
    exhaustive  ~70+ HTTP / param (legacy full matrix escape hatch)

Module 6 executors (engine implements):

    char_drilldown  — taxonomy-class representatives (+ drill-down on deep)
    length_binary   — logarithmic seed + binary midpoint refinement

Module 7 executors (engine implements):

    type_confirm    — passive-first pruned type probes (not full 12 matrix)
    semantic_rules  — business-rule + core validation (no SQLi/XSS by default)

Module 8 executors (engine implements):

    parser_probes   — normalization stages + parser fingerprint (dup/null/array)

Module 9 (surface completeness) has no new action tokens: path/header/cookie/
multipart/GraphQL/XML inject live in surface.py + prepare_iv_probe; planner
still keys profiles by (host, location, name) uniformly.

Module 10 (multi-level learning): PlanContext carries inheritance priors from
endpoint/app profiles.  Under standard/quick, inherited rejected control/null
classes and known parser fingerprints suppress follow-up probe waves so a
second parameter on the same endpoint spends fewer requests.

Dependencies: dataclasses, typing only
Data flow:
    engine.build_plan_context() → plan_next(ctx) → list[PlanAction]
    → engine enqueues jobs / runs synthesize
Side effects: None (pure).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Planner states
# ---------------------------------------------------------------------------

STATE_INIT = "INIT"
STATE_ENSURE_BASELINE = "ENSURE_BASELINE"
STATE_MULTIPROBE = "MULTIPROBE"
STATE_EVALUATE = "EVALUATE"
STATE_FINALIZE = "FINALIZE"
STATE_SYNTHESIZE = "SYNTHESIZE"
STATE_DONE = "DONE"

PLANNER_STATES: frozenset[str] = frozenset({
    STATE_INIT,
    STATE_ENSURE_BASELINE,
    STATE_MULTIPROBE,
    STATE_EVALUATE,
    STATE_FINALIZE,
    STATE_SYNTHESIZE,
    STATE_DONE,
})


# ---------------------------------------------------------------------------
# Action tokens (engine maps these to job types / probe lists)
# ---------------------------------------------------------------------------

ACTION_BASELINE = "baseline"
ACTION_MULTIPROBE = "multiprobe"
ACTION_IDENTIFIER = "identifier"
ACTION_CHARACTERS = "characters"
ACTION_CHAR_DRILLDOWN = "char_drilldown"  # Module 6 — taxonomy class probes
ACTION_LENGTH = "length"
ACTION_LENGTH_BINARY = "length_binary"  # Module 6 — log/binary length search
ACTION_TYPES = "types"
ACTION_TYPE_CONFIRM = "type_confirm"  # Module 7 executor
ACTION_VALIDATION = "validation"
ACTION_SEMANTIC_RULES = "semantic_rules"  # Module 7
ACTION_PARSER_PROBES = "parser_probes"  # Module 8
ACTION_TRANSFORMATIONS = "transformations"
ACTION_REFLECTION = "reflection"
ACTION_SYNTHESIZE = "synthesize"
ACTION_DONE = "done"

# Actions that consume HTTP budget (1+ requests when expanded).
HTTP_ACTIONS: frozenset[str] = frozenset({
    ACTION_BASELINE,
    ACTION_MULTIPROBE,
    ACTION_IDENTIFIER,
    ACTION_CHARACTERS,
    ACTION_CHAR_DRILLDOWN,
    ACTION_LENGTH,
    ACTION_LENGTH_BINARY,
    ACTION_TYPES,
    ACTION_TYPE_CONFIRM,
    ACTION_VALIDATION,
    ACTION_SEMANTIC_RULES,
    ACTION_PARSER_PROBES,
})

# Analysis-only / finalize actions (0 HTTP).
FINALIZE_ACTIONS: frozenset[str] = frozenset({
    ACTION_TRANSFORMATIONS,
    ACTION_REFLECTION,
})

# Tokens reserved for M11+; planner may emit them; engine maps or defers.
# Module 9–10 do not add new action tokens (surface inject + multi-level
# inheritance adjust existing follow-ups via PlanContext priors).
FUTURE_ACTION_TOKENS: frozenset[str] = frozenset({
    # Attack-candidate scoring (M11) is offline (candidates.py); no planner tokens.
})

# Module 6 implemented action tokens (engine has real executors).
M6_ACTION_TOKENS: frozenset[str] = frozenset({
    ACTION_CHAR_DRILLDOWN,
    ACTION_LENGTH_BINARY,
})

# Module 7 implemented action tokens.
M7_ACTION_TOKENS: frozenset[str] = frozenset({
    ACTION_TYPE_CONFIRM,
    ACTION_SEMANTIC_RULES,
})

# Module 8 implemented action tokens.
M8_ACTION_TOKENS: frozenset[str] = frozenset({
    ACTION_PARSER_PROBES,
})


# ---------------------------------------------------------------------------
# Budget defaults (hard caps when max_requests_per_param unset)
# ---------------------------------------------------------------------------

BUDGET_TIER_QUICK = "quick"
BUDGET_TIER_STANDARD = "standard"
BUDGET_TIER_DEEP = "deep"
BUDGET_TIER_EXHAUSTIVE = "exhaustive"

BUDGET_TIERS: tuple[str, ...] = (
    BUDGET_TIER_QUICK,
    BUDGET_TIER_STANDARD,
    BUDGET_TIER_DEEP,
    BUDGET_TIER_EXHAUSTIVE,
)

# Typical max HTTP requests per parameter when config override is absent.
DEFAULT_MAX_REQUESTS: dict[str, int] = {
    BUDGET_TIER_QUICK: 8,
    BUDGET_TIER_STANDARD: 18,
    BUDGET_TIER_DEEP: 40,
    BUDGET_TIER_EXHAUSTIVE: 80,
}

# Typical char_drilldown / length_binary sizes by tier (planner estimates).
# Standard chars: class representatives only (~11), not the legacy 30-char list.
_CHAR_DRILLDOWN_ESTIMATE: dict[str, int] = {
    BUDGET_TIER_QUICK: 4,
    BUDGET_TIER_STANDARD: 11,
    BUDGET_TIER_DEEP: 28,
    BUDGET_TIER_EXHAUSTIVE: 33,
}
_LENGTH_BINARY_SEED_ESTIMATE: dict[str, int] = {
    BUDGET_TIER_QUICK: 3,
    BUDGET_TIER_STANDARD: 5,
    BUDGET_TIER_DEEP: 6,
    BUDGET_TIER_EXHAUSTIVE: 10,
}
# Max total length probes (seed + binary refine) before planner stops.
_LENGTH_PROBE_CAP: dict[str, int] = {
    BUDGET_TIER_QUICK: 3,
    BUDGET_TIER_STANDARD: 7,
    BUDGET_TIER_DEEP: 10,
    BUDGET_TIER_EXHAUSTIVE: 10,
}

# Type confirm / semantic_rules estimates (engine prunes further via type_intel).
_TYPE_CONFIRM_ESTIMATE: dict[str, int] = {
    BUDGET_TIER_QUICK: 2,
    BUDGET_TIER_STANDARD: 4,
    BUDGET_TIER_DEEP: 8,
    BUDGET_TIER_EXHAUSTIVE: 12,
}
_SEMANTIC_RULES_ESTIMATE: dict[str, int] = {
    BUDGET_TIER_QUICK: 2,
    BUDGET_TIER_STANDARD: 5,
    BUDGET_TIER_DEEP: 8,
    BUDGET_TIER_EXHAUSTIVE: 10,
}
# Module 8 parser + normalization probe estimates (engine prunes by location).
_PARSER_PROBES_ESTIMATE: dict[str, int] = {
    BUDGET_TIER_QUICK: 0,
    BUDGET_TIER_STANDARD: 5,
    BUDGET_TIER_DEEP: 10,
    BUDGET_TIER_EXHAUSTIVE: 14,
}

# Confidence thresholds (Section 0.4 consumer guidance).
CONFIDENCE_TRUST = 90
CONFIDENCE_VERIFY = 60

# Max multiprobe jobs under standard/quick when reflection still unknown.
MAX_MULTIPROBE_RETRIES = 2


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlanAction:
    """
    One planner decision item.

    Fields:
        action      — token (baseline, multiprobe, length_binary, …).
        hypothesis  — why this probe was chosen (stored on job meta / attempts).
        estimated_requests — expected HTTP count when engine expands the action.
        meta        — optional hints for the engine (e.g. multiprobe_index).
    """

    action: str
    hypothesis: str
    estimated_requests: int = 1
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlanResult:
    """
    Output of plan_next().

    Fields:
        state       — derived planner state after this decision.
        actions     — next work items (empty when done).
        done        — True when no further probe/analysis work for this param.
        reason      — human-readable decision summary.
        budget_remaining — hard-cap HTTP slots left after this plan step.
    """

    state: str
    actions: list[PlanAction]
    done: bool
    reason: str
    budget_remaining: int


@dataclass
class PlanContext:
    """
    Inputs to the planner for one parameter (all pre-resolved; no I/O).

    Build via engine helpers from probe rows + profile + config, or construct
    directly in unit tests with fake signals.
    """

    budget_tier: str = BUDGET_TIER_STANDARD
    max_requests: int = DEFAULT_MAX_REQUESTS[BUDGET_TIER_STANDARD]
    requests_used: int = 0

    # Completed scan analyses (at least one completed probe row).
    completed_analyses: frozenset[str] = field(default_factory=frozenset)
    multiprobe_completed_count: int = 0
    identifier_completed_count: int = 0
    characters_completed_count: int = 0
    length_completed_count: int = 0
    types_completed_count: int = 0
    validation_completed_count: int = 0
    parser_completed_count: int = 0

    # Analysis / finalize completion (param cache / reflection cache).
    transformations_done: bool = False
    reflection_done: bool = False
    synthesize_done: bool = False

    # Actions already pending or running in the scheduler (action tokens).
    pending_actions: frozenset[str] = field(default_factory=frozenset)

    # Observation signals (from profile and/or probe synthesis).
    reflection_state: str = "unknown"
    reflection_confidence: int = 0
    reflection_uncertainty: str = "high"
    length_state: str = "unknown"
    length_confidence: int = 0
    length_uncertainty: str = "high"
    types_known: bool = False
    types_uncertainty: str = "high"
    types_confidence: int = 0
    acceptance_class_count: int = 0
    parser_known: bool = False

    # Passive Endpoint Intelligence (Module 7 type pruning).
    semantic_type: str = "unknown"
    param_name: str = ""
    max_accepted_length: int | None = None
    # Content-Type hint for parser probe selection (from baseline / flow).
    content_type: str = ""
    # Parameter location (query|body|header|cookie|path) for M8 selection.
    location: str = "query"

    # Module 10 — multi-level inheritance priors (from endpoint/app profiles).
    # These are inferred-only; local observed is already folded into the
    # signals above when present.  Engine fills from learning.load_inheritance_priors.
    inheritance_active: bool = False
    inherited_tested: dict[str, dict] = field(default_factory=dict)
    inherited_rejected_classes: frozenset[str] = field(default_factory=frozenset)
    inherited_accepted_classes: frozenset[str] = field(default_factory=frozenset)
    suppress_control_probes: bool = False
    suppress_parser_probes: bool = False
    inheritance_reduced_estimate: int = 0

    # Per-phase analysis toggles (mirrors IVAnalysesConfig field names).
    analyses_enabled: dict[str, bool] = field(default_factory=dict)

    # Whether an endpoint_id is available (required for reflection jobs).
    has_endpoint: bool = True

    def analysis_on(self, name: str) -> bool:
        """Return True when the named analysis toggle is enabled (default True)."""
        if not self.analyses_enabled:
            return True
        return bool(self.analyses_enabled.get(name, True))

    def remaining_budget(self) -> int:
        """HTTP requests still allowed under the hard cap."""
        return max(0, int(self.max_requests) - int(self.requests_used))

    def has_completed(self, analysis: str) -> bool:
        return analysis in self.completed_analyses

    def is_pending(self, action: str) -> bool:
        return action in self.pending_actions


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def resolve_max_requests(
    budget_tier: str,
    max_requests_per_param: int | None = None,
) -> int:
    """
    Purpose:
        Resolve the hard HTTP request cap for a parameter.
    Input:
        budget_tier            — quick|standard|deep|exhaustive.
        max_requests_per_param — optional config override; 0/None → tier default.
    Output:
        Positive integer hard cap.
    Side effects: None.
    """
    tier = (budget_tier or BUDGET_TIER_STANDARD).lower().strip()
    if tier not in DEFAULT_MAX_REQUESTS:
        tier = BUDGET_TIER_STANDARD
    if max_requests_per_param is not None and int(max_requests_per_param) > 0:
        return int(max_requests_per_param)
    return DEFAULT_MAX_REQUESTS[tier]


def confidence_is_high(confidence: int, uncertainty: str) -> bool:
    """
    Purpose:
        True when a characteristic is trusted enough to skip follow-up probes.
    Side effects: None.
    """
    u = (uncertainty or "high").lower()
    return int(confidence) >= CONFIDENCE_TRUST and u in ("none", "low")


def reflection_needs_retry(
    state: str,
    confidence: int,
    uncertainty: str,
) -> bool:
    """
    Purpose:
        True when reflection is still unknown / low-confidence and another
        multiprobe (or identifier) is warranted.
    Side effects: None.
    """
    st = (state or "unknown").lower()
    if st in ("unknown", "conflicting"):
        return True
    if int(confidence) < CONFIDENCE_VERIFY:
        return True
    if (uncertainty or "high").lower() == "high" and int(confidence) < CONFIDENCE_TRUST:
        return True
    return False


def signals_from_profile(profile: dict[str, Any] | None) -> dict[str, Any]:
    """
    Purpose:
        Extract planner observation signals from a parameter profile document.
    Input:
        profile — param profile dict or None.
    Output:
        Flat dict suitable for PlanContext keyword overrides.
    Side effects: None.
    """
    if not profile or not isinstance(profile, dict):
        return {}
    obs = profile.get("observed") or {}
    refl = obs.get("reflection") or {}
    length = obs.get("length") or {}
    types = obs.get("types") or {}
    acceptance = (obs.get("acceptance") or {}).get("classes") or {}
    parser_obs = obs.get("parser") or profile.get("parser") or {}
    pipeline = profile.get("normalization_pipeline") or []
    inferred = profile.get("inferred") or {}
    synth = inferred.get("synthesis") if isinstance(inferred, dict) else None

    class_count = 0
    if isinstance(acceptance, dict):
        class_count = len(acceptance)

    types_known = bool(types) and any(
        isinstance(v, dict) and v.get("outcome") and not str(k).startswith("_")
        for k, v in types.items()
    ) if isinstance(types, dict) else False

    types_summary = types.get("_summary") if isinstance(types, dict) else None
    types_uncertainty = "low" if types_known else "high"
    types_confidence = 0
    if isinstance(types_summary, dict):
        types_uncertainty = str(types_summary.get("uncertainty") or types_uncertainty)
        types_confidence = int(types_summary.get("confidence") or 0)

    parser_known = bool(
        (isinstance(parser_obs, dict) and any(
            isinstance(v, dict) and (v.get("state") or v.get("behavior"))
            for v in parser_obs.values()
        ))
        or (isinstance(pipeline, list) and len(pipeline) > 0)
    )

    max_accepted: int | None = None
    raw_max = length.get("max_accepted") if isinstance(length, dict) else None
    if raw_max is not None:
        try:
            max_accepted = int(raw_max)
        except (TypeError, ValueError):
            max_accepted = None

    synthesize_done = bool(
        isinstance(synth, dict) and synth.get("source")
    )

    return {
        "reflection_state": str(refl.get("state") or "unknown"),
        "reflection_confidence": int(refl.get("confidence") or 0),
        "reflection_uncertainty": str(refl.get("uncertainty") or "high"),
        "length_state": str(length.get("state") or "unknown"),
        "length_confidence": int(length.get("confidence") or 0),
        "length_uncertainty": str(length.get("uncertainty") or "high"),
        "types_known": types_known,
        "types_uncertainty": types_uncertainty,
        "types_confidence": types_confidence,
        "acceptance_class_count": class_count,
        "parser_known": parser_known,
        "max_accepted_length": max_accepted,
        "synthesize_done": synthesize_done,
        "requests_used": int(profile.get("requests_used") or 0),
        "budget_tier": str(profile.get("budget_tier") or BUDGET_TIER_STANDARD),
    }


# ---------------------------------------------------------------------------
# Core planner
# ---------------------------------------------------------------------------

def plan_next(ctx: PlanContext) -> PlanResult:
    """
    Purpose:
        Deterministic next-step decision for one parameter.

        Never schedules finalize (transformations / reflection) before required
        evidence (baseline + multiprobe when enabled).  Respects hard budget
        for HTTP actions; finalize and synthesize always allowed at 0 cost.

    Input:
        ctx — fully populated PlanContext (no I/O inside this function).
    Output:
        PlanResult with zero or more PlanActions.
    Side effects: None.
    """
    tier = (ctx.budget_tier or BUDGET_TIER_STANDARD).lower().strip()
    if tier not in DEFAULT_MAX_REQUESTS:
        tier = BUDGET_TIER_STANDARD

    remaining = ctx.remaining_budget()
    state = _derive_state(ctx, tier)

    if state == STATE_DONE:
        return PlanResult(
            state=STATE_DONE,
            actions=[],
            done=True,
            reason="parameter intelligence complete",
            budget_remaining=remaining,
        )

    # ── ENSURE_BASELINE ────────────────────────────────────────────────────
    if state == STATE_ENSURE_BASELINE:
        if ctx.is_pending(ACTION_BASELINE):
            return PlanResult(
                state=STATE_ENSURE_BASELINE,
                actions=[],
                done=False,
                reason="baseline already pending",
                budget_remaining=remaining,
            )
        if remaining < 1:
            # Cannot baseline — jump to finalize with empty evidence (degraded).
            return _plan_finalize_or_synthesize(
                ctx, remaining, reason="budget exhausted before baseline"
            )
        return PlanResult(
            state=STATE_ENSURE_BASELINE,
            actions=[
                PlanAction(
                    action=ACTION_BASELINE,
                    hypothesis="baseline.unmutated_replay",
                    estimated_requests=1,
                )
            ],
            done=False,
            reason="ensure baseline response fingerprint",
            budget_remaining=remaining,
        )

    # ── MULTIPROBE (first active multi-signal step) ────────────────────────
    if state == STATE_MULTIPROBE:
        if not ctx.analysis_on("multiprobe"):
            # Fall through to evaluate (may use identifiers under deep/exhaustive).
            return _plan_evaluate(ctx, tier, remaining)

        if ctx.is_pending(ACTION_MULTIPROBE):
            return PlanResult(
                state=STATE_MULTIPROBE,
                actions=[],
                done=False,
                reason="multiprobe already pending",
                budget_remaining=remaining,
            )
        if remaining < 1:
            return _plan_finalize_or_synthesize(
                ctx, remaining, reason="budget exhausted before multiprobe"
            )
        return PlanResult(
            state=STATE_MULTIPROBE,
            actions=[
                PlanAction(
                    action=ACTION_MULTIPROBE,
                    hypothesis="multiprobe.canary_and_taxonomy",
                    estimated_requests=1,
                    meta={"multiprobe_index": ctx.multiprobe_completed_count},
                )
            ],
            done=False,
            reason="multiprobe first active step after baseline",
            budget_remaining=remaining,
        )

    # ── EVALUATE (conditional follow-ups) ──────────────────────────────────
    if state == STATE_EVALUATE:
        return _plan_evaluate(ctx, tier, remaining)

    # ── FINALIZE ───────────────────────────────────────────────────────────
    if state == STATE_FINALIZE:
        return _plan_finalize_or_synthesize(
            ctx, remaining, reason="finalize analysis after evidence"
        )

    # ── SYNTHESIZE ─────────────────────────────────────────────────────────
    if state == STATE_SYNTHESIZE:
        if ctx.is_pending(ACTION_SYNTHESIZE):
            return PlanResult(
                state=STATE_SYNTHESIZE,
                actions=[],
                done=False,
                reason="synthesize already in flight",
                budget_remaining=remaining,
            )
        return PlanResult(
            state=STATE_SYNTHESIZE,
            actions=[
                PlanAction(
                    action=ACTION_SYNTHESIZE,
                    hypothesis="synthesize.offline_profile",
                    estimated_requests=0,
                )
            ],
            done=False,
            reason="offline profile synthesis",
            budget_remaining=remaining,
        )

    return PlanResult(
        state=STATE_DONE,
        actions=[],
        done=True,
        reason="no further actions",
        budget_remaining=remaining,
    )


def _derive_state(ctx: PlanContext, tier: str) -> str:
    """
    Purpose:
        Map completed work + signals to the current state machine node.
    Side effects: None.
    """
    baseline_needed = ctx.analysis_on("baseline") and not ctx.has_completed("baseline")
    if baseline_needed and not ctx.is_pending(ACTION_BASELINE):
        return STATE_ENSURE_BASELINE
    if baseline_needed and ctx.is_pending(ACTION_BASELINE):
        return STATE_ENSURE_BASELINE

    multiprobe_needed = (
        ctx.analysis_on("multiprobe")
        and ctx.multiprobe_completed_count < 1
        and not ctx.is_pending(ACTION_MULTIPROBE)
    )
    if multiprobe_needed:
        return STATE_MULTIPROBE
    if ctx.analysis_on("multiprobe") and ctx.is_pending(ACTION_MULTIPROBE) and ctx.multiprobe_completed_count < 1:
        return STATE_MULTIPROBE

    # Evidence gate: do not finalize until baseline (+ multiprobe if on) exist.
    if not _evidence_ready(ctx):
        # Still waiting on pending first-wave jobs.
        if ctx.is_pending(ACTION_BASELINE) or ctx.is_pending(ACTION_MULTIPROBE):
            return STATE_MULTIPROBE if ctx.has_completed("baseline") else STATE_ENSURE_BASELINE
        return STATE_EVALUATE

    if _needs_scan_followups(ctx, tier):
        return STATE_EVALUATE

    if _needs_finalize(ctx):
        return STATE_FINALIZE

    if not ctx.synthesize_done:
        return STATE_SYNTHESIZE

    return STATE_DONE


def _evidence_ready(ctx: PlanContext) -> bool:
    """
    Purpose:
        True when required characterization evidence is present before finalize.
        Never allow analysis-before-evidence races.
    Side effects: None.
    """
    if ctx.analysis_on("baseline") and not ctx.has_completed("baseline"):
        return False
    if ctx.analysis_on("multiprobe") and ctx.multiprobe_completed_count < 1:
        # Multiprobe off path is handled by identifier under deep/exhaustive.
        if not ctx.analysis_on("identifier"):
            return False
        # If multiprobe on but not done, not ready.
        return False
    return True


def _needs_scan_followups(ctx: PlanContext, tier: str) -> bool:
    """
    Purpose:
        Whether EVALUATE should still schedule HTTP follow-up probes.
    Side effects: None.
    """
    if ctx.remaining_budget() < 1:
        return False

    # Pending HTTP follow-ups already scheduled — stay in EVALUATE until they land.
    for action in (
        ACTION_MULTIPROBE,
        ACTION_IDENTIFIER,
        ACTION_CHARACTERS,
        ACTION_CHAR_DRILLDOWN,
        ACTION_LENGTH,
        ACTION_LENGTH_BINARY,
        ACTION_TYPES,
        ACTION_TYPE_CONFIRM,
        ACTION_VALIDATION,
        ACTION_SEMANTIC_RULES,
        ACTION_PARSER_PROBES,
    ):
        if ctx.is_pending(action):
            return True

    if tier == BUDGET_TIER_EXHAUSTIVE:
        return _exhaustive_matrix_incomplete(ctx)

    if tier == BUDGET_TIER_DEEP:
        return _deep_followups_needed(ctx)

    # quick / standard — adaptive
    return _adaptive_followups_needed(ctx, tier)


def _exhaustive_matrix_incomplete(ctx: PlanContext) -> bool:
    """True when legacy-like coverage is still missing."""
    if ctx.analysis_on("identifier") and ctx.identifier_completed_count < 1:
        return True
    if ctx.analysis_on("characters") and ctx.characters_completed_count < 1:
        return True
    if ctx.analysis_on("length") and _length_search_needed(ctx, BUDGET_TIER_EXHAUSTIVE):
        return True
    if ctx.analysis_on("types") and ctx.types_completed_count < 1:
        return True
    if ctx.analysis_on("validation") and ctx.validation_completed_count < 1:
        return True
    if _parser_probes_needed(ctx, BUDGET_TIER_EXHAUSTIVE):
        return True
    return False


def _deep_followups_needed(ctx: PlanContext) -> bool:
    """Deep tier: identifiers + class drill-down + length/types/semantic/parser when uncertain."""
    if ctx.analysis_on("identifier") and ctx.identifier_completed_count < 1:
        return True
    if ctx.analysis_on("characters") and ctx.characters_completed_count < 1:
        return True
    if ctx.analysis_on("length") and _length_search_needed(ctx, BUDGET_TIER_DEEP):
        return True
    if ctx.analysis_on("types") and ctx.types_completed_count < 1 and not ctx.types_known:
        return True
    if (
        ctx.analysis_on("validation")
        and ctx.validation_completed_count < 1
        and not ctx.is_pending(ACTION_SEMANTIC_RULES)
        and not ctx.is_pending(ACTION_VALIDATION)
    ):
        return True
    if _parser_probes_needed(ctx, BUDGET_TIER_DEEP):
        return True
    return False


def _parser_probes_needed(ctx: PlanContext, tier: str) -> bool:
    """
    Purpose:
        True when Module 8 parser_probes should still run.
        Quick skips; standard/deep/exhaustive when not yet attempted and
        parser fingerprint not already known.

        Module 10: under quick/standard, inherited endpoint/app parser
        fingerprint suppresses re-probe (``suppress_parser_probes``).
    Side effects: None.
    """
    if tier == BUDGET_TIER_QUICK:
        return False
    # Reuse transformations toggle as "normalization/parser characterization on"
    # when present; default on when analyses map empty.
    if not ctx.analysis_on("transformations") and ctx.analyses_enabled:
        # If transformations explicitly off, still allow parser when validation on.
        if not ctx.analysis_on("validation") and not ctx.analysis_on("types"):
            return False
    if ctx.is_pending(ACTION_PARSER_PROBES):
        return True
    if ctx.parser_completed_count >= 1 or ctx.parser_known:
        return False
    if ctx.has_completed("parser"):
        return False
    # M10: parent-level parser known → skip under standard (deep re-confirms).
    if (
        tier in (BUDGET_TIER_QUICK, BUDGET_TIER_STANDARD)
        and getattr(ctx, "suppress_parser_probes", False)
    ):
        return False
    return True


def _length_search_needed(ctx: PlanContext, tier: str) -> bool:
    """
    Purpose:
        True when Module 6 length_binary should still run (seed or refine).
        Stops on high confidence, length probe cap, or resolved bound.
    Side effects: None.
    """
    if not ctx.analysis_on("length"):
        return False
    if ctx.is_pending(ACTION_LENGTH_BINARY) or ctx.is_pending(ACTION_LENGTH):
        return True
    cap = _LENGTH_PROBE_CAP.get(tier, _LENGTH_PROBE_CAP[BUDGET_TIER_STANDARD])
    if ctx.length_completed_count >= cap:
        return False
    if confidence_is_high(ctx.length_confidence, ctx.length_uncertainty):
        return False
    # Bounded/truncated/all_rejected with low uncertainty → done.
    if (
        ctx.length_state in ("bounded", "truncated", "all_rejected")
        and ctx.length_uncertainty in ("none", "low")
        and int(ctx.length_confidence) >= CONFIDENCE_VERIFY
    ):
        return False
    # Never started.
    if ctx.length_completed_count < 1:
        return True
    # Started but still highly uncertain → allow binary refinement wave.
    if ctx.length_uncertainty == "high" or int(ctx.length_confidence) < CONFIDENCE_VERIFY:
        return True
    return False


def _adaptive_followups_needed(ctx: PlanContext, tier: str) -> bool:
    """
    quick/standard: only when uncertainty is high or multiprobe retry needed.
    """
    # Extra multiprobe when reflection still unknown (standard/quick).
    if (
        ctx.analysis_on("multiprobe")
        and ctx.multiprobe_completed_count >= 1
        and ctx.multiprobe_completed_count < MAX_MULTIPROBE_RETRIES
        and reflection_needs_retry(
            ctx.reflection_state,
            ctx.reflection_confidence,
            ctx.reflection_uncertainty,
        )
    ):
        return True

    # High-confidence early stop: no more HTTP scans.
    if _early_stop_ok(ctx, tier):
        return False

    # Length detail when still uncertain (Module 6 length_binary).
    if (
        tier == BUDGET_TIER_STANDARD
        and _length_search_needed(ctx, tier)
        and ctx.remaining_budget() >= 3
    ):
        return True

    # Type confirm when types completely unknown under standard with budget.
    if (
        tier == BUDGET_TIER_STANDARD
        and ctx.analysis_on("types")
        and ctx.types_completed_count < 1
        and not ctx.types_known
        and ctx.types_uncertainty == "high"
        and ctx.remaining_budget() >= 2
        and not _early_stop_ok(ctx, tier)
    ):
        # Prefer early stop when reflection + acceptance classes already solid.
        if ctx.acceptance_class_count >= 3 and confidence_is_high(
            ctx.reflection_confidence, ctx.reflection_uncertainty
        ):
            return False
        return True

    # Semantic / core validation when still unattempted under standard.
    if (
        tier == BUDGET_TIER_STANDARD
        and ctx.analysis_on("validation")
        and ctx.validation_completed_count < 1
        and not ctx.is_pending(ACTION_SEMANTIC_RULES)
        and not ctx.is_pending(ACTION_VALIDATION)
        and ctx.remaining_budget() >= 2
        and not _early_stop_ok(ctx, tier)
    ):
        if ctx.acceptance_class_count >= 3 and confidence_is_high(
            ctx.reflection_confidence, ctx.reflection_uncertainty
        ):
            return False
        # M10: rich inherited tested negatives → validation less urgent.
        if _inheritance_covers_validation(ctx):
            return False
        return True

    # Parser / normalization fingerprint under standard when budget remains.
    if (
        tier == BUDGET_TIER_STANDARD
        and _parser_probes_needed(ctx, tier)
        and ctx.remaining_budget() >= 2
        and not _early_stop_ok(ctx, tier)
    ):
        return True

    return False


def _inheritance_covers_validation(ctx: PlanContext) -> bool:
    """
    Purpose:
        True when Module 10 inherited tested already covers core validation
        families (null/control/empty/unicode) so standard can skip semantic_rules.
    Side effects: None.
    """
    if not getattr(ctx, "inheritance_active", False):
        return False
    tested = getattr(ctx, "inherited_tested", None) or {}
    if not isinstance(tested, dict):
        return False
    core_keys = ("null", "null_byte", "control", "empty", "unicode", "whitespace")
    rejected = 0
    for key in core_keys:
        entry = tested.get(key)
        if not isinstance(entry, dict):
            continue
        if str(entry.get("outcome") or "").lower() != "rejected":
            continue
        try:
            conf = int(entry.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0
        if conf >= CONFIDENCE_VERIFY:
            rejected += 1
    # Also count suppress_control as covering control/null.
    if getattr(ctx, "suppress_control_probes", False):
        rejected = max(rejected, 2)
    return rejected >= 2


def _early_stop_ok(ctx: PlanContext, tier: str) -> bool:
    """
    Purpose:
        High-confidence early stop for quick/standard after multiprobe evidence.
    Side effects: None.
    """
    if tier not in (BUDGET_TIER_QUICK, BUDGET_TIER_STANDARD):
        return False
    if ctx.analysis_on("multiprobe") and ctx.multiprobe_completed_count < 1:
        return False
    # Reflection resolved with trustable confidence, or clear not_reflected.
    refl_ok = (
        confidence_is_high(ctx.reflection_confidence, ctx.reflection_uncertainty)
        or (
            ctx.reflection_state in ("reflected", "not_reflected")
            and int(ctx.reflection_confidence) >= CONFIDENCE_VERIFY
            and ctx.reflection_uncertainty in ("none", "low")
        )
    )
    # Taxonomy signal from multiprobe is enough for standard.
    classes_ok = ctx.acceptance_class_count >= 1 or not ctx.analysis_on("multiprobe")
    if tier == BUDGET_TIER_QUICK:
        # Quick: stop as soon as multiprobe completed and reflection is not
        # completely unknown — even medium confidence.
        if ctx.reflection_state != "unknown":
            return True
        if ctx.multiprobe_completed_count >= MAX_MULTIPROBE_RETRIES:
            return True
        return False
    return bool(refl_ok and classes_ok)


def _needs_finalize(ctx: PlanContext) -> bool:
    """True when transformations and/or reflection still need scheduling."""
    if ctx.analysis_on("transformations") and not ctx.transformations_done:
        if not ctx.is_pending(ACTION_TRANSFORMATIONS):
            return True
        return True  # still finalizing
    if (
        ctx.analysis_on("reflection")
        and ctx.has_endpoint
        and not ctx.reflection_done
    ):
        if not ctx.is_pending(ACTION_REFLECTION):
            return True
        return True
    # Pending finalize actions keep us in FINALIZE.
    if ctx.is_pending(ACTION_TRANSFORMATIONS) or ctx.is_pending(ACTION_REFLECTION):
        return True
    return False


def _plan_evaluate(ctx: PlanContext, tier: str, remaining: int) -> PlanResult:
    """
    Purpose:
        Choose conditional follow-up HTTP probes under the current tier.
    Side effects: None.
    """
    actions: list[PlanAction] = []
    budget_left = remaining

    def _can_afford(n: int) -> bool:
        return budget_left >= n and n > 0

    def _take(action: PlanAction) -> None:
        nonlocal budget_left
        if action.action in HTTP_ACTIONS:
            if action.estimated_requests > budget_left:
                return
            budget_left -= action.estimated_requests
        actions.append(action)

    # ── Exhaustive: approximate full matrix ───────────────────────────────
    if tier == BUDGET_TIER_EXHAUSTIVE:
        if (
            ctx.analysis_on("identifier")
            and ctx.identifier_completed_count < 1
            and not ctx.is_pending(ACTION_IDENTIFIER)
        ):
            # ~9–11 identifier probes; estimate 11.
            est = min(11, budget_left) if budget_left else 0
            if est:
                _take(PlanAction(
                    action=ACTION_IDENTIFIER,
                    hypothesis="identifier.exhaustive_matrix",
                    estimated_requests=est,
                ))
        if (
            ctx.analysis_on("characters")
            and ctx.characters_completed_count < 1
            and not ctx.is_pending(ACTION_CHARACTERS)
            and not ctx.is_pending(ACTION_CHAR_DRILLDOWN)
        ):
            est = min(
                _CHAR_DRILLDOWN_ESTIMATE[BUDGET_TIER_EXHAUSTIVE],
                budget_left,
            ) if budget_left else 0
            if est:
                _take(PlanAction(
                    action=ACTION_CHARACTERS,
                    hypothesis="charset.exhaustive_matrix",
                    estimated_requests=est,
                    meta={"tier": BUDGET_TIER_EXHAUSTIVE, "force_full": True},
                ))
        if (
            ctx.analysis_on("length")
            and _length_search_needed(ctx, BUDGET_TIER_EXHAUSTIVE)
            and not ctx.is_pending(ACTION_LENGTH)
            and not ctx.is_pending(ACTION_LENGTH_BINARY)
        ):
            est = min(
                _LENGTH_BINARY_SEED_ESTIMATE[BUDGET_TIER_EXHAUSTIVE],
                budget_left,
            ) if budget_left else 0
            if est:
                _take(PlanAction(
                    action=ACTION_LENGTH,
                    hypothesis="length.exhaustive_matrix",
                    estimated_requests=est,
                    meta={"tier": BUDGET_TIER_EXHAUSTIVE, "method": "matrix"},
                ))
        if (
            ctx.analysis_on("types")
            and ctx.types_completed_count < 1
            and not ctx.is_pending(ACTION_TYPES)
            and not ctx.is_pending(ACTION_TYPE_CONFIRM)
        ):
            est = min(12, budget_left) if budget_left else 0
            if est:
                _take(PlanAction(
                    action=ACTION_TYPES,
                    hypothesis="types.exhaustive_matrix",
                    estimated_requests=est,
                ))
        if (
            ctx.analysis_on("validation")
            and ctx.validation_completed_count < 1
            and not ctx.is_pending(ACTION_VALIDATION)
        ):
            est = min(8, budget_left) if budget_left else 0
            if est:
                _take(PlanAction(
                    action=ACTION_VALIDATION,
                    hypothesis="validation.exhaustive_matrix",
                    estimated_requests=est,
                ))
        if (
            _parser_probes_needed(ctx, BUDGET_TIER_EXHAUSTIVE)
            and not ctx.is_pending(ACTION_PARSER_PROBES)
            and budget_left >= 1
        ):
            est = min(
                _PARSER_PROBES_ESTIMATE[BUDGET_TIER_EXHAUSTIVE],
                budget_left,
            )
            if est:
                _take(PlanAction(
                    action=ACTION_PARSER_PROBES,
                    hypothesis="parser.fingerprint_exhaustive",
                    estimated_requests=est,
                    meta={
                        "tier": BUDGET_TIER_EXHAUSTIVE,
                        "location": ctx.location or "query",
                        "content_type": ctx.content_type or "",
                        "reflection_state": ctx.reflection_state,
                    },
                ))
        if actions:
            return PlanResult(
                state=STATE_EVALUATE,
                actions=actions,
                done=False,
                reason="exhaustive matrix follow-ups",
                budget_remaining=budget_left,
            )
        return _plan_finalize_or_synthesize(
            ctx, budget_left, reason="exhaustive matrix complete → finalize"
        )

    # ── Deep: canaries + full characters + remaining phases ───────────────
    if tier == BUDGET_TIER_DEEP:
        if (
            ctx.analysis_on("identifier")
            and ctx.identifier_completed_count < 1
            and not ctx.is_pending(ACTION_IDENTIFIER)
            and _can_afford(1)
        ):
            est = min(5, budget_left)
            _take(PlanAction(
                action=ACTION_IDENTIFIER,
                hypothesis="identifier.deep_canaries",
                estimated_requests=est,
            ))
        if (
            ctx.analysis_on("characters")
            and ctx.characters_completed_count < 1
            and not ctx.is_pending(ACTION_CHARACTERS)
            and not ctx.is_pending(ACTION_CHAR_DRILLDOWN)
            and budget_left >= 1
        ):
            est = min(
                _CHAR_DRILLDOWN_ESTIMATE[BUDGET_TIER_DEEP],
                budget_left,
            )
            _take(PlanAction(
                action=ACTION_CHAR_DRILLDOWN,
                hypothesis="charset.char_drilldown",
                estimated_requests=est,
                meta={
                    "tier": BUDGET_TIER_DEEP,
                    "drilldown": True,
                    "reflection_state": ctx.reflection_state,
                },
            ))
        if (
            ctx.analysis_on("length")
            and _length_search_needed(ctx, BUDGET_TIER_DEEP)
            and not ctx.is_pending(ACTION_LENGTH_BINARY)
            and not ctx.is_pending(ACTION_LENGTH)
            and budget_left >= 1
        ):
            seed_est = _LENGTH_BINARY_SEED_ESTIMATE[BUDGET_TIER_DEEP]
            # Refinement waves are smaller (1–2 midpoints).
            est = min(
                seed_est if ctx.length_completed_count < 1 else 2,
                budget_left,
            )
            _take(PlanAction(
                action=ACTION_LENGTH_BINARY,
                hypothesis=(
                    "length.binary_seed"
                    if ctx.length_completed_count < 1
                    else "length.binary_refine"
                ),
                estimated_requests=est,
                meta={
                    "tier": BUDGET_TIER_DEEP,
                    "method": "binary",
                    "refine": ctx.length_completed_count >= 1,
                },
            ))
        if (
            ctx.analysis_on("types")
            and ctx.types_completed_count < 1
            and not ctx.types_known
            and not ctx.is_pending(ACTION_TYPES)
            and not ctx.is_pending(ACTION_TYPE_CONFIRM)
            and budget_left >= 1
        ):
            est = min(
                _TYPE_CONFIRM_ESTIMATE[BUDGET_TIER_DEEP],
                budget_left,
            )
            _take(PlanAction(
                action=ACTION_TYPE_CONFIRM,
                hypothesis=f"types.confirm.{ctx.semantic_type or 'unknown'}",
                estimated_requests=est,
                meta={
                    "semantic_type": ctx.semantic_type or "unknown",
                    "param_name": ctx.param_name or "",
                    "tier": BUDGET_TIER_DEEP,
                },
            ))
        if (
            ctx.analysis_on("validation")
            and ctx.validation_completed_count < 1
            and not ctx.is_pending(ACTION_VALIDATION)
            and not ctx.is_pending(ACTION_SEMANTIC_RULES)
            and budget_left >= 1
        ):
            est = min(
                _SEMANTIC_RULES_ESTIMATE[BUDGET_TIER_DEEP],
                budget_left,
            )
            _take(PlanAction(
                action=ACTION_SEMANTIC_RULES,
                hypothesis=f"semantic.rules.{ctx.semantic_type or 'unknown'}",
                estimated_requests=est,
                meta={
                    "semantic_type": ctx.semantic_type or "unknown",
                    "param_name": ctx.param_name or "",
                    "tier": BUDGET_TIER_DEEP,
                    "max_accepted_length": ctx.max_accepted_length,
                    "include_edge": True,
                },
            ))
        if (
            _parser_probes_needed(ctx, BUDGET_TIER_DEEP)
            and not ctx.is_pending(ACTION_PARSER_PROBES)
            and budget_left >= 1
        ):
            est = min(
                _PARSER_PROBES_ESTIMATE[BUDGET_TIER_DEEP],
                budget_left,
            )
            _take(PlanAction(
                action=ACTION_PARSER_PROBES,
                hypothesis="parser.fingerprint_deep",
                estimated_requests=est,
                meta={
                    "tier": BUDGET_TIER_DEEP,
                    "location": ctx.location or "query",
                    "content_type": ctx.content_type or "",
                    "reflection_state": ctx.reflection_state,
                    "include_unicode": True,
                    "include_double_encode": True,
                },
            ))
        if actions:
            return PlanResult(
                state=STATE_EVALUATE,
                actions=actions,
                done=False,
                reason="deep-tier follow-ups",
                budget_remaining=budget_left,
            )
        return _plan_finalize_or_synthesize(
            ctx, budget_left, reason="deep follow-ups complete → finalize"
        )

    # ── Quick / standard adaptive path ────────────────────────────────────

    # Reflection unknown → extra multiprobe (unique canary, index ≥ 1).
    if (
        ctx.analysis_on("multiprobe")
        and ctx.multiprobe_completed_count >= 1
        and ctx.multiprobe_completed_count < MAX_MULTIPROBE_RETRIES
        and reflection_needs_retry(
            ctx.reflection_state,
            ctx.reflection_confidence,
            ctx.reflection_uncertainty,
        )
        and not ctx.is_pending(ACTION_MULTIPROBE)
        and _can_afford(1)
    ):
        _take(PlanAction(
            action=ACTION_MULTIPROBE,
            hypothesis="multiprobe.retry_reflection_unknown",
            estimated_requests=1,
            meta={"multiprobe_index": ctx.multiprobe_completed_count},
        ))
        return PlanResult(
            state=STATE_EVALUATE,
            actions=actions,
            done=False,
            reason="reflection unknown → extra multiprobe",
            budget_remaining=budget_left,
        )

    if _early_stop_ok(ctx, tier):
        return _plan_finalize_or_synthesize(
            ctx,
            budget_left,
            reason="high-confidence early stop after multiprobe",
        )

    # Standard: length_binary (log seed ≤5, refine ≤2) when length uncertain.
    if (
        tier == BUDGET_TIER_STANDARD
        and _length_search_needed(ctx, BUDGET_TIER_STANDARD)
        and not ctx.is_pending(ACTION_LENGTH_BINARY)
        and not ctx.is_pending(ACTION_LENGTH)
        and budget_left >= 3
    ):
        seed_est = _LENGTH_BINARY_SEED_ESTIMATE[BUDGET_TIER_STANDARD]
        est = min(
            seed_est if ctx.length_completed_count < 1 else 2,
            budget_left,
        )
        _take(PlanAction(
            action=ACTION_LENGTH_BINARY,
            hypothesis=(
                "length.binary_seed"
                if ctx.length_completed_count < 1
                else "length.binary_refine"
            ),
            estimated_requests=est,
            meta={
                "tier": BUDGET_TIER_STANDARD,
                "method": "binary",
                "refine": ctx.length_completed_count >= 1,
            },
        ))

    # Standard: type_confirm when types unknown (passive-first pruned set).
    if (
        tier == BUDGET_TIER_STANDARD
        and ctx.analysis_on("types")
        and ctx.types_completed_count < 1
        and not ctx.types_known
        and not ctx.is_pending(ACTION_TYPE_CONFIRM)
        and not ctx.is_pending(ACTION_TYPES)
        and budget_left >= 2
    ):
        # Skip when multiprobe already gave solid classes + reflection.
        skip_types = (
            ctx.acceptance_class_count >= 3
            and confidence_is_high(
                ctx.reflection_confidence, ctx.reflection_uncertainty
            )
        )
        if not skip_types:
            est = min(
                _TYPE_CONFIRM_ESTIMATE[BUDGET_TIER_STANDARD],
                budget_left,
            )
            _take(PlanAction(
                action=ACTION_TYPE_CONFIRM,
                hypothesis=f"types.confirm.{ctx.semantic_type or 'unknown'}",
                estimated_requests=est,
                meta={
                    "reduced": True,
                    "semantic_type": ctx.semantic_type or "unknown",
                    "param_name": ctx.param_name or "",
                    "tier": BUDGET_TIER_STANDARD,
                },
            ))

    # Standard: semantic_rules (core validation + shallow business rules).
    if (
        tier == BUDGET_TIER_STANDARD
        and ctx.analysis_on("validation")
        and ctx.validation_completed_count < 1
        and not ctx.is_pending(ACTION_SEMANTIC_RULES)
        and not ctx.is_pending(ACTION_VALIDATION)
        and budget_left >= 2
    ):
        skip_sem = (
            ctx.acceptance_class_count >= 3
            and confidence_is_high(
                ctx.reflection_confidence, ctx.reflection_uncertainty
            )
        )
        # M10: inherited tested covers core families → skip semantic wave.
        if not skip_sem and _inheritance_covers_validation(ctx):
            skip_sem = True
        if not skip_sem:
            est = min(
                _SEMANTIC_RULES_ESTIMATE[BUDGET_TIER_STANDARD],
                budget_left,
            )
            # Shrink estimate when some families already inherited as rejected.
            if ctx.inheritance_active and ctx.inherited_tested:
                skip_n = sum(
                    1
                    for e in ctx.inherited_tested.values()
                    if isinstance(e, dict)
                    and str(e.get("outcome") or "").lower() == "rejected"
                )
                est = max(1, est - min(skip_n, est - 1)) if est > 1 else est
            _take(PlanAction(
                action=ACTION_SEMANTIC_RULES,
                hypothesis=f"semantic.rules.{ctx.semantic_type or 'unknown'}",
                estimated_requests=est,
                meta={
                    "semantic_type": ctx.semantic_type or "unknown",
                    "param_name": ctx.param_name or "",
                    "tier": BUDGET_TIER_STANDARD,
                    "max_accepted_length": ctx.max_accepted_length,
                    "include_edge": False,
                    "inherited_tested": dict(ctx.inherited_tested or {}),
                    "suppress_control": bool(ctx.suppress_control_probes),
                },
            ))

    # Standard: parser_probes (dup/null + light normalization) when budget remains.
    if (
        tier == BUDGET_TIER_STANDARD
        and _parser_probes_needed(ctx, BUDGET_TIER_STANDARD)
        and not ctx.is_pending(ACTION_PARSER_PROBES)
        and budget_left >= 2
    ):
        est = min(
            _PARSER_PROBES_ESTIMATE[BUDGET_TIER_STANDARD],
            budget_left,
        )
        if est:
            _take(PlanAction(
                action=ACTION_PARSER_PROBES,
                hypothesis="parser.fingerprint_standard",
                estimated_requests=est,
                meta={
                    "tier": BUDGET_TIER_STANDARD,
                    "location": ctx.location or "query",
                    "content_type": ctx.content_type or "",
                    "reflection_state": ctx.reflection_state,
                    "include_unicode": False,
                    "include_double_encode": False,
                },
            ))

    # Module 6 char_drilldown under standard when inheritance rejected classes
    # still leave room for a short class wave (estimate reduced by inheritance).
    if (
        tier == BUDGET_TIER_STANDARD
        and ctx.analysis_on("characters")
        and ctx.characters_completed_count < 1
        and not ctx.is_pending(ACTION_CHAR_DRILLDOWN)
        and not ctx.is_pending(ACTION_CHARACTERS)
        and budget_left >= 2
        and not _early_stop_ok(ctx, tier)
        and ctx.acceptance_class_count < 3
    ):
        est = min(
            _CHAR_DRILLDOWN_ESTIMATE[BUDGET_TIER_STANDARD],
            budget_left,
        )
        if ctx.inheritance_active and (
            ctx.inherited_rejected_classes or ctx.inherited_accepted_classes
        ):
            known = len(ctx.inherited_rejected_classes) + len(
                ctx.inherited_accepted_classes
            )
            est = max(0, est - known)
        if est >= 2:
            _take(PlanAction(
                action=ACTION_CHAR_DRILLDOWN,
                hypothesis="charset.char_drilldown.inherited_skip",
                estimated_requests=est,
                meta={
                    "tier": BUDGET_TIER_STANDARD,
                    "drilldown": False,
                    "reflection_state": ctx.reflection_state,
                    "inherited_rejected_classes": sorted(
                        ctx.inherited_rejected_classes or []
                    ),
                    "suppress_control": bool(ctx.suppress_control_probes),
                },
            ))

    if actions:
        reason = "standard conditional follow-ups"
        if ctx.inheritance_active:
            reason = (
                f"standard conditional follow-ups "
                f"(inheritance active, ~{ctx.inheritance_reduced_estimate} req saved)"
            )
        return PlanResult(
            state=STATE_EVALUATE,
            actions=actions,
            done=False,
            reason=reason,
            budget_remaining=budget_left,
        )

    # Budget hard stop: no more HTTP; finalize with what we have.
    if remaining < 1:
        return _plan_finalize_or_synthesize(
            ctx, remaining, reason="budget hard stop → finalize"
        )

    return _plan_finalize_or_synthesize(
        ctx, budget_left, reason="no further scan follow-ups → finalize"
    )


def _plan_finalize_or_synthesize(
    ctx: PlanContext,
    remaining: int,
    reason: str,
) -> PlanResult:
    """
    Purpose:
        Schedule 0-HTTP analysis jobs, then synthesize, then done.
        Never schedules finalize before evidence when evidence is still pending.
    Side effects: None.
    """
    # If evidence not ready and something is still pending, wait.
    if not _evidence_ready(ctx):
        if ctx.is_pending(ACTION_BASELINE) or ctx.is_pending(ACTION_MULTIPROBE):
            return PlanResult(
                state=STATE_ENSURE_BASELINE if not ctx.has_completed("baseline") else STATE_MULTIPROBE,
                actions=[],
                done=False,
                reason="waiting for evidence before finalize",
                budget_remaining=remaining,
            )

    actions: list[PlanAction] = []

    if (
        ctx.analysis_on("transformations")
        and not ctx.transformations_done
        and not ctx.is_pending(ACTION_TRANSFORMATIONS)
    ):
        actions.append(PlanAction(
            action=ACTION_TRANSFORMATIONS,
            hypothesis="analysis.transformations",
            estimated_requests=0,
        ))

    if (
        ctx.analysis_on("reflection")
        and ctx.has_endpoint
        and not ctx.reflection_done
        and not ctx.is_pending(ACTION_REFLECTION)
    ):
        actions.append(PlanAction(
            action=ACTION_REFLECTION,
            hypothesis="analysis.reflection",
            estimated_requests=0,
        ))

    if actions:
        return PlanResult(
            state=STATE_FINALIZE,
            actions=actions,
            done=False,
            reason=reason,
            budget_remaining=remaining,
        )

    # Waiting on pending finalize?
    if ctx.is_pending(ACTION_TRANSFORMATIONS) or ctx.is_pending(ACTION_REFLECTION):
        return PlanResult(
            state=STATE_FINALIZE,
            actions=[],
            done=False,
            reason="finalize jobs pending",
            budget_remaining=remaining,
        )

    if not ctx.synthesize_done and not ctx.is_pending(ACTION_SYNTHESIZE):
        return PlanResult(
            state=STATE_SYNTHESIZE,
            actions=[
                PlanAction(
                    action=ACTION_SYNTHESIZE,
                    hypothesis="synthesize.offline_profile",
                    estimated_requests=0,
                )
            ],
            done=False,
            reason="offline profile synthesis",
            budget_remaining=remaining,
        )

    return PlanResult(
        state=STATE_DONE,
        actions=[],
        done=True,
        reason="done",
        budget_remaining=remaining,
    )
