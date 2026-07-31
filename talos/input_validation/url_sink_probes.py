"""
Module: talos.input_validation.url_sink_probes

Purpose:
    URL Sink Discovery Phase 3 — active characterization probes and offline
    synthesis of ``observed.url_sink``.

    Benign canaries only (``.invalid`` TLD, loopback shape, path form).  No
    collaborator/OAST domains, no exploit chains, no Findings.  Capabilities
    and candidate rewrites are Phase 4.

    Design goals (PR-6 / PR-7):
        - Schedule when passive ``url_features`` warrants (network resource
          score/category or semantic_type=url).
        - Standard budget stays small; deep/exhaustive expand protocols.
        - Fingerprint body/header phrases + Location canary reflection +
          soft timing delta into validation/fetch/redirect/DNS signals.
        - Record ``tested.url_sink:*`` outcomes for negative evidence.

Pure computation only — no HTTP, no SQLite.

Dependencies: dataclasses, typing; fingerprint analyzers; outcomes; profile
Data flow:
    planner url_sink_probes → select_url_sink_probes()
    engine expands → scheduler → synthesize_url_sink_state()
        → observed.url_sink + tested.url_sink:*
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from talos.input_validation.fingerprint import (
    CANARY_HOST,
    UrlSinkResponseSignals,
    analyze_url_sink_response,
)
from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_REJECTED,
    OUTCOME_UNKNOWN,
)
from talos.input_validation.profile import (
    UNCERTAINTY_HIGH,
    UNCERTAINTY_LOW,
    UNCERTAINTY_NONE,
    set_tested,
)

# Soft-accept outcomes that also imply the value was *processed* (not ignored).
_PROCESSED_SOFT: frozenset[str] = frozenset({
    OUTCOME_MODIFIED,
    "encoded",
    "normalized",
})

# Error classes that show the server treated the value as a network resource
# (attempted resolve/fetch) even when the HTTP outcome is rejected/modified.
_NETWORK_PROCESS_CLASSES: frozenset[str] = frozenset({
    "dns_lookup_failed",
    "unable_to_fetch",
    "connection_refused",
    "host_unreachable",
    "timeout",
})


# ---------------------------------------------------------------------------
# Constants — canaries (benign characterization only)
# ---------------------------------------------------------------------------

# Fixed canary host on the reserved .invalid TLD (never resolves on the public
# Internet).  Documented as non-exploit characterization.
CANARY_HOST_DEFAULT = CANARY_HOST  # talos-canary.invalid

# Soft-accept outcomes for "app treated this form as a value it understands".
_SOFT_ACCEPT: frozenset[str] = frozenset({
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    "encoded",
    "normalized",
})

# Name categories that warrant URL sink probes even without a high value score.
URL_SINK_WARRANT_CATEGORIES: frozenset[str] = frozenset({
    "redirect",
    "webhook",
    "remote_fetch",
    "remote_asset",
    "import_metadata",
    "infrastructure",
    "network_probe",
    "oauth",
})

# Probe form → (payload_type, payload, form_kind)
# form_kind drives accepts_* synthesis fields.
_FORM_HTTPS = "https_url"
_FORM_HTTP = "http_url"
_FORM_HOSTNAME = "hostname"
_FORM_IPV4 = "ipv4"
_FORM_PATH = "path"
_FORM_FILE = "file"
_FORM_UNC = "unc"
_FORM_FTP = "ftp"
_FORM_GOPHER = "gopher"

# Standard canaries (characterization only).
URL_SINK_STANDARD_PROBES: tuple[tuple[str, str, str], ...] = (
    ("url_sink:https", f"https://{CANARY_HOST_DEFAULT}/", _FORM_HTTPS),
    ("url_sink:http", f"http://{CANARY_HOST_DEFAULT}/", _FORM_HTTP),
    ("url_sink:hostname", CANARY_HOST_DEFAULT, _FORM_HOSTNAME),
    ("url_sink:ipv4_loopback", "127.0.0.1", _FORM_IPV4),
    ("url_sink:path", "/talos-canary", _FORM_PATH),
)

# Deep+ protocol / UNC / file forms (acceptance only — not exploit).
URL_SINK_DEEP_PROBES: tuple[tuple[str, str, str], ...] = (
    ("url_sink:ftp", f"ftp://{CANARY_HOST_DEFAULT}/", _FORM_FTP),
    ("url_sink:gopher", f"gopher://{CANARY_HOST_DEFAULT}/", _FORM_GOPHER),
    ("url_sink:file", f"file://{CANARY_HOST_DEFAULT}/", _FORM_FILE),
    ("url_sink:unc", f"\\\\{CANARY_HOST_DEFAULT}\\share", _FORM_UNC),
)

# Max probes by budget tier.
_URL_SINK_PROBE_CAP: dict[str, int] = {
    "quick": 2,
    "standard": 5,
    "deep": 8,
    "exhaustive": 9,
}

# Payload type → form kind (for synthesis).
PAYLOAD_TYPE_FORM: dict[str, str] = {
    pt: form for pt, _val, form in (URL_SINK_STANDARD_PROBES + URL_SINK_DEEP_PROBES)
}

# Form → accepted_protocols token when soft-accepted.
_FORM_PROTOCOL: dict[str, str | None] = {
    _FORM_HTTPS: "https",
    _FORM_HTTP: "http",
    _FORM_FTP: "ftp",
    _FORM_GOPHER: "gopher",
    _FORM_FILE: "file",
    _FORM_HOSTNAME: None,
    _FORM_IPV4: None,
    _FORM_PATH: None,
    _FORM_UNC: None,
}


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UrlSinkProbeSpec:
    """
    One URL sink characterization probe.

    Fields:
        payload_type — stable label (url_sink:https, …).
        payload      — benign canary string injected into the parameter.
        form_kind    — abstract form for synthesis (https_url, hostname, …).
        hypothesis   — planner / job meta hypothesis fragment.
    """

    payload_type: str
    payload: str
    form_kind: str
    hypothesis: str = ""


@dataclass(frozen=True)
class UrlSinkProbePlan:
    """
    Selected URL sink probes for one parameter.

    Fields:
        probes   — ordered specs.
        reason   — human-readable selection summary.
        skipped  — labels intentionally omitted (tier).
        warranted — whether passive signals justified scheduling.
    """

    probes: tuple[UrlSinkProbeSpec, ...]
    reason: str = ""
    skipped: tuple[str, ...] = ()
    warranted: bool = False


@dataclass
class UrlSinkSynthesisResult:
    """
    Aggregated URL sink characterization (→ observed.url_sink).

    Matches the plan contract for active post-IV url_sink block.  Does **not**
    emit Findings or network_resource_sink capability (Phase 4).
    """

    confidence: int = 0
    uncertainty: str = UNCERTAINTY_HIGH
    accepts_url: bool = False
    accepts_hostname: bool = False
    accepts_ip: bool = False
    accepts_path: bool = False
    accepts_unc: bool = False
    accepts_protocol: bool = False
    accepted_protocols: list[str] = field(default_factory=list)
    requires_absolute: bool = False
    requires_https: bool = False
    dns_resolution_detected: bool = False
    redirect_behavior: bool = False
    fetch_behavior: bool = False
    validation_behavior: str = ""
    error_classes: list[str] = field(default_factory=list)
    per_probe: dict[str, Any] = field(default_factory=dict)
    tested_updates: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    def to_observed_block(self) -> dict[str, Any]:
        """
        Purpose:
            Serialize into the profile ``observed.url_sink`` shape.
        Side effects: None.
        """
        return {
            "confidence": max(0, min(100, int(self.confidence))),
            "uncertainty": self.uncertainty,
            "accepts_url": bool(self.accepts_url),
            "accepts_hostname": bool(self.accepts_hostname),
            "accepts_ip": bool(self.accepts_ip),
            "accepts_path": bool(self.accepts_path),
            "accepts_unc": bool(self.accepts_unc),
            "accepts_protocol": bool(self.accepts_protocol),
            "accepted_protocols": list(self.accepted_protocols),
            "requires_absolute": bool(self.requires_absolute),
            "requires_https": bool(self.requires_https),
            "dns_resolution_detected": bool(self.dns_resolution_detected),
            "redirect_behavior": bool(self.redirect_behavior),
            "fetch_behavior": bool(self.fetch_behavior),
            "validation_behavior": self.validation_behavior or "",
            "error_classes": list(self.error_classes),
            "per_probe": dict(self.per_probe),
            "evidence": list(self.evidence)[:40],
        }


# ---------------------------------------------------------------------------
# Eligibility / warrant
# ---------------------------------------------------------------------------

def url_sink_is_warranted(
    *,
    url_features: dict[str, Any] | None = None,
    semantic_type: str | None = None,
    param_name: str | None = None,
    name_categories: list[str] | None = None,
) -> bool:
    """
    Purpose:
        True when the planner should schedule URL sink canary probes.

        Warranted when any of:
            - passive url_features.possible_network_resource
            - url_features.score >= 45
            - name_category / name_categories intersects warrant set
            - semantic_type == url
            - param_name leaf matches a warrant category via features when
              categories list is provided

    Input:
        url_features    — passive EI document (may be {}).
        semantic_type   — parameters.semantic_type.
        param_name      — unused for matching when categories already known.
        name_categories — optional override list.

    Output: bool.
    Side effects: None.
    """
    uf = url_features if isinstance(url_features, dict) else {}
    if uf.get("possible_network_resource") is True:
        return True
    try:
        if int(uf.get("score") or 0) >= 45:
            return True
    except (TypeError, ValueError):
        pass

    cats: set[str] = set()
    for c in name_categories or []:
        if c:
            cats.add(str(c).lower())
    primary = uf.get("name_category")
    if primary:
        cats.add(str(primary).lower())
    for c in uf.get("name_categories") or []:
        if c:
            cats.add(str(c).lower())

    # If passive features omit categories (partial write / pre-compose row),
    # re-classify the name via the catalog so callback_url etc. still warrant.
    if param_name and not (cats & URL_SINK_WARRANT_CATEGORIES):
        try:
            from talos.url_sink.name_classify import classify_name

            nf = classify_name(param_name)
            if nf.name_category:
                cats.add(str(nf.name_category).lower())
            for c in nf.name_categories or []:
                if c:
                    cats.add(str(c).lower())
        except Exception:
            # Fall back to light token check when catalog unavailable.
            low = (param_name or "").lower().replace("-", "_")
            leaf = low.rsplit(".", 1)[-1]
            strong = (
                "url", "uri", "redirect", "callback", "webhook", "avatar",
                "return_url", "redirect_uri", "base_url", "api_url",
            )
            if leaf in strong or any(
                t in leaf for t in ("url", "uri", "redirect", "webhook", "callback")
            ):
                return True

    if cats & URL_SINK_WARRANT_CATEGORIES:
        return True

    st = (semantic_type or "").strip().lower()
    if st == "url":
        return True

    return False


def empty_url_sink_observed() -> dict[str, Any]:
    """
    Purpose:
        Zeroed observed.url_sink skeleton (stable keys for consumers).
    Side effects: None.
    """
    return UrlSinkSynthesisResult().to_observed_block()


# ---------------------------------------------------------------------------
# Probe selection
# ---------------------------------------------------------------------------

def select_url_sink_probes(
    *,
    strategy: str = "standard",
    url_features: dict[str, Any] | None = None,
    semantic_type: str | None = None,
    param_name: str | None = None,
    max_probes: int | None = None,
    force: bool = False,
) -> UrlSinkProbePlan:
    """
    Purpose:
        Choose a budget-tiered set of benign URL canary probes.

        - quick: 1–2 probes (https + hostname) when warranted
        - standard: full standard set (≤5)
        - deep/exhaustive: + file/ftp/gopher/unc

    Input:
        strategy / url_features / semantic_type / param_name — eligibility.
        max_probes — optional hard cap (overrides tier).
        force — schedule even when not warranted (CLI / tests).

    Output:
        UrlSinkProbePlan (empty probes when not warranted and not force).

    Side effects: None.
    """
    tier = (strategy or "standard").lower().strip()
    warranted = force or url_sink_is_warranted(
        url_features=url_features,
        semantic_type=semantic_type,
        param_name=param_name,
    )
    if not warranted:
        return UrlSinkProbePlan(
            probes=(),
            reason="not warranted (no network-resource signal / category)",
            warranted=False,
        )

    cap = max_probes if max_probes is not None else _URL_SINK_PROBE_CAP.get(tier, 5)
    cap = max(0, int(cap))
    if cap == 0:
        return UrlSinkProbePlan(
            probes=(),
            reason=f"tier={tier} cap=0",
            warranted=True,
            skipped=tuple(pt for pt, _, _ in URL_SINK_STANDARD_PROBES),
        )

    selected_rows: list[tuple[str, str, str]] = []
    skipped: list[str] = []

    if tier == "quick":
        # Prefer absolute URL + hostname forms only.
        for row in URL_SINK_STANDARD_PROBES:
            if row[2] in (_FORM_HTTPS, _FORM_HOSTNAME):
                selected_rows.append(row)
            else:
                skipped.append(row[0])
    else:
        selected_rows.extend(URL_SINK_STANDARD_PROBES)
        if tier in ("deep", "exhaustive"):
            selected_rows.extend(URL_SINK_DEEP_PROBES)
        else:
            skipped.extend(pt for pt, _, _ in URL_SINK_DEEP_PROBES)

    selected_rows = selected_rows[:cap]
    # Anything not selected from the full catalogue counts as skipped.
    all_pts = {pt for pt, _, _ in URL_SINK_STANDARD_PROBES + URL_SINK_DEEP_PROBES}
    selected_pts = {r[0] for r in selected_rows}
    for pt in sorted(all_pts - selected_pts):
        if pt not in skipped:
            skipped.append(pt)

    specs = tuple(
        UrlSinkProbeSpec(
            payload_type=pt,
            payload=val,
            form_kind=form,
            hypothesis=f"url_sink.characterize.{form}",
        )
        for pt, val, form in selected_rows
    )
    reason = (
        f"warranted=true; tier={tier}; n={len(specs)}/{cap}; "
        f"passive_score={(url_features or {}).get('score', '?')}"
    )
    return UrlSinkProbePlan(
        probes=specs,
        reason=reason,
        skipped=tuple(skipped),
        warranted=True,
    )


def estimated_url_sink_probe_count(
    strategy: str = "standard",
    *,
    warranted: bool = True,
) -> int:
    """
    Purpose:
        Planner estimate for url_sink_probes HTTP count.
    Side effects: None.
    """
    if not warranted:
        return 0
    tier = (strategy or "standard").lower().strip()
    return int(_URL_SINK_PROBE_CAP.get(tier, 5))


# ---------------------------------------------------------------------------
# Synthesis from probe rows
# ---------------------------------------------------------------------------

def synthesize_url_sink_state(
    rows: list[dict[str, Any]],
    *,
    baseline_duration_ms: float | None = None,
    canary_host: str = CANARY_HOST_DEFAULT,
) -> UrlSinkSynthesisResult:
    """
    Purpose:
        Aggregate completed url_sink probe outcomes + response signals into
        ``observed.url_sink`` (characterization only).

    Input:
        rows — list of probe summary dicts with keys:
            payload_type, payload, outcome, confidence, body, status_code,
            response_headers (dict|str|None), duration_ms, flow_id,
            redirect (optional Location summary), error_signature (optional).
        baseline_duration_ms — optional baseline timing for fetch soft-signal.
        canary_host — expected canary host in Location / body phrases.

    Output:
        UrlSinkSynthesisResult.

    Side effects: None.
    """
    result = UrlSinkSynthesisResult()
    if not rows:
        return result

    accepted_forms: set[str] = set()
    rejected_forms: set[str] = set()
    protocols: list[str] = []
    error_classes: list[str] = []
    validation_hits: list[str] = []
    evidence: list[str] = []
    confidences: list[int] = []
    any_dns = False
    any_redirect = False
    any_fetch = False

    for row in rows:
        if not isinstance(row, dict):
            continue
        ptype = str(row.get("payload_type") or "")
        if not ptype.startswith("url_sink:"):
            # Tolerate bare labels.
            if ptype and not ptype.startswith("url_sink"):
                ptype = f"url_sink:{ptype}" if ":" not in ptype else ptype
        form = PAYLOAD_TYPE_FORM.get(ptype) or _infer_form_from_payload(
            str(row.get("payload") or "")
        )
        outcome = str(row.get("outcome") or OUTCOME_UNKNOWN)
        conf = int(row.get("confidence") or 0)
        confidences.append(conf)
        payload = str(row.get("payload") or "")
        body = str(row.get("body") or "")
        status = row.get("status_code")
        try:
            status_i = int(status) if status is not None else None
        except (TypeError, ValueError):
            status_i = None
        duration = row.get("duration_ms")
        try:
            duration_f = float(duration) if duration is not None else None
        except (TypeError, ValueError):
            duration_f = None

        signals = analyze_url_sink_response(
            body=body,
            status_code=status_i,
            response_headers=row.get("response_headers"),
            redirect=row.get("redirect"),
            error_signature=row.get("error_signature"),
            payload=payload,
            canary_host=canary_host,
            baseline_duration_ms=baseline_duration_ms,
            probe_duration_ms=duration_f,
        )

        entry: dict[str, Any] = {
            "outcome": outcome,
            "confidence": conf,
            "form_kind": form,
            "error_classes": list(signals.error_classes),
            "redirect_behavior": signals.redirect_behavior,
            "fetch_behavior": signals.fetch_behavior,
            "dns_resolution_detected": signals.dns_resolution_detected,
            "validation_behavior": signals.validation_behavior,
            "evidence_flow_ids": (
                [row["flow_id"]] if row.get("flow_id") else []
            ),
        }
        result.per_probe[ptype or form] = entry

        # tested{} always records the family.
        tested_key = ptype if ptype.startswith("url_sink:") else f"url_sink:{form}"
        result.tested_updates[tested_key] = {
            "outcome": outcome,
            "confidence": conf,
            "evidence_flow_ids": entry["evidence_flow_ids"],
        }

        if signals.error_classes:
            for ec in signals.error_classes:
                if ec not in error_classes:
                    error_classes.append(ec)
        if signals.validation_behavior:
            validation_hits.append(signals.validation_behavior)
        if signals.dns_resolution_detected:
            any_dns = True
            evidence.append(f"dns:{ptype}")
        if signals.redirect_behavior:
            any_redirect = True
            evidence.append(f"redirect:{ptype}")
        if signals.fetch_behavior:
            any_fetch = True
            evidence.append(f"fetch:{ptype}")
        if signals.canary_in_location:
            evidence.append(f"location_canary:{ptype}")
        if signals.canary_in_body:
            evidence.append(f"body_canary:{ptype}")

        # Form acceptance requires evidence the value was *processed* as a
        # network resource — not a pure fingerprint-identical soft-accept
        # (server ignored the mutation).  Network error phrases count when the
        # response is error-like (status ≥ 400 or rejected/modified outcome).
        if _form_counts_as_accepted(outcome, signals, status_code=status_i):
            accepted_forms.add(form)
            proto = _FORM_PROTOCOL.get(form)
            if proto and proto not in protocols:
                protocols.append(proto)
            evidence.append(f"accept:{ptype}")
        elif outcome == OUTCOME_REJECTED:
            rejected_forms.add(form)
            evidence.append(f"reject:{ptype}")
        elif outcome in _SOFT_ACCEPT:
            # Weak soft-accept (identical baseline, no URL signals) — inventory
            # only under per_probe; do not set accepts_*.
            evidence.append(f"weak_accept:{ptype}")

    # ── Derive accepts_* flags ───────────────────────────────────────────
    result.accepts_url = bool(
        accepted_forms & {_FORM_HTTPS, _FORM_HTTP, _FORM_FTP, _FORM_GOPHER, _FORM_FILE}
    )
    result.accepts_hostname = _FORM_HOSTNAME in accepted_forms
    result.accepts_ip = _FORM_IPV4 in accepted_forms
    result.accepts_path = _FORM_PATH in accepted_forms
    result.accepts_unc = _FORM_UNC in accepted_forms
    result.accepted_protocols = protocols
    result.accepts_protocol = bool(protocols)

    # Absolute required: absolute schemes accepted but path/hostname rejected.
    abs_ok = bool(accepted_forms & {_FORM_HTTPS, _FORM_HTTP})
    non_abs_rejected = (
        (_FORM_HOSTNAME in rejected_forms or _FORM_PATH in rejected_forms)
        and abs_ok
        and _FORM_HOSTNAME not in accepted_forms
        and _FORM_PATH not in accepted_forms
    )
    result.requires_absolute = non_abs_rejected

    # HTTPS-only: https accepted, http rejected.
    if (
        _FORM_HTTPS in accepted_forms
        and _FORM_HTTP in rejected_forms
        and _FORM_HTTP not in accepted_forms
    ):
        result.requires_https = True

    result.dns_resolution_detected = any_dns
    result.redirect_behavior = any_redirect
    result.fetch_behavior = any_fetch
    result.error_classes = error_classes
    if validation_hits:
        # Prefer most specific / first stable label.
        result.validation_behavior = validation_hits[0]
    elif error_classes and not (result.accepts_url or result.accepts_hostname):
        result.validation_behavior = "url_error_phrase"
    result.evidence = list(dict.fromkeys(evidence))

    # Confidence / uncertainty.
    n = len(rows)
    soft_n = sum(
        1 for r in rows
        if str(r.get("outcome") or "") in _SOFT_ACCEPT
    )
    reject_n = sum(
        1 for r in rows
        if str(r.get("outcome") or "") == OUTCOME_REJECTED
    )
    signal_boost = 0
    if any_redirect:
        signal_boost += 10
    if any_dns or any_fetch:
        signal_boost += 10
    if error_classes:
        signal_boost += 5
    base = 40
    if n:
        base = 45 + min(30, n * 5)
    if soft_n or reject_n:
        # Characterized either way.
        base = max(base, 55 + min(25, (soft_n + reject_n) * 4))
    result.confidence = max(0, min(100, base + signal_boost))
    if confidences:
        result.confidence = max(
            result.confidence,
            min(95, int(sum(confidences) / len(confidences))),
        )
    if result.confidence >= 90 and n >= 3:
        result.uncertainty = UNCERTAINTY_NONE
    elif result.confidence >= 60:
        result.uncertainty = UNCERTAINTY_LOW
    else:
        result.uncertainty = UNCERTAINTY_HIGH

    return result


def apply_url_sink_synthesis_to_profile(
    profile: dict[str, Any],
    synth: UrlSinkSynthesisResult,
) -> None:
    """
    Purpose:
        Write ``observed.url_sink`` and ``tested.url_sink:*`` into a profile.
    Side effects: Mutates profile.
    """
    if not isinstance(profile.get("observed"), dict):
        profile["observed"] = {}
    profile["observed"]["url_sink"] = synth.to_observed_block()

    for key, entry in synth.tested_updates.items():
        if not isinstance(entry, dict):
            continue
        set_tested(
            profile,
            key,
            outcome=str(entry.get("outcome") or OUTCOME_UNKNOWN),
            confidence=int(entry.get("confidence") or 0),
            evidence_flow_ids=entry.get("evidence_flow_ids"),
        )


def _form_counts_as_accepted(
    outcome: str,
    signals: UrlSinkResponseSignals,
    *,
    status_code: int | None = None,
) -> bool:
    """
    Purpose:
        True when a probe outcome is strong enough to set accepts_* for a form.

        Pure ``accepted`` with identical-to-baseline fingerprint and no URL
        processing signals is **not** enough (server may have ignored the
        mutation).  Require a strong URL signal:

            - Location / body canary reflection, or
            - network-process error phrases (DNS/fetch/timeout) on an
              error-like response (status ≥ 400 or rejected/modified outcome)

        Soft-accept alone (including modified without URL signals) does not
        set accepts_*.  Timing-only fetch_behavior does not set accepts_*.

    Side effects: None.
    """
    classes = set(signals.error_classes or ())
    network_phrase = bool(classes & _NETWORK_PROCESS_CLASSES) or bool(
        signals.dns_resolution_detected
    )
    try:
        status_err = status_code is not None and int(status_code) >= 400
    except (TypeError, ValueError):
        status_err = False

    canary = bool(
        signals.redirect_behavior
        or signals.canary_in_body
        or signals.canary_in_location
    )
    # Phrases in 2xx HTML/docs (e.g. "connection timeout" help text) are noise.
    network_strong = network_phrase and (
        status_err
        or outcome == OUTCOME_REJECTED
        or outcome in _PROCESSED_SOFT
    )
    strong = canary or network_strong
    if not strong:
        return False
    if outcome in _SOFT_ACCEPT or outcome == OUTCOME_REJECTED:
        return True
    return False


def _infer_form_from_payload(payload: str) -> str:
    """Best-effort form_kind when payload_type is missing."""
    v = (payload or "").strip()
    if not v:
        return "unknown"
    low = v.lower()
    if low.startswith("https://"):
        return _FORM_HTTPS
    if low.startswith("http://"):
        return _FORM_HTTP
    if low.startswith("ftp://"):
        return _FORM_FTP
    if low.startswith("gopher://"):
        return _FORM_GOPHER
    if low.startswith("file:"):
        return _FORM_FILE
    if v.startswith("\\\\") or v.startswith("//"):
        return _FORM_UNC
    if v.startswith("/"):
        return _FORM_PATH
    if v.replace(".", "").isdigit() and v.count(".") == 3:
        return _FORM_IPV4
    # hostname-ish
    if "." in v and "://" not in v and " " not in v:
        return _FORM_HOSTNAME
    try:
        p = urlparse(v)
        if p.scheme and p.netloc:
            return f"{p.scheme}_url" if p.scheme in ("http", "https") else p.scheme
    except Exception:
        pass
    return "unknown"
