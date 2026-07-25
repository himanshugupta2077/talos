"""
Module: talos.input_validation.multiprobe

Purpose:
    Module 4 — Canaries & Multiprobe (multi-signal, fewer requests).

    Builds high-entropy canary markers and multiplexed probe payloads so a
    single HTTP request can answer:

        - Is the value reflected (and with which encoding / transforms)?
        - Which character taxonomy classes appear to survive?

    Characterization only — no exploit payloads.  All real HTTP still goes
    through the scheduler + replay engine; this module is pure computation.

Design rules
    - Separators never appear inside class samples.
    - Payload is self-describing so synthesis can re-analyze from body alone.
    - When nothing is reflected, class survival is inferred only from fingerprint
      delta (lower confidence) — callers attach that via ``reflected=False``.
    - Canaries use a stable prefix (default ``TL``) plus high-entropy hex so
      they do not collide with common static page content.

Dependencies: secrets, re, urllib.parse (stdlib); profile CHARSET_CLASSES;
              taxonomy (Module 6 class representatives)
Data flow:
    build_multiprobe_payload() → payload string + MultiprobePlan
    scheduler injects payload → one flow
    analyze_multiprobe_response(plan|payload, body) → reflection + per-class
    synthesize folds multiprobe_classes into observed.acceptance.classes
Side effects: None.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import quote

from talos.input_validation.profile import CHARSET_CLASSES
from talos.input_validation.taxonomy import multiprobe_default_samples


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default canary prefix (project-configurable via build_canary / config later).
DEFAULT_CANARY_PREFIX = "TL"

# Entropy length in random hex characters (8 bytes → 16 hex).
DEFAULT_CANARY_HEX_LEN = 16

# Multi-character separator: must not appear in any class sample below.
# Avoid single punctuation used in injection classes (quotes, <, /, etc.).
MULTIPROBE_SEPARATOR = "~^~"

# Tagged fragment: CLASS=sample  (sample is one char or short token).
# Class names are taxonomy labels from CHARSET_CLASSES.
_FRAGMENT_RE = re.compile(
    r"^([a-z_]+)=(.*)$",
    re.DOTALL,
)

# Representative samples for taxonomy classes used in the default multiprobe.
# Anchored to Module 6 taxonomy.CLASS_SPECS so multiprobe and char_drilldown
# share the same class anchors.  Samples must not contain MULTIPROBE_SEPARATOR
# or "=" (tag delimiter).
DEFAULT_CLASS_SAMPLES: tuple[tuple[str, str], ...] = multiprobe_default_samples()

# Operator sample uses "=" which conflicts with CLASS=sample parsing.
# Encode as a single-char sample via a safe alias when needed.
_SAFE_OPERATOR_SAMPLE = "+"
_SAFE_COMMENT_SAMPLE = "#"


def _normalized_class_samples(
    samples: tuple[tuple[str, str], ...] | None = None,
) -> list[tuple[str, str]]:
    """
    Purpose:
        Resolve class samples for multiprobe, fixing separator / tag conflicts.
    Side effects: None.
    """
    raw = list(samples) if samples is not None else list(DEFAULT_CLASS_SAMPLES)
    out: list[tuple[str, str]] = []
    for cls, sample in raw:
        if cls not in CHARSET_CLASSES:
            continue
        if sample == "=" or MULTIPROBE_SEPARATOR in sample:
            if cls == "operator":
                sample = _SAFE_OPERATOR_SAMPLE
            elif cls == "comment":
                sample = _SAFE_COMMENT_SAMPLE
            else:
                # Drop unsafe samples rather than corrupt the payload grammar.
                continue
        out.append((cls, sample))
    return out


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MultiprobeFragment:
    """One taxonomy class sample embedded in a multiprobe payload."""

    class_name: str
    sample: str
    index: int


@dataclass
class MultiprobePlan:
    """
    Self-describing multiprobe plan.

    Fields:
        canary       — high-entropy marker (also appears left + right of body).
        separator    — fragment delimiter (default MULTIPROBE_SEPARATOR).
        fragments    — ordered class samples.
        payload      — full string injected into the parameter.
        prefix       — canary prefix used (e.g. TL).
    """

    canary: str
    separator: str
    fragments: list[MultiprobeFragment] = field(default_factory=list)
    payload: str = ""
    prefix: str = DEFAULT_CANARY_PREFIX

    def to_dict(self) -> dict[str, Any]:
        """Serialize for flow_meta / tests. Side effects: None."""
        return {
            "canary": self.canary,
            "separator": self.separator,
            "prefix": self.prefix,
            "payload": self.payload,
            "fragments": [
                {
                    "class_name": f.class_name,
                    "sample": f.sample,
                    "index": f.index,
                }
                for f in self.fragments
            ],
            "classes": [f.class_name for f in self.fragments],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MultiprobePlan":
        """
        Purpose:
            Rebuild a plan from flow_meta or stored JSON.
        Side effects: None.
        """
        frags = [
            MultiprobeFragment(
                class_name=str(item.get("class_name") or item.get("class") or ""),
                sample=str(item.get("sample") or ""),
                index=int(item.get("index") or i),
            )
            for i, item in enumerate(data.get("fragments") or [])
        ]
        return cls(
            canary=str(data.get("canary") or ""),
            separator=str(data.get("separator") or MULTIPROBE_SEPARATOR),
            fragments=frags,
            payload=str(data.get("payload") or ""),
            prefix=str(data.get("prefix") or DEFAULT_CANARY_PREFIX),
        )


@dataclass
class ClassSurvivalResult:
    """Per-class survival observation from one multiprobe response."""

    class_name: str
    sample: str
    survived: bool
    encoding: str  # raw | html_encoded | url_encoded | ""
    transforms: list[str]
    confidence: int
    outcome: str  # accepted | rejected | modified | encoded | normalized | unknown


@dataclass
class MultiprobeAnalysis:
    """Full multiprobe response analysis (reflection + class outcomes)."""

    canary_reflected: bool
    canary_encoding: str
    canary_transforms: list[str]
    location: str  # html|json|xml|javascript|other|""
    classes: list[ClassSurvivalResult]
    multiprobe_classes: list[str]  # classes with positive survival (compat hook)
    class_outcomes: dict[str, dict[str, Any]]
    confidence_reflection: int
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for tests / optional storage. Side effects: None."""
        return {
            "canary_reflected": self.canary_reflected,
            "canary_encoding": self.canary_encoding,
            "canary_transforms": list(self.canary_transforms),
            "location": self.location,
            "classes": [asdict(c) for c in self.classes],
            "multiprobe_classes": list(self.multiprobe_classes),
            "class_outcomes": dict(self.class_outcomes),
            "confidence_reflection": self.confidence_reflection,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Canary generation
# ---------------------------------------------------------------------------

def generate_canary(
    prefix: str = DEFAULT_CANARY_PREFIX,
    hex_len: int = DEFAULT_CANARY_HEX_LEN,
    *,
    avoid_in: str | None = None,
    max_attempts: int = 8,
) -> str:
    """
    Purpose:
        Create a unique high-entropy canary marker.

    Input:
        prefix       — leading marker (default ``TL``).
        hex_len      — number of hex characters of entropy (even, >= 8).
        avoid_in     — optional text the canary must not appear in (e.g. page
                       body); regenerate on collision.
        max_attempts — regeneration limit when avoid_in is set.

    Output:
        Canary string, e.g. ``TLa1b2c3d4e5f67890``.

    Side effects: Reads OS entropy via secrets.
    """
    if hex_len < 8:
        hex_len = 8
    if hex_len % 2:
        hex_len += 1
    nbytes = hex_len // 2
    safe_prefix = prefix or DEFAULT_CANARY_PREFIX

    for _ in range(max(1, max_attempts)):
        canary = f"{safe_prefix}{secrets.token_hex(nbytes)}"
        if avoid_in is None or canary not in avoid_in:
            return canary
    # Extremely unlikely full-collision path: append extra entropy.
    return f"{safe_prefix}{secrets.token_hex(nbytes)}{secrets.token_hex(4)}"


def canary_collides(canary: str, text: str) -> bool:
    """
    Purpose:
        True when canary already appears in text (static collision risk).
    Side effects: None.
    """
    if not canary or not text:
        return False
    return canary in text


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------

def class_samples_for_location(
    location: str = "query",
    samples: tuple[tuple[str, str], ...] | None = None,
) -> list[tuple[str, str]]:
    """
    Purpose:
        Location-aware multiprobe class samples.

        Header/cookie inject goes through the HTTP client header stack, which
        rejects NUL and other CTL octets.  Those classes are omitted so the
        multiprobe still characterizes legal character classes without
        ``Illegal header value`` transport failures.
    Side effects: None.
    """
    from talos.input_validation.surface import (
        COOKIE_UNSAFE_TAXONOMY_CLASSES,
        HEADER_UNSAFE_TAXONOMY_CLASSES,
        LOCATION_COOKIE,
        LOCATION_HEADER,
    )

    base = _normalized_class_samples(samples)
    loc = (location or "query").strip().lower()
    if loc == LOCATION_HEADER:
        ban = HEADER_UNSAFE_TAXONOMY_CLASSES
    elif loc == LOCATION_COOKIE:
        ban = COOKIE_UNSAFE_TAXONOMY_CLASSES
    else:
        return base
    return [(cls, sample) for cls, sample in base if cls not in ban]


def build_multiprobe_payload(
    *,
    prefix: str = DEFAULT_CANARY_PREFIX,
    separator: str = MULTIPROBE_SEPARATOR,
    class_samples: tuple[tuple[str, str], ...] | None = None,
    canary: str | None = None,
    avoid_in: str | None = None,
    location: str = "query",
) -> MultiprobePlan:
    """
    Purpose:
        Build one multiplexed probe string embedding a canary and taxonomy
        class samples with unambiguous separators.

    Payload grammar (self-describing)::

        {canary}{SEP}{class}={sample}{SEP}...{SEP}{canary}

    Input:
        prefix / separator / class_samples — structure knobs.
        canary   — optional fixed canary (tests); else generated.
        avoid_in — optional body text to avoid canary collision with.
        location — injection location; header/cookie drop null/control samples.

    Output:
        MultiprobePlan with ``payload`` ready for injection.

    Side effects: May read OS entropy when generating a canary.
    """
    sep = separator or MULTIPROBE_SEPARATOR
    # Location-aware: header/cookie omit null/control samples so the payload
    # remains a legal HTTP header field-value for h11/httpx.
    resolved = class_samples_for_location(location, class_samples)
    token = canary or generate_canary(prefix=prefix, avoid_in=avoid_in)

    fragments: list[MultiprobeFragment] = []
    parts: list[str] = [token]
    for idx, (cls, sample) in enumerate(resolved):
        fragments.append(MultiprobeFragment(class_name=cls, sample=sample, index=idx))
        # Escape separator inside sample (should not occur after normalize).
        safe_sample = sample.replace(sep, "")
        parts.append(f"{cls}={safe_sample}")
    parts.append(token)

    payload = sep.join(parts)
    return MultiprobePlan(
        canary=token,
        separator=sep,
        fragments=fragments,
        payload=payload,
        prefix=prefix,
    )


def parse_multiprobe_payload(payload: str, separator: str = MULTIPROBE_SEPARATOR) -> MultiprobePlan | None:
    """
    Purpose:
        Recover a MultiprobePlan from a stored payload string.
        Returns None if the string does not match multiprobe grammar.

    Side effects: None.
    """
    if not payload or separator not in payload:
        return None
    parts = payload.split(separator)
    if len(parts) < 3:
        return None
    left = parts[0]
    right = parts[-1]
    if not left or left != right:
        # Allow asymmetric only if both look like canaries with same prefix.
        if not (left and right and left[:2] == right[:2]):
            return None
        # Prefer left as canonical canary.
    canary = left
    fragments: list[MultiprobeFragment] = []
    for i, part in enumerate(parts[1:-1]):
        m = _FRAGMENT_RE.match(part)
        if not m:
            continue
        cls, sample = m.group(1), m.group(2)
        if cls not in CHARSET_CLASSES:
            continue
        fragments.append(MultiprobeFragment(class_name=cls, sample=sample, index=i))
    if not fragments:
        return None
    prefix = "TL"
    if canary.startswith("TL"):
        prefix = "TL"
    elif len(canary) >= 2 and canary[:2].isalpha():
        prefix = canary[:2]
    return MultiprobePlan(
        canary=canary,
        separator=separator,
        fragments=fragments,
        payload=payload,
        prefix=prefix,
    )


# ---------------------------------------------------------------------------
# Response analyzer
# ---------------------------------------------------------------------------

def _html_encode(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _find_encoded_forms(value: str, body: str) -> tuple[bool, str, list[str]]:
    """
    Purpose:
        Detect value in body as raw / html / url and simple transforms.
    Output:
        (found, encoding, transforms)
    Side effects: None.
    """
    if not value or not body:
        return False, "", []

    transforms: list[str] = []

    if value in body:
        return True, "raw", []

    html = _html_encode(value)
    if html in body:
        return True, "html_encoded", []

    url = quote(value, safe="")
    if url and url in body:
        return True, "url_encoded", []

    stripped = value.strip()
    if stripped and stripped != value and stripped in body:
        return True, "raw", ["trim"]

    lower = value.lower()
    if lower != value and lower in body:
        return True, "raw", ["lowercase"]

    upper = value.upper()
    if upper != value and upper in body:
        return True, "raw", ["uppercase"]

    if stripped:
        if stripped.lower() in body and stripped.lower() != stripped:
            return True, "raw", ["trim", "lowercase"]
        if stripped.upper() in body and stripped.upper() != stripped:
            return True, "raw", ["trim", "uppercase"]
        html_s = _html_encode(stripped)
        if html_s in body:
            return True, "html_encoded", ["trim"]

    return False, "", transforms


def _infer_location(content_type: str) -> str:
    ct = (content_type or "").lower()
    if "html" in ct:
        return "html"
    if "json" in ct:
        return "json"
    if "xml" in ct:
        return "xml"
    if "javascript" in ct:
        return "javascript"
    if ct:
        return "other"
    return ""


def analyze_multiprobe_response(
    plan_or_payload: MultiprobePlan | str,
    body: str,
    content_type: str = "",
    *,
    fingerprint_outcome: str | None = None,
    fingerprint_confidence: int | None = None,
) -> MultiprobeAnalysis:
    """
    Purpose:
        Analyze a response body against a multiprobe plan/payload.

        When the canary is reflected, per-class sample survival is high-
        confidence.  When nothing is reflected, class outcomes fall back to
        optional fingerprint_outcome (accept/reject of the whole probe) with
        reduced confidence — charset survival cannot be claimed.

    Input:
        plan_or_payload       — MultiprobePlan or payload string.
        body / content_type   — response.
        fingerprint_outcome   — optional whole-probe outcome from M1 classifier.
        fingerprint_confidence — optional 0–100 from classifier.

    Output:
        MultiprobeAnalysis with reflection + per-class results.

    Side effects: None.
    """
    if isinstance(plan_or_payload, MultiprobePlan):
        plan = plan_or_payload
    else:
        plan = parse_multiprobe_payload(str(plan_or_payload or ""))
        if plan is None:
            return MultiprobeAnalysis(
                canary_reflected=False,
                canary_encoding="",
                canary_transforms=[],
                location="",
                classes=[],
                multiprobe_classes=[],
                class_outcomes={},
                confidence_reflection=0,
                notes=["unparseable multiprobe payload"],
            )

    body = body or ""
    location = _infer_location(content_type)
    notes: list[str] = []

    canary_found, canary_enc, canary_tx = _find_encoded_forms(plan.canary, body)
    conf_refl = 0
    if canary_found:
        conf_refl = 92 if canary_enc == "raw" else 88
        if canary_tx:
            conf_refl = max(70, conf_refl - 5)
    else:
        # Full payload reflection without isolated canary is still a signal.
        if plan.payload and plan.payload in body:
            canary_found = True
            canary_enc = "raw"
            conf_refl = 80
            notes.append("full payload reflected; canary not isolated")
        else:
            conf_refl = 70 if fingerprint_outcome == "rejected" else 55
            notes.append("canary not reflected")

    class_results: list[ClassSurvivalResult] = []
    multiprobe_classes: list[str] = []
    class_outcomes: dict[str, dict[str, Any]] = {}

    for frag in plan.fragments:
        sample = frag.sample
        # Null byte rarely appears literally; also check URL / unicode escapes.
        found, enc, txs = _find_encoded_forms(sample, body)
        if not found and sample == "\x00":
            if "%00" in body or "\\u0000" in body or "\\x00" in body:
                found, enc, txs = True, "url_encoded", []

        if canary_found:
            if found:
                if enc in ("html_encoded", "url_encoded"):
                    outcome = "encoded"
                    conf = 85
                elif txs:
                    outcome = "normalized"
                    conf = 80
                else:
                    outcome = "accepted"
                    conf = 90
                multiprobe_classes.append(frag.class_name)
            else:
                # Canary reflected but this sample missing → filtered/rejected.
                outcome = "rejected"
                conf = 82
        else:
            # No reflection: cannot claim per-char survival.
            # Map whole-probe fingerprint only as weak class signal.
            if fingerprint_outcome == "rejected":
                outcome = "rejected"
                conf = min(55, int(fingerprint_confidence or 45))
                notes.append(f"{frag.class_name}: no reflection; fingerprint rejected")
            elif fingerprint_outcome in ("accepted", "modified", "ignored"):
                outcome = "unknown"
                conf = min(40, int(fingerprint_confidence or 30))
                notes.append(f"{frag.class_name}: no reflection; charset unknown")
            else:
                outcome = "unknown"
                conf = 25
            found = False
            enc = ""
            txs = []

        result = ClassSurvivalResult(
            class_name=frag.class_name,
            sample=sample,
            survived=bool(found and canary_found),
            encoding=enc,
            transforms=list(txs),
            confidence=conf,
            outcome=outcome,
        )
        class_results.append(result)
        class_outcomes[frag.class_name] = {
            "outcome": outcome,
            "confidence": conf,
            "survived": result.survived,
            "encoding": enc,
            "transforms": list(txs),
            "sample": sample,
            "source": "multiprobe",
        }

    return MultiprobeAnalysis(
        canary_reflected=canary_found,
        canary_encoding=canary_enc,
        canary_transforms=list(canary_tx),
        location=location,
        classes=class_results,
        multiprobe_classes=multiprobe_classes,
        class_outcomes=class_outcomes,
        confidence_reflection=conf_refl,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Identifier canaries (replace weak fixed tokens outside deep/exhaustive)
# ---------------------------------------------------------------------------

# Legacy weak identifiers kept only for deep/exhaustive strategies.
LEGACY_WEAK_IDENTIFIERS: tuple[str, ...] = (
    "123456",
    "987654",
    "135790",
    "abcdef",
    "ABCDEF",
    "AbCdEf",
    "abc123",
    "ABC123",
    "a1b2c3",
)


def build_canary_identifier_probes(
    count: int = 3,
    *,
    prefix: str = DEFAULT_CANARY_PREFIX,
) -> list[str]:
    """
    Purpose:
        Produce ``count`` unique high-entropy canary strings for the
        identifier phase (default / standard path).

    Side effects: Reads OS entropy.
    """
    n = max(1, min(count, 9))
    seen: set[str] = set()
    out: list[str] = []
    while len(out) < n:
        c = generate_canary(prefix=prefix)
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def identifier_probes_for_strategy(
    strategy: str,
    *,
    prefix: str = DEFAULT_CANARY_PREFIX,
) -> list[str]:
    """
    Purpose:
        Select identifier probe list by probe_strategy.

        - quick / standard: high-entropy canaries only (no weak fixed tokens)
        - deep: several canaries (no weak list)
        - exhaustive: legacy weak list + canaries (escape hatch)

    Side effects: May read OS entropy.
    """
    s = (strategy or "standard").lower().strip()
    if s == "exhaustive":
        canaries = build_canary_identifier_probes(2, prefix=prefix)
        return list(LEGACY_WEAK_IDENTIFIERS) + canaries
    if s == "deep":
        return build_canary_identifier_probes(5, prefix=prefix)
    if s == "quick":
        return build_canary_identifier_probes(1, prefix=prefix)
    # standard
    return build_canary_identifier_probes(2, prefix=prefix)
