"""
Module: talos.scheduler.testing_windows

Purpose:
    IST testing-window gate for the replay scheduler.

    When enabled, the scheduler holds *all* outbound job execution and
    auto-enqueue (IV / unauth) until the current India Standard Time falls
    inside at least one configured window.  Capture, review, and enqueue
    still work at any hour — only scheduler-sent HTTP is deferred.

    Timezone is always IST (UTC+05:30, no DST).  Windows are 24-hour
    ``HH:MM-HH:MM`` ranges.  An overnight range such as ``22:00-06:00``
    wraps midnight.

Dependencies: datetime
Data flow:
    scheduler loop / CLI / status → evaluate() → allow or hold
Side effects: None (pure).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Iterable, Sequence

# India Standard Time is UTC+05:30 year-round (no DST).
IST = timezone(timedelta(hours=5, minutes=30), name="IST")

_WINDOW_SEP = "-"


class WindowParseError(ValueError):
    """Invalid testing-window string."""


def now_ist(now: datetime | None = None) -> datetime:
    """
    Purpose:
        Return ``now`` converted to IST.  Naive datetimes are treated as UTC.
    """
    if now is None:
        return datetime.now(IST)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(IST)


def parse_hhmm(raw: str) -> time:
    """
    Purpose:
        Parse a 24-hour ``HH:MM`` clock value.
    """
    text = (raw or "").strip()
    parts = text.split(":")
    if len(parts) != 2:
        raise WindowParseError(f"Time '{text}' must be HH:MM (24-hour IST).")
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError as exc:
        raise WindowParseError(f"Time '{text}' must be HH:MM (24-hour IST).") from exc
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        raise WindowParseError(f"Time '{text}' is out of range (00:00–23:59).")
    return time(hour, minute)


def parse_window(raw: str) -> tuple[time, time]:
    """
    Purpose:
        Parse one ``HH:MM-HH:MM`` IST window.
        Start equals end is rejected (that is not a 24-hour window).
    """
    text = (raw or "").strip()
    if not text:
        raise WindowParseError("Window must be HH:MM-HH:MM (IST).")
    # Allow "09:00 - 18:00".
    cleaned = text.replace(" ", "")
    if cleaned.count(_WINDOW_SEP) != 1:
        raise WindowParseError(
            f"Window '{text}' must be HH:MM-HH:MM (IST), e.g. 09:00-18:00."
        )
    start_raw, end_raw = cleaned.split(_WINDOW_SEP, 1)
    start = parse_hhmm(start_raw)
    end = parse_hhmm(end_raw)
    if start == end:
        raise WindowParseError(
            f"Window '{text}' start and end are the same — use a real range."
        )
    return start, end


def format_window(start: time, end: time) -> str:
    """Canonical ``HH:MM-HH:MM`` form."""
    return f"{start.strftime('%H:%M')}-{end.strftime('%H:%M')}"


def normalize_windows(raw_windows: Iterable[object]) -> tuple[str, ...]:
    """
    Purpose:
        Validate and canonicalize a list of window strings.
        Duplicates are dropped; order is preserved.
    """
    seen: set[str] = set()
    out: list[str] = []
    for item in raw_windows:
        if item is None:
            continue
        start, end = parse_window(str(item))
        key = format_window(start, end)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return tuple(out)


def _clock(moment: datetime) -> time:
    return time(moment.hour, moment.minute, moment.second, moment.microsecond)


def window_contains(start: time, end: time, clock: time) -> bool:
    """
    Purpose:
        Inclusive start, exclusive end.  Overnight windows wrap midnight.
    """
    if start < end:
        return start <= clock < end
    return clock >= start or clock < end


def in_any_window(windows: Sequence[str], *, now: datetime | None = None) -> bool:
    """True when IST ``now`` falls inside at least one window."""
    if not windows:
        return False
    clock = _clock(now_ist(now))
    for raw in windows:
        start, end = parse_window(raw)
        if window_contains(start, end, clock):
            return True
    return False


def allows_execution(
    enabled: bool,
    windows: Sequence[str],
    *,
    now: datetime | None = None,
) -> bool:
    """
    Purpose:
        Decide whether the scheduler may send HTTP / auto-enqueue.
        Disabled → always allow.  Enabled with no windows → never allow.
    """
    if not enabled:
        return True
    return in_any_window(windows, now=now)


@dataclass(frozen=True)
class TestingWindowState:
    """Snapshot for CLI / status / Control Panel."""

    enabled: bool
    allows_execution: bool
    timezone: str
    windows: tuple[str, ...]
    now_ist: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "allows_execution": self.allows_execution,
            "timezone": self.timezone,
            "windows": list(self.windows),
            "now_ist": self.now_ist,
            "detail": self.detail,
        }


def _next_open_label(windows: Sequence[str], moment: datetime) -> str:
    if not windows:
        return "no windows configured"
    clock = _clock(moment)
    parsed = [parse_window(w) for w in windows]
    # If we are already inside, say so.
    for start, end in parsed:
        if window_contains(start, end, clock):
            return f"open until {end.strftime('%H:%M')} IST"
    # Next start today, else tomorrow.
    later_today = sorted(
        start for start, _end in parsed if start > clock
    )
    if later_today:
        return f"next window {later_today[0].strftime('%H:%M')} IST"
    earliest = min(start for start, _end in parsed)
    return f"next window {earliest.strftime('%H:%M')} IST tomorrow"


def evaluate(
    enabled: bool,
    windows: Sequence[str],
    *,
    now: datetime | None = None,
) -> TestingWindowState:
    """
    Purpose:
        Build a display snapshot of the testing-window gate.
    """
    moment = now_ist(now)
    now_label = moment.strftime("%H:%M")
    canon = tuple(windows)
    if not enabled:
        return TestingWindowState(
            enabled=False,
            allows_execution=True,
            timezone="IST",
            windows=canon,
            now_ist=now_label,
            detail="feature off — scheduler sends at any hour",
        )
    if not canon:
        return TestingWindowState(
            enabled=True,
            allows_execution=False,
            timezone="IST",
            windows=(),
            now_ist=now_label,
            detail="enabled but no windows configured — holding all jobs",
        )
    allowed = in_any_window(canon, now=moment)
    if allowed:
        detail = _next_open_label(canon, moment)
        return TestingWindowState(
            enabled=True,
            allows_execution=True,
            timezone="IST",
            windows=canon,
            now_ist=now_label,
            detail=detail,
        )
    return TestingWindowState(
        enabled=True,
        allows_execution=False,
        timezone="IST",
        windows=canon,
        now_ist=now_label,
        detail=f"outside window — {_next_open_label(canon, moment)}",
    )
