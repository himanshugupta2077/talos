"""
Module: talos.intruder.generators.dates

Purpose:
    Date-range payload generator (Phase 4). Inclusive calendar steps with
    strftime formatting.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Iterator, Optional

from talos.intruder.models import (
    DEFAULT_DATES_FORMAT,
    DEFAULT_DATES_STEP_DAYS,
    ERR_INVALID_DATES,
)


def _parse_date(raw: Any) -> date:
    if isinstance(raw, date) and not isinstance(raw, datetime):
        return raw
    if isinstance(raw, datetime):
        return raw.date()
    s = str(raw).strip()
    if not s:
        raise ValueError(f"{ERR_INVALID_DATES}:empty_date")
    # ISO date or datetime
    try:
        if "T" in s or " " in s:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
        return date.fromisoformat(s[:10])
    except ValueError as exc:
        raise ValueError(f"{ERR_INVALID_DATES}:bad_date:{s}") from exc


class DatesGenerator:
    """
    Yields formatted date strings from start..end inclusive by step_days.

    Options:
        start (str, required) — ISO date YYYY-MM-DD (or datetime)
        end (str, required) — ISO date
        step_days (int, default 1) — positive or negative step
        format (str, default %Y-%m-%d) — strftime format
    """

    def __init__(self) -> None:
        self._values: list[str] = []
        self._index = 0
        self.start: Optional[date] = None
        self.end: Optional[date] = None
        self.step_days = DEFAULT_DATES_STEP_DAYS
        self.fmt = DEFAULT_DATES_FORMAT

    def open(self, config: dict[str, Any]) -> None:
        if "start" not in config or "end" not in config:
            raise ValueError(f"{ERR_INVALID_DATES}:start_end_required")
        self.start = _parse_date(config["start"])
        self.end = _parse_date(config["end"])
        self.step_days = int(config.get("step_days", config.get("step", DEFAULT_DATES_STEP_DAYS)))
        if self.step_days == 0:
            raise ValueError(f"{ERR_INVALID_DATES}:step_zero")
        self.fmt = str(config.get("format") or DEFAULT_DATES_FORMAT)

        if self.step_days > 0 and self.start > self.end:
            raise ValueError(f"{ERR_INVALID_DATES}:start_gt_end")
        if self.step_days < 0 and self.start < self.end:
            raise ValueError(f"{ERR_INVALID_DATES}:start_lt_end")

        self._values = []
        cur = self.start
        delta = timedelta(days=self.step_days)
        # Cap at 1e6 dates without force (mirrors wordlist line cap spirit)
        force = bool(config.get("force"))
        max_n = 1_000_000 if force else 100_000
        while True:
            if self.step_days > 0 and cur > self.end:
                break
            if self.step_days < 0 and cur < self.end:
                break
            try:
                self._values.append(cur.strftime(self.fmt))
            except Exception as exc:  # noqa: BLE001
                raise ValueError(f"{ERR_INVALID_DATES}:bad_format:{self.fmt}") from exc
            if len(self._values) > max_n:
                raise ValueError(f"{ERR_INVALID_DATES}:too_many:{len(self._values)}")
            cur = cur + delta
        self._index = 0
        if not self._values:
            raise ValueError(f"{ERR_INVALID_DATES}:empty")

    def __iter__(self) -> Iterator[str]:
        while self._index < len(self._values):
            v = self._values[self._index]
            self._index += 1
            yield v

    def estimate_count(self) -> int | None:
        return len(self._values)

    def checkpoint(self) -> dict[str, Any]:
        return {
            "type": "dates",
            "index": self._index,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "step_days": self.step_days,
            "format": self.fmt,
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        if not self._values and checkpoint.get("start") is not None:
            self.open({
                "start": checkpoint.get("start"),
                "end": checkpoint.get("end"),
                "step_days": checkpoint.get("step_days", 1),
                "format": checkpoint.get("format", DEFAULT_DATES_FORMAT),
            })
        self._index = int(checkpoint.get("index", 0))
