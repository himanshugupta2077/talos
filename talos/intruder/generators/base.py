"""
Module: talos.intruder.generators.base

Purpose:
    PayloadGenerator protocol for Intruder payload sets.
"""

from __future__ import annotations

from typing import Any, Iterator, Protocol, runtime_checkable


@runtime_checkable
class PayloadGenerator(Protocol):
    """Produces an iterator of string payloads with checkpoint support."""

    def open(self, config: dict[str, Any]) -> None: ...

    def __iter__(self) -> Iterator[str]: ...

    def estimate_count(self) -> int | None:
        """None if unbounded / unknown."""
        ...

    def checkpoint(self) -> dict[str, Any]:
        """Serializable cursor for resume."""
        ...

    def restore(self, checkpoint: dict[str, Any]) -> None: ...
