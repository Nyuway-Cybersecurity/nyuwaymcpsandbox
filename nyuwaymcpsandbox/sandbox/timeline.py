"""BehavioralTimeline - ordered, mergeable collection of BehavioralEvent.

Capture sources run concurrently and each emits events with their own
relative timestamps. The timeline merges them into a single
chronologically-ordered sequence that the detection engine and output
renderers consume.

Design notes:
- Events are stored as added; `events` returns them sorted on demand. This
  keeps writes cheap; sorting is a one-time cost at read.
- Equal-timestamp events are stable-ordered by insertion order. This
  matters when two captures emit at the same monotonic instant.
- Filtering returns plain lists, not generators - rule evaluation
  iterates the same filter result multiple times in some cases.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from nyuwaymcpsandbox.sandbox.events import BehavioralEvent


class BehavioralTimeline:
    """Ordered collection of BehavioralEvent with filter + merge support."""

    def __init__(self) -> None:
        self._events: list[BehavioralEvent] = []

    # ── mutation ──────────────────────────────────────────────────────────

    def add(self, event: BehavioralEvent) -> None:
        """Append a single event."""
        self._events.append(event)

    def extend(self, events: Iterable[BehavioralEvent]) -> None:
        """Append many events at once."""
        self._events.extend(events)

    def merge(self, other: BehavioralTimeline) -> None:
        """Pull every event from another timeline into this one.

        The other timeline is not modified. Use this to combine the output
        of independent capture sources into a single record.
        """
        self._events.extend(other._events)

    # ── inspection ────────────────────────────────────────────────────────

    @property
    def events(self) -> list[BehavioralEvent]:
        """Return events sorted by timestamp (stable on equal timestamps)."""
        # Python's sort is stable, so insertion order breaks ties.
        return sorted(self._events, key=lambda e: e.timestamp)

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self):
        return iter(self.events)

    def filter_by_type(self, type_or_prefix: str) -> list[BehavioralEvent]:
        """Return events matching a type or a "prefix.*" wildcard."""
        return [e for e in self.events if e.matches_type(type_or_prefix)]

    def filter_by_source(self, source: str) -> list[BehavioralEvent]:
        """Return events emitted by a specific capture source."""
        return [e for e in self.events if e.source == source]

    def caused_by(self, event_id: str) -> list[BehavioralEvent]:
        """Return events whose triggered_by points at the given event_id."""
        return [e for e in self.events if e.triggered_by == event_id]

    # ── serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Return a JSON-serializable timeline record."""
        return {
            "event_count": len(self._events),
            "events": [e.to_dict() for e in self.events],
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Return a JSON-encoded timeline."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)
