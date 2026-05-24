"""Report - the container every renderer consumes.

A Report bundles everything a single detonation produced: what was
scanned, when, in which mode, the full behavioural timeline, the
findings the detection engine produced, and the final verdict. Each
renderer (Rich timeline, JSON, SARIF) consumes a Report and serializes
it for a different audience.

Keep this dumb: no rendering decisions, no formatting - just data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from nyuwaymcpsandbox.detection.engine import Finding
from nyuwaymcpsandbox.detection.verdict import Verdict
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


@dataclass
class Report:
    """All data produced by a single detonation."""

    target: str
    mode: str  # "fast" | "full"
    timeline: BehavioralTimeline
    findings: list[Finding]
    verdict: Verdict
    duration_seconds: float = 0.0
    scanned_at: str = field(
        default_factory=lambda: (
            datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        )
    )

    def matched_event_ids(self) -> set[str]:
        """Return every event_id referenced by at least one finding."""
        ids: set[str] = set()
        for f in self.findings:
            ids.update(f.matched_event_ids)
        return ids
