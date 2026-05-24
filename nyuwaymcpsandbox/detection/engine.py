"""Detection engine - evaluate rules against a BehavioralTimeline.

The engine is intentionally simple for v1: each rule is evaluated
independently, and each event pattern in a rule is matched against the
timeline. A rule fires when every event pattern in its detection.events
list has at least threshold_count matching events.

This means a rule with a single pattern is the common case; multi-pattern
rules express "both A and B must occur" but do not enforce ordering or
correlation between separate patterns. Correlation within a single
pattern is expressed via triggered_by_type.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nyuwaymcpsandbox.detection.rules import (
    DetectionRule,
    EventPattern,
    evaluate_match_expression,
    lookup_payload_path,
)
from nyuwaymcpsandbox.sandbox.events import BehavioralEvent
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


@dataclass
class Finding:
    """A rule that fired against the timeline."""

    rule_id: str
    title: str
    severity: str
    weight: int
    category: str
    description: str
    recommendation: str
    matched_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "weight": self.weight,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "matched_event_ids": list(self.matched_event_ids),
        }


def _event_matches_pattern(
    event: BehavioralEvent,
    pattern: EventPattern,
    timeline_by_id: dict[str, BehavioralEvent],
) -> bool:
    """Return True if a single event satisfies an event pattern."""
    if not event.matches_type(pattern.type):
        return False

    # Payload key/value checks.
    for key, expr in pattern.payload.items():
        actual = lookup_payload_path(event.payload, key)
        if not evaluate_match_expression(expr, actual):
            return False

    # Causal upstream check.
    if pattern.triggered_by_type is not None:
        if event.triggered_by is None:
            return False
        upstream = timeline_by_id.get(event.triggered_by)
        if upstream is None:
            return False
        if not upstream.matches_type(pattern.triggered_by_type):
            return False

    return True


def _events_matching(
    pattern: EventPattern,
    timeline: BehavioralTimeline,
    timeline_by_id: dict[str, BehavioralEvent],
) -> list[BehavioralEvent]:
    return [e for e in timeline.events if _event_matches_pattern(e, pattern, timeline_by_id)]


def evaluate_rule(rule: DetectionRule, timeline: BehavioralTimeline) -> Finding | None:
    """Evaluate a single rule. Returns a Finding if the rule fires, else None.

    All event patterns must each find >= threshold_count matching events
    for the rule to fire. Matched event IDs from every pattern are
    collected as the finding's evidence (deduped, order preserved).
    """
    if not rule.event_patterns:
        return None
    timeline_by_id = {e.event_id: e for e in timeline.events}

    collected_ids: list[str] = []
    seen: set[str] = set()

    for pattern in rule.event_patterns:
        matches = _events_matching(pattern, timeline, timeline_by_id)
        if len(matches) < rule.threshold_count:
            return None
        for m in matches:
            if m.event_id not in seen:
                seen.add(m.event_id)
                collected_ids.append(m.event_id)

    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        weight=rule.weight,
        category=rule.category,
        description=rule.description,
        recommendation=rule.recommendation,
        matched_event_ids=collected_ids,
    )


def evaluate_rules(rules: list[DetectionRule], timeline: BehavioralTimeline) -> list[Finding]:
    """Evaluate every rule against the timeline. Returns all firings."""
    findings: list[Finding] = []
    for rule in rules:
        finding = evaluate_rule(rule, timeline)
        if finding is not None:
            findings.append(finding)
    return findings
