"""Detection rule data model and YAML loader.

A detection rule maps a behavioral pattern to a finding with severity,
weight, and remediation guidance. Rules are written in YAML so they are
reviewable by security analysts who do not necessarily read Python.

Schema (v1):

    id: shell_exec_in_tool                    # required, unique
    title: Subprocess spawned during MCP tool # required, short headline
    severity: high                            # low | medium | high | critical
    weight: 25                                # 0-35, contributes to score
    category: code_execution                  # free-form grouping tag
    description: |                            # optional, multi-line
      Why this matters.
    recommendation: |                         # optional, multi-line
      What to do about it.
    detection:
      events:                                 # at least one event pattern
        - type: process.spawn                 # exact or "network.*" wildcard
          payload:                            # optional, key -> match expression
            argv.0: contains:/bin/sh
          triggered_by_type: mcp.*            # optional, causal upstream type
      threshold:
        count: 1                              # default 1; min matching events

Payload match expressions:
    "literal"           exact string equality
    "contains:foo"      substring match (case sensitive)
    "regex:foo.*"       Python regex match
    "any"               key must exist, value can be anything
    "absent"            key must be missing OR value must be None / empty string

The ``absent`` expression is how rules express negative guards.  For
example, the sensitive_file_read rule uses ``error: absent`` to ensure
the rule only fires when the tool call actually succeeded (not when
the server errored out before any file was touched).

Nested payload keys use dot notation: "argv.0" means payload["argv"][0].
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VALID_SEVERITIES = ("low", "medium", "high", "critical")

# Bundled rule files ship alongside the package.
BUILTIN_RULES_DIR = Path(__file__).resolve().parent / "builtin"


class RuleLoadError(Exception):
    """Raised when a YAML rule file is malformed or missing required fields."""


@dataclass
class EventPattern:
    """A single event matcher inside a detection rule.

    Attributes:
        type: exact event type or "prefix.*" wildcard.
        payload: dict of payload-key (dot path) -> match expression.
        triggered_by_type: if set, the matched event must have triggered_by
            pointing at another event whose type matches this pattern.
    """

    type: str
    payload: dict[str, str] = field(default_factory=dict)
    triggered_by_type: str | None = None


@dataclass
class DetectionRule:
    """A loaded, validated detection rule."""

    id: str
    title: str
    severity: str
    weight: int
    category: str
    description: str = ""
    recommendation: str = ""
    event_patterns: list[EventPattern] = field(default_factory=list)
    threshold_count: int = 1


# ── Loader ────────────────────────────────────────────────────────────────


def _require(d: dict, key: str, ctx: str) -> Any:
    if key not in d:
        raise RuleLoadError(f"{ctx}: missing required field '{key}'")
    return d[key]


def _parse_event_pattern(raw: dict, ctx: str) -> EventPattern:
    if not isinstance(raw, dict):
        raise RuleLoadError(f"{ctx}: event pattern must be a mapping, got {type(raw).__name__}")
    type_ = _require(raw, "type", ctx)
    if not isinstance(type_, str):
        raise RuleLoadError(f"{ctx}: 'type' must be a string")

    payload_raw = raw.get("payload", {}) or {}
    if not isinstance(payload_raw, dict):
        raise RuleLoadError(f"{ctx}: 'payload' must be a mapping if provided")
    # All payload match expressions must be strings.
    payload: dict[str, str] = {}
    for k, v in payload_raw.items():
        if not isinstance(v, str):
            raise RuleLoadError(
                f"{ctx}: payload['{k}'] match expression must be a string, got {type(v).__name__}"
            )
        payload[str(k)] = v

    triggered_by_type = raw.get("triggered_by_type")
    if triggered_by_type is not None and not isinstance(triggered_by_type, str):
        raise RuleLoadError(f"{ctx}: 'triggered_by_type' must be a string if provided")

    return EventPattern(type=type_, payload=payload, triggered_by_type=triggered_by_type)


def parse_rule(raw: dict, source: str = "<dict>") -> DetectionRule:
    """Convert a parsed YAML document into a DetectionRule.

    Raises RuleLoadError on any schema violation.
    """
    if not isinstance(raw, dict):
        raise RuleLoadError(f"{source}: top-level rule must be a mapping")

    rule_id = _require(raw, "id", source)
    if not isinstance(rule_id, str) or not rule_id:
        raise RuleLoadError(f"{source}: 'id' must be a non-empty string")

    ctx = f"{source}#{rule_id}"
    title = _require(raw, "title", ctx)
    severity = _require(raw, "severity", ctx)
    if severity not in VALID_SEVERITIES:
        raise RuleLoadError(f"{ctx}: severity must be one of {VALID_SEVERITIES}, got '{severity}'")
    weight = _require(raw, "weight", ctx)
    if not isinstance(weight, int) or weight < 0:
        raise RuleLoadError(f"{ctx}: 'weight' must be a non-negative integer")
    category = _require(raw, "category", ctx)
    if not isinstance(category, str):
        raise RuleLoadError(f"{ctx}: 'category' must be a string")

    detection = _require(raw, "detection", ctx)
    if not isinstance(detection, dict):
        raise RuleLoadError(f"{ctx}: 'detection' must be a mapping")
    events_raw = _require(detection, "events", f"{ctx}.detection")
    if not isinstance(events_raw, list) or not events_raw:
        raise RuleLoadError(f"{ctx}: 'detection.events' must be a non-empty list")
    event_patterns = [
        _parse_event_pattern(e, f"{ctx}.detection.events[{i}]") for i, e in enumerate(events_raw)
    ]

    threshold = detection.get("threshold", {}) or {}
    if not isinstance(threshold, dict):
        raise RuleLoadError(f"{ctx}: 'detection.threshold' must be a mapping if provided")
    threshold_count = threshold.get("count", 1)
    if not isinstance(threshold_count, int) or threshold_count < 1:
        raise RuleLoadError(f"{ctx}: 'threshold.count' must be a positive integer")

    return DetectionRule(
        id=rule_id,
        title=str(title),
        severity=severity,
        weight=weight,
        category=category,
        description=str(raw.get("description", "")),
        recommendation=str(raw.get("recommendation", "")),
        event_patterns=event_patterns,
        threshold_count=threshold_count,
    )


def load_rule_file(path: Path | str) -> DetectionRule:
    """Load a single YAML rule file."""
    p = Path(path)
    if not p.is_file():
        raise RuleLoadError(f"Rule file not found: {p}")
    try:
        with p.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise RuleLoadError(f"{p}: YAML parse error: {e}") from e
    if raw is None:
        raise RuleLoadError(f"{p}: file is empty")
    return parse_rule(raw, source=str(p))


def load_rules_dir(directory: Path | str) -> list[DetectionRule]:
    """Load every *.yaml and *.yml rule from a directory.

    Duplicate rule IDs raise RuleLoadError. Rules are returned in
    filename-sorted order for deterministic test runs.
    """
    d = Path(directory)
    if not d.is_dir():
        raise RuleLoadError(f"Rules directory not found: {d}")
    paths = sorted(p for p in d.iterdir() if p.suffix.lower() in (".yaml", ".yml"))
    rules: list[DetectionRule] = []
    seen: dict[str, Path] = {}
    for p in paths:
        rule = load_rule_file(p)
        if rule.id in seen:
            raise RuleLoadError(
                f"Duplicate rule id '{rule.id}' in {p} (also defined in {seen[rule.id]})"
            )
        seen[rule.id] = p
        rules.append(rule)
    return rules


def load_builtin_rules() -> list[DetectionRule]:
    """Load every rule bundled with the package."""
    return load_rules_dir(BUILTIN_RULES_DIR)


# ── Payload match expressions ─────────────────────────────────────────────


def evaluate_match_expression(expression: str, value: Any) -> bool:
    """Evaluate a payload match expression against an actual value.

    Supports: "literal", "contains:foo", "regex:foo", "any", "absent".
    Returns False if the value is None unless the expression is "absent".
    """
    if expression == "absent":
        # Matches when the key is missing or the value is None/empty string.
        # Used by rules that need to assert "no error occurred", e.g. so
        # sensitive_file_read only fires on a successful tool call.
        return value is None or value == ""

    if value is None:
        # Missing key never matches anything else, including "any". A pattern
        # that needs to assert presence should use "any"; absence stays a
        # non-match.
        return False

    if expression == "any":
        return True
    if expression.startswith("contains:"):
        return expression[len("contains:") :] in str(value)
    if expression.startswith("regex:"):
        try:
            return re.search(expression[len("regex:") :], str(value)) is not None
        except re.error:
            return False
    # Default: exact string equality (coerce value via str()).
    return str(value) == expression


def lookup_payload_path(payload: dict, dotted_key: str) -> Any:
    """Resolve a dot-separated key path inside a nested payload.

    "argv.0" returns payload["argv"][0]; "user.name" returns
    payload["user"]["name"]. Returns None if any segment is missing.
    """
    cur: Any = payload
    for segment in dotted_key.split("."):
        if isinstance(cur, dict):
            if segment not in cur:
                return None
            cur = cur[segment]
        elif isinstance(cur, list):
            try:
                idx = int(segment)
            except ValueError:
                return None
            if idx < 0 or idx >= len(cur):
                return None
            cur = cur[idx]
        else:
            return None
    return cur
