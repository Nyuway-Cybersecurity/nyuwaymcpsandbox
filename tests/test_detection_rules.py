"""Tests for the detection rule loader and payload match expressions."""

import pytest

from nyuwaymcpsandbox.detection.rules import (
    RuleLoadError,
    evaluate_match_expression,
    load_builtin_rules,
    load_rule_file,
    load_rules_dir,
    lookup_payload_path,
    parse_rule,
)

# ── parse_rule schema validation ─────────────────────────────────────────


def _minimal_rule_dict(**overrides):
    base = {
        "id": "test_rule",
        "title": "Test Rule",
        "severity": "high",
        "weight": 20,
        "category": "test",
        "detection": {"events": [{"type": "process.spawn"}]},
    }
    base.update(overrides)
    return base


def test_parse_rule_minimal_succeeds():
    rule = parse_rule(_minimal_rule_dict())
    assert rule.id == "test_rule"
    assert rule.severity == "high"
    assert rule.weight == 20
    assert len(rule.event_patterns) == 1
    assert rule.event_patterns[0].type == "process.spawn"
    assert rule.threshold_count == 1


def test_parse_rule_missing_id_raises():
    with pytest.raises(RuleLoadError, match="'id'"):
        parse_rule({k: v for k, v in _minimal_rule_dict().items() if k != "id"})


def test_parse_rule_invalid_severity_raises():
    with pytest.raises(RuleLoadError, match="severity"):
        parse_rule(_minimal_rule_dict(severity="catastrophic"))


def test_parse_rule_negative_weight_raises():
    with pytest.raises(RuleLoadError, match="weight"):
        parse_rule(_minimal_rule_dict(weight=-5))


def test_parse_rule_empty_events_list_raises():
    bad = _minimal_rule_dict()
    bad["detection"]["events"] = []
    with pytest.raises(RuleLoadError, match="events"):
        parse_rule(bad)


def test_parse_rule_threshold_zero_raises():
    bad = _minimal_rule_dict()
    bad["detection"]["threshold"] = {"count": 0}
    with pytest.raises(RuleLoadError, match="threshold"):
        parse_rule(bad)


def test_parse_rule_payload_must_be_strings():
    bad = _minimal_rule_dict()
    bad["detection"]["events"][0]["payload"] = {"key": 42}
    with pytest.raises(RuleLoadError, match="match expression"):
        parse_rule(bad)


def test_parse_rule_carries_triggered_by():
    rule = parse_rule(
        _minimal_rule_dict(
            detection={
                "events": [{"type": "network.*", "triggered_by_type": "mcp.tool_invocation"}]
            }
        )
    )
    assert rule.event_patterns[0].triggered_by_type == "mcp.tool_invocation"


# ── File and directory loading ───────────────────────────────────────────


def test_load_rule_file_missing_raises(tmp_path):
    with pytest.raises(RuleLoadError, match="not found"):
        load_rule_file(tmp_path / "nope.yaml")


def test_load_rule_file_empty_raises(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    with pytest.raises(RuleLoadError, match="empty"):
        load_rule_file(p)


def test_load_rule_file_bad_yaml_raises(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("id: foo\n  bad indent: : :")
    with pytest.raises(RuleLoadError, match="YAML"):
        load_rule_file(p)


def test_load_rules_dir_duplicate_id_raises(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "id: same\ntitle: A\nseverity: high\nweight: 10\ncategory: x\n"
        "detection:\n  events:\n    - type: process.spawn\n"
    )
    (tmp_path / "b.yaml").write_text(
        "id: same\ntitle: B\nseverity: high\nweight: 10\ncategory: x\n"
        "detection:\n  events:\n    - type: process.spawn\n"
    )
    with pytest.raises(RuleLoadError, match="Duplicate"):
        load_rules_dir(tmp_path)


def test_load_builtin_rules_returns_all_bundled():
    rules = load_builtin_rules()
    ids = {r.id for r in rules}
    expected = {
        "shell_exec_in_tool",
        "outbound_network_from_tool",
        "credential_env_access",
        "suspicious_dns_tld",
        "file_write_outside_workdir",
        "sensitive_file_read",
        # Phase 6 additions (timing + tool-name signals).
        "destructive_tool_invoked",
        "slow_tool_response",
        "pre_tool_network_activity",
    }
    assert expected.issubset(ids), f"missing: {expected - ids}"


def test_destructive_tool_invoked_rule_loads_with_expected_severity():
    rules = {r.id: r for r in load_builtin_rules()}
    rule = rules["destructive_tool_invoked"]
    assert rule.severity == "high"
    assert rule.weight == 20
    assert rule.category == "state_mutation"
    # The rule must match the mcp.tool_invocation event type.
    assert any(p.type == "mcp.tool_invocation" for p in rule.event_patterns)


def test_slow_tool_response_rule_loads_as_informational():
    rules = {r.id: r for r in load_builtin_rules()}
    rule = rules["slow_tool_response"]
    assert rule.severity == "low"
    assert rule.weight == 5
    assert rule.category == "reliability"
    assert any(p.type == "mcp.slow_tool_response" for p in rule.event_patterns)


def test_pre_tool_network_activity_rule_loads_medium_severity():
    rules = {r.id: r for r in load_builtin_rules()}
    rule = rules["pre_tool_network_activity"]
    assert rule.severity == "medium"
    assert rule.weight == 15
    assert rule.category == "stealth_behavior"
    assert any(p.type == "mcp.delayed_initialization" for p in rule.event_patterns)


# ── Match expressions ─────────────────────────────────────────────────────


def test_match_expression_exact():
    assert evaluate_match_expression("foo", "foo")
    assert not evaluate_match_expression("foo", "bar")


def test_match_expression_contains():
    assert evaluate_match_expression("contains:bar", "foobarbaz")
    assert not evaluate_match_expression("contains:zzz", "foobarbaz")


def test_match_expression_regex():
    assert evaluate_match_expression("regex:^foo.*baz$", "foobarbaz")
    assert not evaluate_match_expression("regex:^foo.*baz$", "qux")


def test_match_expression_invalid_regex_returns_false():
    """A broken regex shouldn't crash rule evaluation."""
    assert not evaluate_match_expression("regex:[unclosed", "anything")


def test_match_expression_any_requires_present_value():
    assert evaluate_match_expression("any", "anything")
    # None means key is absent; "any" requires presence, so it must reject.
    assert not evaluate_match_expression("any", None)


def test_match_expression_none_value_otherwise_false():
    assert not evaluate_match_expression("foo", None)
    assert not evaluate_match_expression("contains:foo", None)


# ── Payload path lookup ───────────────────────────────────────────────────


def test_lookup_payload_path_simple_key():
    assert lookup_payload_path({"a": 1}, "a") == 1


def test_lookup_payload_path_nested_dict():
    assert lookup_payload_path({"a": {"b": {"c": "x"}}}, "a.b.c") == "x"


def test_lookup_payload_path_list_index():
    assert lookup_payload_path({"argv": ["/bin/sh", "-c"]}, "argv.0") == "/bin/sh"
    assert lookup_payload_path({"argv": ["/bin/sh", "-c"]}, "argv.1") == "-c"


def test_lookup_payload_path_missing_returns_none():
    assert lookup_payload_path({"a": 1}, "b") is None
    assert lookup_payload_path({"a": {"b": 1}}, "a.c") is None
    assert lookup_payload_path({"argv": ["x"]}, "argv.5") is None


def test_lookup_payload_path_into_scalar_returns_none():
    """Resolving a deeper path on a scalar must not crash."""
    assert lookup_payload_path({"a": "scalar"}, "a.b") is None
