"""Tests for the detection engine - rule evaluation against a timeline."""

from nyuwaymcpsandbox.detection.engine import evaluate_rule, evaluate_rules
from nyuwaymcpsandbox.detection.rules import (
    DetectionRule,
    EventPattern,
    load_builtin_rules,
)
from nyuwaymcpsandbox.sandbox.events import (
    EVT_ENV_READ,
    EVT_FS_WRITE,
    EVT_MCP_TOOL_INVOKE,
    EVT_NETWORK_DNS,
    EVT_NETWORK_HTTP,
    EVT_PROCESS_SPAWN,
    SRC_ENV,
    SRC_FILESYSTEM,
    SRC_MCP_CLIENT,
    SRC_NETWORK,
    SRC_PROCESS,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


def _tl(*events):
    tl = BehavioralTimeline()
    for e in events:
        tl.add(e)
    return tl


def _evt(type_, source, ts, payload=None, triggered_by=None):
    return BehavioralEvent(
        type=type_, source=source, timestamp=ts, payload=payload or {}, triggered_by=triggered_by
    )


def _rule(patterns, threshold=1, rule_id="r1", severity="high", weight=20):
    return DetectionRule(
        id=rule_id,
        title="Test",
        severity=severity,
        weight=weight,
        category="test",
        event_patterns=patterns,
        threshold_count=threshold,
    )


# ── Single-pattern matching ──────────────────────────────────────────────


def test_no_matching_event_returns_none():
    rule = _rule([EventPattern(type=EVT_PROCESS_SPAWN)])
    tl = _tl(_evt(EVT_NETWORK_DNS, SRC_NETWORK, 1.0))
    assert evaluate_rule(rule, tl) is None


def test_single_match_returns_finding():
    rule = _rule([EventPattern(type=EVT_PROCESS_SPAWN)])
    tl = _tl(_evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 1.0))
    finding = evaluate_rule(rule, tl)
    assert finding is not None
    assert finding.rule_id == "r1"
    assert len(finding.matched_event_ids) == 1


def test_wildcard_type_matches_any_subtype():
    rule = _rule([EventPattern(type="network.*")])
    tl = _tl(
        _evt(EVT_NETWORK_DNS, SRC_NETWORK, 1.0),
        _evt(EVT_NETWORK_HTTP, SRC_NETWORK, 2.0),
    )
    finding = evaluate_rule(rule, tl)
    assert finding is not None
    assert len(finding.matched_event_ids) == 2


# ── Payload matching ─────────────────────────────────────────────────────


def test_payload_exact_match():
    rule = _rule([EventPattern(type=EVT_ENV_READ, payload={"name": "AWS_SECRET_ACCESS_KEY"})])
    tl = _tl(_evt(EVT_ENV_READ, SRC_ENV, 1.0, payload={"name": "AWS_SECRET_ACCESS_KEY"}))
    assert evaluate_rule(rule, tl) is not None


def test_payload_mismatch_skips_event():
    rule = _rule([EventPattern(type=EVT_ENV_READ, payload={"name": "AWS_SECRET_ACCESS_KEY"})])
    tl = _tl(_evt(EVT_ENV_READ, SRC_ENV, 1.0, payload={"name": "HOME"}))
    assert evaluate_rule(rule, tl) is None


def test_payload_regex_match():
    rule = _rule([EventPattern(type=EVT_ENV_READ, payload={"name": "regex:(AWS|GCP)_.*"})])
    tl = _tl(
        _evt(EVT_ENV_READ, SRC_ENV, 1.0, payload={"name": "AWS_ACCESS_KEY_ID"}),
        _evt(EVT_ENV_READ, SRC_ENV, 2.0, payload={"name": "PATH"}),  # no match
    )
    finding = evaluate_rule(rule, tl)
    assert finding is not None
    assert len(finding.matched_event_ids) == 1


def test_payload_dot_path_matches_argv_index():
    rule = _rule([EventPattern(type=EVT_PROCESS_SPAWN, payload={"argv.0": "/bin/sh"})])
    tl = _tl(
        _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 1.0, payload={"argv": ["/bin/sh", "-c", "ls"]}),
        _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 2.0, payload={"argv": ["/usr/bin/grep"]}),
    )
    finding = evaluate_rule(rule, tl)
    assert finding is not None
    assert len(finding.matched_event_ids) == 1


# ── Causal triggered_by matching ─────────────────────────────────────────


def test_triggered_by_type_matches_upstream_tool_invocation():
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 1.0, payload={"name": "fetch"})
    spawn = _evt(
        EVT_PROCESS_SPAWN,
        SRC_PROCESS,
        1.1,
        payload={"argv": ["/bin/sh"]},
        triggered_by=tool.event_id,
    )
    tl = _tl(tool, spawn)
    rule = _rule([EventPattern(type=EVT_PROCESS_SPAWN, triggered_by_type="mcp.*")])
    finding = evaluate_rule(rule, tl)
    assert finding is not None


def test_triggered_by_required_but_missing_does_not_fire():
    """Spawn happened, but not triggered by a tool - rule must not fire."""
    spawn = _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 1.0)  # no triggered_by
    tl = _tl(spawn)
    rule = _rule([EventPattern(type=EVT_PROCESS_SPAWN, triggered_by_type="mcp.*")])
    assert evaluate_rule(rule, tl) is None


def test_triggered_by_wrong_upstream_type_does_not_fire():
    """Spawn was triggered, but by an unrelated event type."""
    container = _evt("container.started", "container", 0.0)
    spawn = _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 1.0, triggered_by=container.event_id)
    tl = _tl(container, spawn)
    rule = _rule([EventPattern(type=EVT_PROCESS_SPAWN, triggered_by_type="mcp.*")])
    assert evaluate_rule(rule, tl) is None


# ── Threshold ────────────────────────────────────────────────────────────


def test_threshold_count_requires_n_matches():
    rule = _rule([EventPattern(type=EVT_PROCESS_SPAWN)], threshold=3)
    tl = _tl(
        _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 1.0),
        _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 2.0),
    )
    # Only 2 matches, threshold 3 - must not fire.
    assert evaluate_rule(rule, tl) is None


def test_threshold_count_satisfied_fires():
    rule = _rule([EventPattern(type=EVT_PROCESS_SPAWN)], threshold=2)
    tl = _tl(
        _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 1.0),
        _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 2.0),
        _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 3.0),
    )
    finding = evaluate_rule(rule, tl)
    assert finding is not None
    assert len(finding.matched_event_ids) == 3


# ── Multi-pattern AND semantics ──────────────────────────────────────────


def test_multi_pattern_all_must_match():
    rule = _rule(
        [
            EventPattern(type=EVT_PROCESS_SPAWN),
            EventPattern(type=EVT_NETWORK_DNS),
        ]
    )
    tl_only_spawn = _tl(_evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 1.0))
    assert evaluate_rule(rule, tl_only_spawn) is None

    tl_both = _tl(
        _evt(EVT_PROCESS_SPAWN, SRC_PROCESS, 1.0),
        _evt(EVT_NETWORK_DNS, SRC_NETWORK, 2.0),
    )
    finding = evaluate_rule(rule, tl_both)
    assert finding is not None
    assert len(finding.matched_event_ids) == 2


# ── End-to-end against bundled rules ─────────────────────────────────────


def test_bundled_shell_exec_rule_fires_on_realistic_timeline():
    rules = load_builtin_rules()
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1, payload={"name": "exec"})
    spawn = _evt(
        EVT_PROCESS_SPAWN,
        SRC_PROCESS,
        0.2,
        payload={"argv": ["/bin/sh", "-c", "curl http://x"]},
        triggered_by=tool.event_id,
    )
    tl = _tl(tool, spawn)
    findings = evaluate_rules(rules, tl)
    fired = {f.rule_id for f in findings}
    assert "shell_exec_in_tool" in fired


def test_bundled_outbound_network_rule_fires_when_tool_makes_http_call():
    rules = load_builtin_rules()
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1, payload={"name": "fetch_data"})
    http = _evt(
        EVT_NETWORK_HTTP,
        SRC_NETWORK,
        0.2,
        payload={"host": "log.external.io"},
        triggered_by=tool.event_id,
    )
    tl = _tl(tool, http)
    findings = evaluate_rules(rules, tl)
    fired = {f.rule_id for f in findings}
    assert "outbound_network_from_tool" in fired


def test_bundled_credential_env_rule_fires_for_aws_key():
    rules = load_builtin_rules()
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1)
    env = _evt(
        EVT_ENV_READ,
        SRC_ENV,
        0.2,
        payload={"name": "AWS_SECRET_ACCESS_KEY"},
        triggered_by=tool.event_id,
    )
    tl = _tl(tool, env)
    findings = evaluate_rules(rules, tl)
    fired = {f.rule_id for f in findings}
    assert "credential_env_access" in fired


def test_bundled_credential_env_rule_does_not_fire_for_home():
    """Reading HOME or PATH should not flag - tests our regex isn't too greedy."""
    rules = load_builtin_rules()
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1)
    env = _evt(
        EVT_ENV_READ,
        SRC_ENV,
        0.2,
        payload={"name": "HOME"},
        triggered_by=tool.event_id,
    )
    tl = _tl(tool, env)
    findings = evaluate_rules(rules, tl)
    fired = {f.rule_id for f in findings}
    assert "credential_env_access" not in fired


def test_bundled_suspicious_tld_rule_fires_for_tk():
    rules = load_builtin_rules()
    dns = _evt(EVT_NETWORK_DNS, SRC_NETWORK, 0.1, payload={"domain": "evil.tk"})
    tl = _tl(dns)
    findings = evaluate_rules(rules, tl)
    fired = {f.rule_id for f in findings}
    assert "suspicious_dns_tld" in fired


def test_bundled_file_write_rule_fires_for_etc_write():
    rules = load_builtin_rules()
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1)
    write = _evt(
        EVT_FS_WRITE,
        SRC_FILESYSTEM,
        0.2,
        payload={"path": "/etc/cron.d/payload"},
        triggered_by=tool.event_id,
    )
    tl = _tl(tool, write)
    findings = evaluate_rules(rules, tl)
    fired = {f.rule_id for f in findings}
    assert "file_write_outside_workdir" in fired


def test_clean_timeline_produces_no_findings():
    """Sanity: a benign timeline must not trigger any bundled rules."""
    rules = load_builtin_rules()
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1)
    # Tool listing only, no spawn, no network, no env reads, no writes.
    tl = _tl(tool)
    findings = evaluate_rules(rules, tl)
    assert findings == []
