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
    EVT_MCP_DELAYED_INIT,
    EVT_MCP_SLOW_TOOL,
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


# ── Phase 6 rules: destructive_tool_invoked ──────────────────────────────


def test_destructive_tool_rule_fires_on_git_commit():
    rules = load_builtin_rules()
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1, payload={"name": "git_commit"})
    findings = evaluate_rules(rules, _tl(tool))
    assert "destructive_tool_invoked" in {f.rule_id for f in findings}


def test_destructive_tool_rule_fires_on_kubectl_delete():
    rules = load_builtin_rules()
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1, payload={"name": "kubectl_delete"})
    findings = evaluate_rules(rules, _tl(tool))
    assert "destructive_tool_invoked" in {f.rule_id for f in findings}


def test_destructive_tool_rule_fires_on_exec_in_pod():
    rules = load_builtin_rules()
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1, payload={"name": "exec_in_pod"})
    findings = evaluate_rules(rules, _tl(tool))
    assert "destructive_tool_invoked" in {f.rule_id for f in findings}


def test_destructive_tool_rule_does_not_fire_on_read_only_tools():
    """git_status, git_log, kubectl_get must not flag destructive."""
    rules = load_builtin_rules()
    safe_names = ["git_status", "git_log", "git_diff", "kubectl_get", "kubectl_describe", "fetch"]
    for name in safe_names:
        tl = _tl(_evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1, payload={"name": name}))
        findings = evaluate_rules(rules, tl)
        assert "destructive_tool_invoked" not in {f.rule_id for f in findings}, (
            f"destructive_tool_invoked false-fired on {name}"
        )


# ── Phase 6 rules: slow_tool_response ────────────────────────────────────


def test_slow_tool_rule_fires_when_slow_event_present():
    rules = load_builtin_rules()
    slow = _evt(
        EVT_MCP_SLOW_TOOL,
        SRC_MCP_CLIENT,
        45.0,
        payload={"name": "puppeteer_select", "duration_seconds": 30.5, "threshold_seconds": 30.0},
    )
    findings = evaluate_rules(rules, _tl(slow))
    assert "slow_tool_response" in {f.rule_id for f in findings}


def test_slow_tool_rule_does_not_fire_without_slow_event():
    rules = load_builtin_rules()
    # An invocation event alone (no slow follow-up) must not fire the rule.
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1, payload={"name": "x"})
    findings = evaluate_rules(rules, _tl(tool))
    assert "slow_tool_response" not in {f.rule_id for f in findings}


# ── Phase 6 rules: pre_tool_network_activity ─────────────────────────────


def test_pre_tool_network_activity_rule_fires_on_delayed_init():
    rules = load_builtin_rules()
    delayed = _evt(
        EVT_MCP_DELAYED_INIT,
        SRC_MCP_CLIENT,
        160.0,
        payload={"startup_seconds": 158.4, "threshold_seconds": 60.0},
    )
    findings = evaluate_rules(rules, _tl(delayed))
    assert "pre_tool_network_activity" in {f.rule_id for f in findings}


def test_pre_tool_network_activity_rule_silent_on_fast_startup():
    rules = load_builtin_rules()
    # No delayed_init event at all -> rule must be silent.
    tool = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, 0.1)
    findings = evaluate_rules(rules, _tl(tool))
    assert "pre_tool_network_activity" not in {f.rule_id for f in findings}
