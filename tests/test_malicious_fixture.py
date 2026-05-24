"""Tests for the deliberately malicious MCP server fixture.

Three levels of coverage:

1. test_malicious_server_lists_five_tools
   The malicious server speaks valid MCP - list_tools returns all 5.

2. test_all_six_rules_fire_on_synthetic_timeline
   Builds a synthetic BehavioralTimeline with exactly the events each
   rule needs, runs all 6 builtin rules, asserts every rule fires, and
   confirms the verdict is CRITICAL (combined weight 115, capped to 100).

3. test_malicious_server_rule6_fires_via_pipeline
   Runs the malicious server end-to-end through run_pipeline() using
   subprocess transport. A custom LLM fake calls 'read_file' with
   '/etc/passwd' as the path argument. Asserts the sensitive_file_read
   rule fires and the verdict is not PASS.
"""

from __future__ import annotations

import sys
from pathlib import Path

from nyuwaymcpsandbox.detection.engine import evaluate_rules
from nyuwaymcpsandbox.detection.rules import load_builtin_rules
from nyuwaymcpsandbox.detection.verdict import calculate_verdict
from nyuwaymcpsandbox.drivers.fakes import fake_docker_client_factory
from nyuwaymcpsandbox.drivers.llm_backend import LlmResponse, LlmToolCall
from nyuwaymcpsandbox.drivers.mcp_client import McpTool
from nyuwaymcpsandbox.pipeline import PipelineConfig, PipelineDeps, run_pipeline
from nyuwaymcpsandbox.sandbox.events import (
    EVT_ENV_READ,
    EVT_FS_WRITE,
    EVT_MCP_TOOL_INVOKE,
    EVT_NETWORK_DNS,
    EVT_PROCESS_SPAWN,
    SRC_ENV,
    SRC_FILESYSTEM,
    SRC_MCP_CLIENT,
    SRC_NETWORK,
    SRC_PROCESS,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "malicious_mcp_server.py"
PYTHON = sys.executable


# ── helpers ──────────────────────────────────────────────────────────────


def _evt(type_: str, source: str, payload: dict | None = None, triggered_by: str | None = None):
    return BehavioralEvent(
        type=type_,
        source=source,
        timestamp=0.0,
        payload=payload or {},
        triggered_by=triggered_by,
    )


def _malicious_timeline() -> BehavioralTimeline:
    """Build a synthetic timeline with exactly the events that fire all 6 rules.

    Each rule needs specific event types and payload shapes. We create one
    tool invocation event per rule so the triggered_by causal links are clean.
    """
    tl = BehavioralTimeline()

    # Rule 1: shell_exec_in_tool
    # process.spawn triggered_by mcp.tool_invocation
    tool_shell = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, {"name": "run_shell_command"})
    tl.add(tool_shell)
    tl.add(_evt(EVT_PROCESS_SPAWN, SRC_PROCESS, {"argv": ["id"]}, triggered_by=tool_shell.event_id))

    # Rule 2: outbound_network_from_tool
    # network.* triggered_by mcp.tool_invocation
    tool_net = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, {"name": "phone_home"})
    tl.add(tool_net)
    tl.add(
        _evt(
            EVT_NETWORK_DNS,
            SRC_NETWORK,
            {"domain": "c2.evil.xyz"},
            triggered_by=tool_net.event_id,
        )
    )

    # Rule 3: credential_env_access
    # environment.read with name matching credential regex, triggered_by mcp.tool_invocation
    tool_cred = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, {"name": "steal_credentials"})
    tl.add(tool_cred)
    tl.add(
        _evt(
            EVT_ENV_READ,
            SRC_ENV,
            {"name": "AWS_SECRET_ACCESS_KEY"},
            triggered_by=tool_cred.event_id,
        )
    )

    # Rule 4: suspicious_dns_tld
    # network.dns_lookup with domain on high-risk TLD (no triggered_by required)
    tl.add(_evt(EVT_NETWORK_DNS, SRC_NETWORK, {"domain": "c2.evil.xyz"}))

    # Rule 5: file_write_outside_workdir
    # filesystem.write with system path, triggered_by mcp.tool_invocation
    tool_drop = _evt(EVT_MCP_TOOL_INVOKE, SRC_MCP_CLIENT, {"name": "drop_payload"})
    tl.add(tool_drop)
    tl.add(
        _evt(
            EVT_FS_WRITE,
            SRC_FILESYSTEM,
            {"path": "/home/nyuway_malicious_drop.txt"},
            triggered_by=tool_drop.event_id,
        )
    )

    # Rule 6: sensitive_file_read
    # mcp.tool_invocation with arguments containing a sensitive path
    tl.add(
        _evt(
            EVT_MCP_TOOL_INVOKE,
            SRC_MCP_CLIENT,
            {"name": "read_file", "arguments": {"path": "/etc/passwd"}},
        )
    )

    return tl


# ── Test 1: server speaks valid MCP ──────────────────────────────────────


def test_malicious_server_lists_five_tools():
    """The malicious fixture speaks the full MCP protocol and exposes 5 tools."""
    from nyuwaymcpsandbox.drivers.stdio_mcp import StdioMcpClient
    from nyuwaymcpsandbox.drivers.subprocess_stream import SubprocessStdioStream

    stream = SubprocessStdioStream(command=[PYTHON, str(FIXTURE_PATH)])
    client = StdioMcpClient(stream=stream)
    try:
        tools = client.list_tools()
    finally:
        client.close()

    names = {t.name for t in tools}
    assert "steal_credentials" in names
    assert "run_shell_command" in names
    assert "phone_home" in names
    assert "drop_payload" in names
    assert "read_file" in names
    assert len(tools) == 5


# ── Test 2: all 6 rules fire on the synthetic timeline ───────────────────


def test_all_six_rules_fire_on_synthetic_timeline():
    """Every builtin detection rule fires against the malicious synthetic timeline."""
    tl = _malicious_timeline()
    rules = load_builtin_rules()
    findings = evaluate_rules(rules, tl)

    fired_ids = {f.rule_id for f in findings}
    assert "shell_exec_in_tool" in fired_ids, "shell_exec_in_tool did not fire"
    assert "outbound_network_from_tool" in fired_ids, "outbound_network_from_tool did not fire"
    assert "credential_env_access" in fired_ids, "credential_env_access did not fire"
    assert "suspicious_dns_tld" in fired_ids, "suspicious_dns_tld did not fire"
    assert "file_write_outside_workdir" in fired_ids, "file_write_outside_workdir did not fire"
    assert "sensitive_file_read" in fired_ids, "sensitive_file_read did not fire"
    assert len(findings) == 6, f"expected 6 findings, got {len(findings)}: {fired_ids}"


def test_all_six_rules_produce_critical_verdict():
    """Combined weight of all 6 rules exceeds 100 - verdict must be CRITICAL."""
    tl = _malicious_timeline()
    rules = load_builtin_rules()
    findings = evaluate_rules(rules, tl)
    verdict = calculate_verdict(findings)

    # Total weight: 25+25+15+10+15+25 = 115, capped at 100.
    assert verdict.score == 100, f"expected score 100, got {verdict.score}"
    assert verdict.tier == "CRITICAL", f"expected CRITICAL, got {verdict.tier}"


def test_each_finding_has_evidence():
    """Every finding references at least one matched event ID."""
    tl = _malicious_timeline()
    rules = load_builtin_rules()
    findings = evaluate_rules(rules, tl)
    for f in findings:
        assert f.matched_event_ids, f"rule {f.rule_id} has no matched_event_ids"


# ── Test 3: rule 6 fires via the real pipeline ────────────────────────────


def test_malicious_server_rule6_fires_via_pipeline(tmp_path):
    """sensitive_file_read fires when the malicious server is probed end-to-end.

    Uses subprocess transport (no Docker needed). A custom LLM fake issues
    a targeted call to 'read_file' with '/etc/passwd' as the path argument,
    which is exactly the payload the sensitive_file_read rule matches on.
    """

    class _TargetedLlm:
        """LLM that always calls read_file with /etc/passwd."""

        def chat(self, user_message: str, tools: list[McpTool], system_message: str = ""):
            read_file = next((t for t in tools if t.name == "read_file"), None)
            if read_file:
                return LlmResponse(
                    text="Reading the file as instructed.",
                    tool_calls=[
                        LlmToolCall(
                            name="read_file",
                            arguments={"path": "/etc/passwd"},
                        )
                    ],
                )
            return LlmResponse(text="no read_file tool available")

    config = PipelineConfig(
        target=str(tmp_path),
        mode="full",
        output="json",
        mcp_transport="subprocess",
        mcp_command=[PYTHON, str(FIXTURE_PATH)],
    )
    deps = PipelineDeps()
    deps.docker_client_factory = fake_docker_client_factory
    deps.llm_backend_factory = lambda _model, _key: _TargetedLlm()

    result = run_pipeline(config, deps)

    fired_ids = {f.rule_id for f in result.report.findings}
    assert "sensitive_file_read" in fired_ids, (
        f"sensitive_file_read did not fire. Findings: {fired_ids}"
    )
    assert result.report.verdict.tier != "PASS", (
        f"expected non-PASS verdict, got {result.report.verdict.tier}"
    )


# ── FP regression: non-file tools must not trigger sensitive_file_read ───


def test_sensitive_file_read_does_not_fire_for_memory_graph_tools():
    """Regression: create_entities/open_nodes with /etc/passwd as node name
    must NOT trigger sensitive_file_read.

    Real FP discovered during real-world testing against
    @modelcontextprotocol/server-memory: Mistral used create_entities with
    '/etc/passwd' as an entity observation. The rule now requires the tool
    name to match a file-I/O pattern, eliminating this class of FP.
    """
    tl = BehavioralTimeline()
    # These are exactly the events seen from the memory server FP.
    for tool_name in ("create_entities", "open_nodes", "search_nodes", "add_observations"):
        tl.add(
            _evt(
                EVT_MCP_TOOL_INVOKE,
                SRC_MCP_CLIENT,
                {"name": tool_name, "arguments": {"entities": [{"name": "entity1", "entityType": "file", "observations": ["/etc/passwd"]}]}},
            )
        )

    rules = load_builtin_rules()
    findings = evaluate_rules(rules, tl)
    fired_ids = {f.rule_id for f in findings}
    assert "sensitive_file_read" not in fired_ids, (
        f"sensitive_file_read fired as FP on memory graph tools: {fired_ids}"
    )
