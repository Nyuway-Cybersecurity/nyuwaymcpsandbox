"""Tests for the deterministic MCP harness.

Uses a FakeMcpClient that lets each test assert exactly which calls
were made and inject failures at specific tools.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import pytest

from nyuwaymcpsandbox.drivers.deterministic import run_deterministic_harness
from nyuwaymcpsandbox.drivers.mcp_client import McpTool, McpToolResult
from nyuwaymcpsandbox.drivers.synth import PROBE_STRING
from nyuwaymcpsandbox.sandbox.events import (
    EVT_CONTAINER_STARTED,
    EVT_MCP_DELAYED_INIT,
    EVT_MCP_SLOW_TOOL,
    EVT_MCP_TOOL_INVOKE,
    EVT_MCP_TOOL_LIST,
    SRC_CONTAINER,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


@dataclass
class FakeMcpClient:
    tools: list[McpTool] = field(default_factory=list)
    # Optional: name -> result override.
    results: dict[str, McpToolResult] = field(default_factory=dict)
    # Optional: name -> exception to raise on call.
    call_exceptions: dict[str, Exception] = field(default_factory=dict)
    # Captured: every (name, arguments) pair we got.
    call_log: list[tuple[str, dict]] = field(default_factory=list)
    list_tools_raises: Exception | None = None

    def list_tools(self) -> list[McpTool]:
        if self.list_tools_raises:
            raise self.list_tools_raises
        return list(self.tools)

    def call_tool(self, name: str, arguments: dict) -> McpToolResult:
        self.call_log.append((name, arguments))
        if name in self.call_exceptions:
            raise self.call_exceptions[name]
        if name in self.results:
            return self.results[name]
        return McpToolResult(name=name, content=f"ok-{name}")


# ── tools/list event ─────────────────────────────────────────────────────


def test_emits_tool_list_event_with_zero_tools():
    timeline = BehavioralTimeline()
    client = FakeMcpClient(tools=[])
    summary = run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    list_events = [e for e in timeline.events if e.type == EVT_MCP_TOOL_LIST]
    assert len(list_events) == 1
    assert list_events[0].payload["tool_count"] == 0
    assert summary.tool_count == 0
    assert summary.invocations_attempted == 0


def test_emits_tool_list_event_with_tool_descriptors():
    timeline = BehavioralTimeline()
    client = FakeMcpClient(
        tools=[McpTool(name="fetch", description="Fetch URL"), McpTool(name="ls")]
    )
    run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    list_event = next(e for e in timeline.events if e.type == EVT_MCP_TOOL_LIST)
    names = [t["name"] for t in list_event.payload["tools"]]
    assert names == ["fetch", "ls"]


def test_tool_list_event_carries_triggered_by():
    timeline = BehavioralTimeline()
    client = FakeMcpClient(tools=[])
    upstream_id = "container-started-1234"
    run_deterministic_harness(
        client, timeline, scan_start=time.monotonic(), triggered_by=upstream_id
    )
    list_event = next(e for e in timeline.events if e.type == EVT_MCP_TOOL_LIST)
    assert list_event.triggered_by == upstream_id


# ── tool invocations ─────────────────────────────────────────────────────


def test_each_tool_gets_invoked_once():
    timeline = BehavioralTimeline()
    client = FakeMcpClient(tools=[McpTool(name="a"), McpTool(name="b"), McpTool(name="c")])
    run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    invokes = [e for e in timeline.events if e.type == EVT_MCP_TOOL_INVOKE]
    assert [e.payload["name"] for e in invokes] == ["a", "b", "c"]
    assert [c[0] for c in client.call_log] == ["a", "b", "c"]


def test_invocation_uses_synthesized_input():
    timeline = BehavioralTimeline()
    tool = McpTool(
        name="fetch",
        input_schema={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    )
    client = FakeMcpClient(tools=[tool])
    run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    assert client.call_log == [("fetch", {"url": PROBE_STRING})]


def test_invocation_event_links_back_to_tool_list():
    """Tool invocation event triggered_by must point at the tools/list event id."""
    timeline = BehavioralTimeline()
    client = FakeMcpClient(tools=[McpTool(name="a")])
    run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    list_event = next(e for e in timeline.events if e.type == EVT_MCP_TOOL_LIST)
    invoke = next(e for e in timeline.events if e.type == EVT_MCP_TOOL_INVOKE)
    assert invoke.triggered_by == list_event.event_id


def test_result_summary_recorded_on_success():
    timeline = BehavioralTimeline()
    client = FakeMcpClient(
        tools=[McpTool(name="a")],
        results={"a": McpToolResult(name="a", content={"status": "ok", "size": 42})},
    )
    run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    invoke = next(e for e in timeline.events if e.type == EVT_MCP_TOOL_INVOKE)
    assert "result_summary" in invoke.payload
    assert "ok" in invoke.payload["result_summary"]
    assert "error" not in invoke.payload


# ── Error handling ───────────────────────────────────────────────────────


def test_list_tools_failure_propagates():
    """If tools/list itself fails, the harness raises - nothing to probe."""
    timeline = BehavioralTimeline()
    client = FakeMcpClient(list_tools_raises=RuntimeError("transport broken"))
    with pytest.raises(RuntimeError, match="transport broken"):
        run_deterministic_harness(client, timeline, scan_start=time.monotonic())


def test_per_tool_exception_recorded_does_not_stop_harness():
    timeline = BehavioralTimeline()
    client = FakeMcpClient(
        tools=[McpTool(name="ok1"), McpTool(name="bad"), McpTool(name="ok2")],
        call_exceptions={"bad": ConnectionResetError("server died")},
    )
    summary = run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    invokes = [e for e in timeline.events if e.type == EVT_MCP_TOOL_INVOKE]
    by_name = {e.payload["name"]: e for e in invokes}
    # All three tools were attempted.
    assert set(by_name) == {"ok1", "bad", "ok2"}
    # Only the broken one carries an error field.
    assert "error" in by_name["bad"].payload
    assert "ConnectionResetError" in by_name["bad"].payload["error"]
    assert "error" not in by_name["ok1"].payload
    assert "error" not in by_name["ok2"].payload
    assert summary.invocations_failed == 1
    assert summary.invocations_attempted == 3


def test_server_returned_error_recorded():
    """A McpToolResult with an error field is recorded but doesn't crash."""
    timeline = BehavioralTimeline()
    client = FakeMcpClient(
        tools=[McpTool(name="a")],
        results={"a": McpToolResult(name="a", error="permission denied")},
    )
    summary = run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    invoke = next(e for e in timeline.events if e.type == EVT_MCP_TOOL_INVOKE)
    assert invoke.payload["error"] == "permission denied"
    assert summary.invocations_failed == 1


def test_summary_counts_match_events():
    timeline = BehavioralTimeline()
    client = FakeMcpClient(
        tools=[McpTool(name=f"t{i}") for i in range(5)],
        call_exceptions={"t2": RuntimeError("x")},
    )
    summary = run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    assert summary.tool_count == 5
    assert summary.invocations_attempted == 5
    assert summary.invocations_failed == 1


# ── Derived timing signals: mcp.slow_tool_response ───────────────────────


def _stepped_clock(steps):
    """Return a clock callable that advances through a fixed sequence."""
    state = {"i": 0, "steps": list(steps)}

    def _now() -> float:
        i = state["i"]
        if i >= len(state["steps"]):
            return state["steps"][-1]
        state["i"] += 1
        return state["steps"][i]

    return _now


def test_slow_tool_event_emitted_when_call_exceeds_threshold():
    """A single call_tool that takes >= threshold seconds emits one event.

    Clock-call ordering inside the harness for a one-tool successful run:
      1. list_call_started_at
      2. list_event_ts
      3. call_started_at
      4. clock used to compute duration_seconds (after call_tool returns)
      5. clock used to compute emit_at_ts (passed to _maybe_emit_slow_tool)
    """
    timeline = BehavioralTimeline()
    client = FakeMcpClient(tools=[McpTool(name="slow")])
    clock = _stepped_clock([100.0, 100.0, 100.0, 145.0, 145.0])
    run_deterministic_harness(
        client,
        timeline,
        scan_start=100.0,
        slow_tool_threshold_seconds=30.0,
        delayed_init_threshold_seconds=60.0,
        clock=clock,
    )
    slow_events = [e for e in timeline.events if e.type == EVT_MCP_SLOW_TOOL]
    assert len(slow_events) == 1
    payload = slow_events[0].payload
    assert payload["name"] == "slow"
    assert payload["duration_seconds"] == 45.0
    assert payload["threshold_seconds"] == 30.0


def test_fast_tool_does_not_emit_slow_event():
    """Calls under the threshold leave the slow_tool_response stream empty."""
    timeline = BehavioralTimeline()
    client = FakeMcpClient(tools=[McpTool(name="fast")])
    clock = _stepped_clock([100.0, 100.0, 100.0, 100.5, 100.5])
    run_deterministic_harness(
        client,
        timeline,
        scan_start=100.0,
        slow_tool_threshold_seconds=30.0,
        delayed_init_threshold_seconds=60.0,
        clock=clock,
    )
    assert [e for e in timeline.events if e.type == EVT_MCP_SLOW_TOOL] == []


def test_slow_tool_event_emitted_when_tool_raises():
    """A call_tool that raises after the threshold still emits the event."""
    timeline = BehavioralTimeline()
    client = FakeMcpClient(
        tools=[McpTool(name="hangs_then_fails")],
        call_exceptions={"hangs_then_fails": ConnectionResetError("hung")},
    )
    clock = _stepped_clock([100.0, 100.0, 100.0, 140.0, 140.0])
    run_deterministic_harness(
        client,
        timeline,
        scan_start=100.0,
        slow_tool_threshold_seconds=30.0,
        delayed_init_threshold_seconds=60.0,
        clock=clock,
    )
    slow_events = [e for e in timeline.events if e.type == EVT_MCP_SLOW_TOOL]
    assert len(slow_events) == 1
    assert slow_events[0].payload["name"] == "hangs_then_fails"


def test_slow_tool_event_triggered_by_call_event():
    """The slow_tool_response event must link back to the tool_invocation."""
    timeline = BehavioralTimeline()
    client = FakeMcpClient(tools=[McpTool(name="slow")])
    clock = _stepped_clock([100.0, 100.0, 100.0, 145.0, 145.0])
    run_deterministic_harness(
        client,
        timeline,
        scan_start=100.0,
        slow_tool_threshold_seconds=30.0,
        delayed_init_threshold_seconds=60.0,
        clock=clock,
    )
    invoke = next(e for e in timeline.events if e.type == EVT_MCP_TOOL_INVOKE)
    slow = next(e for e in timeline.events if e.type == EVT_MCP_SLOW_TOOL)
    assert slow.triggered_by == invoke.event_id


def test_duration_seconds_always_recorded_on_invocation_event():
    """Even fast calls should record duration_seconds for downstream tools."""
    timeline = BehavioralTimeline()
    client = FakeMcpClient(tools=[McpTool(name="a"), McpTool(name="b")])
    run_deterministic_harness(client, timeline, scan_start=time.monotonic())
    invokes = [e for e in timeline.events if e.type == EVT_MCP_TOOL_INVOKE]
    assert all("duration_seconds" in e.payload for e in invokes)
    assert all(isinstance(e.payload["duration_seconds"], float) for e in invokes)


# ── Derived timing signals: mcp.delayed_initialization ───────────────────


def test_delayed_init_emitted_when_startup_exceeds_threshold():
    """tools/list that completes more than threshold seconds after the upstream
    event fires an mcp.delayed_initialization event."""
    timeline = BehavioralTimeline()
    upstream = BehavioralEvent(
        type=EVT_CONTAINER_STARTED,
        source=SRC_CONTAINER,
        timestamp=0.0,
        payload={},
    )
    timeline.add(upstream)
    client = FakeMcpClient(tools=[])
    # First clock call sets list_call_started_at; second sets list_event_ts;
    # subsequent calls aren't needed because the tool list is empty.
    clock = _stepped_clock([100.0, 175.0])
    run_deterministic_harness(
        client,
        timeline,
        scan_start=100.0,
        triggered_by=upstream.event_id,
        slow_tool_threshold_seconds=30.0,
        delayed_init_threshold_seconds=60.0,
        clock=clock,
    )
    delayed = [e for e in timeline.events if e.type == EVT_MCP_DELAYED_INIT]
    assert len(delayed) == 1
    payload = delayed[0].payload
    assert payload["startup_seconds"] == 75.0
    assert payload["threshold_seconds"] == 60.0


def test_delayed_init_not_emitted_for_fast_startup():
    timeline = BehavioralTimeline()
    upstream = BehavioralEvent(
        type=EVT_CONTAINER_STARTED,
        source=SRC_CONTAINER,
        timestamp=0.0,
        payload={},
    )
    timeline.add(upstream)
    client = FakeMcpClient(tools=[])
    clock = _stepped_clock([100.0, 102.0])
    run_deterministic_harness(
        client,
        timeline,
        scan_start=100.0,
        triggered_by=upstream.event_id,
        slow_tool_threshold_seconds=30.0,
        delayed_init_threshold_seconds=60.0,
        clock=clock,
    )
    assert [e for e in timeline.events if e.type == EVT_MCP_DELAYED_INIT] == []


def test_delayed_init_uses_scan_start_when_upstream_missing():
    """No upstream id -> fall back to scan_start as the baseline."""
    timeline = BehavioralTimeline()
    client = FakeMcpClient(tools=[])
    clock = _stepped_clock([100.0, 175.0])
    run_deterministic_harness(
        client,
        timeline,
        scan_start=100.0,
        triggered_by=None,
        slow_tool_threshold_seconds=30.0,
        delayed_init_threshold_seconds=60.0,
        clock=clock,
    )
    delayed = [e for e in timeline.events if e.type == EVT_MCP_DELAYED_INIT]
    assert len(delayed) == 1
    assert delayed[0].payload["startup_seconds"] == 75.0


def test_delayed_init_links_back_to_upstream_event():
    timeline = BehavioralTimeline()
    upstream = BehavioralEvent(
        type=EVT_CONTAINER_STARTED,
        source=SRC_CONTAINER,
        timestamp=0.0,
        payload={},
    )
    timeline.add(upstream)
    client = FakeMcpClient(tools=[])
    clock = _stepped_clock([100.0, 175.0])
    run_deterministic_harness(
        client,
        timeline,
        scan_start=100.0,
        triggered_by=upstream.event_id,
        delayed_init_threshold_seconds=60.0,
        clock=clock,
    )
    delayed = next(e for e in timeline.events if e.type == EVT_MCP_DELAYED_INIT)
    assert delayed.triggered_by == upstream.event_id
