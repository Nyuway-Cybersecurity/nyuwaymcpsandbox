"""Deterministic MCP harness.

Drives an MCP server with a fixed test plan: list its tools, then call
every one of them with a synthesized input. The server's actual
behaviour (network calls, file accesses, env reads, subprocess spawns)
is captured by the parallel monitors and evaluated by the detection
rules; this module's only job is to make sure those code paths run.

Every tool list and tool invocation is recorded into the supplied
BehavioralTimeline. Tool invocations are causally linked
(``triggered_by``) to the upstream tools/list event so detection rules
can reason about "this network call was triggered by an MCP tool
invocation, which was triggered by tools/list".

The harness also derives two timing-based behavioral signals:
``mcp.delayed_initialization`` (server stalled before responding to
tools/list) and ``mcp.slow_tool_response`` (a single tool call hung
for longer than the threshold). Both feed directly into detection rules.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from nyuwaymcpsandbox.drivers.mcp_client import McpClient, McpTool
from nyuwaymcpsandbox.drivers.synth import synthesize_input
from nyuwaymcpsandbox.sandbox.events import (
    EVT_MCP_DELAYED_INIT,
    EVT_MCP_SLOW_TOOL,
    EVT_MCP_TOOL_INVOKE,
    EVT_MCP_TOOL_LIST,
    SRC_MCP_CLIENT,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

# Default thresholds for the derived timing signals. Picked from real-world
# Phase 6 observations: mcp-server-kubernetes spent 2m38s before answering
# tools/list (network retries into a sinkhole); server-puppeteer's
# select/hover/evaluate each timed out at puppeteer's own 30s default.
SLOW_TOOL_THRESHOLD_SECONDS = 30.0
DELAYED_INIT_THRESHOLD_SECONDS = 60.0


@dataclass
class HarnessSummary:
    """Outcome of a deterministic run."""

    tool_count: int
    invocations_attempted: int
    invocations_failed: int


def run_deterministic_harness(
    client: McpClient,
    timeline: BehavioralTimeline,
    scan_start: float,
    triggered_by: str | None = None,
    slow_tool_threshold_seconds: float = SLOW_TOOL_THRESHOLD_SECONDS,
    delayed_init_threshold_seconds: float = DELAYED_INIT_THRESHOLD_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> HarnessSummary:
    """Probe every tool the MCP server declares.

    ``triggered_by`` is typically the container.started event id, so the
    tools/list event is anchored to the lifecycle, and the harness can
    look it up in the timeline to compute the delta between "container
    ready" and "MCP responsive".

    Errors raised by the client during list_tools are surfaced; per-tool
    invocation errors are recorded into the timeline (as the call's own
    event with an ``error`` payload field) but never raised - one
    broken tool must not stop the harness from probing the rest.

    ``clock`` defaults to time.monotonic and is injectable for tests
    that want deterministic timing of the derived signals.
    """
    # tools/list ----------------------------------------------------------
    list_call_started_at = clock()
    tools: list[McpTool] = client.list_tools()
    list_event_ts = clock() - scan_start
    list_event = BehavioralEvent(
        type=EVT_MCP_TOOL_LIST,
        source=SRC_MCP_CLIENT,
        timestamp=list_event_ts,
        payload={
            "tool_count": len(tools),
            "tools": [t.to_dict() for t in tools],
        },
        triggered_by=triggered_by,
    )
    timeline.add(list_event)

    # delayed_initialization signal --------------------------------------
    # The gap we care about is "container ready -> first MCP response".
    # When the harness was started from container_session it receives the
    # container.started event id; look it up in the timeline to get the
    # baseline. If the upstream event is not available, fall back to
    # "scan_start -> list_event" which still answers the same question
    # accurately within a sub-second margin.
    upstream_ts = _lookup_upstream_timestamp(timeline, triggered_by)
    if upstream_ts is None:
        startup_seconds = list_event_ts
    else:
        startup_seconds = list_event_ts - upstream_ts
    if startup_seconds >= delayed_init_threshold_seconds:
        timeline.add(
            BehavioralEvent(
                type=EVT_MCP_DELAYED_INIT,
                source=SRC_MCP_CLIENT,
                timestamp=list_event_ts,
                payload={
                    "startup_seconds": round(startup_seconds, 3),
                    "threshold_seconds": delayed_init_threshold_seconds,
                },
                triggered_by=triggered_by,
            )
        )

    attempted = 0
    failed = 0
    for tool in tools:
        attempted += 1
        arguments = synthesize_input(tool.input_schema)
        # Pre-call event timestamp captured before client.call_tool() so
        # rule evidence reflects when the harness issued the request.
        call_started_at = clock()
        call_event = BehavioralEvent(
            type=EVT_MCP_TOOL_INVOKE,
            source=SRC_MCP_CLIENT,
            timestamp=call_started_at - scan_start,
            payload={
                "name": tool.name,
                "arguments": arguments,
            },
            triggered_by=list_event.event_id,
        )
        timeline.add(call_event)

        try:
            result = client.call_tool(tool.name, arguments)
        except Exception as e:
            failed += 1
            duration_seconds = clock() - call_started_at
            # Mutate the existing event payload so causal links stay intact.
            call_event.payload["error"] = f"{type(e).__name__}: {e}"
            call_event.payload["duration_seconds"] = round(duration_seconds, 3)
            _maybe_emit_slow_tool(
                timeline=timeline,
                tool_name=tool.name,
                duration_seconds=duration_seconds,
                threshold_seconds=slow_tool_threshold_seconds,
                triggered_by=call_event.event_id,
                emit_at_ts=clock() - scan_start,
            )
            continue

        duration_seconds = clock() - call_started_at
        call_event.payload["duration_seconds"] = round(duration_seconds, 3)
        if result.error is not None:
            failed += 1
            call_event.payload["error"] = result.error
        else:
            # Capture a short summary of the response; full content is
            # intentionally omitted from the timeline to keep reports
            # readable. Output renderers can inspect detail elsewhere.
            content_summary = _summarize_content(result.content)
            call_event.payload["result_summary"] = content_summary
        _maybe_emit_slow_tool(
            timeline=timeline,
            tool_name=tool.name,
            duration_seconds=duration_seconds,
            threshold_seconds=slow_tool_threshold_seconds,
            triggered_by=call_event.event_id,
            emit_at_ts=clock() - scan_start,
        )

    # Use list_call_started_at to satisfy linters / for future use.
    _ = list_call_started_at

    return HarnessSummary(
        tool_count=len(tools),
        invocations_attempted=attempted,
        invocations_failed=failed,
    )


def _lookup_upstream_timestamp(
    timeline: BehavioralTimeline, event_id: str | None
) -> float | None:
    """Return the timestamp of the event whose id matches, or None."""
    if not event_id:
        return None
    for e in timeline.events:
        if e.event_id == event_id:
            return e.timestamp
    return None


def _maybe_emit_slow_tool(
    *,
    timeline: BehavioralTimeline,
    tool_name: str,
    duration_seconds: float,
    threshold_seconds: float,
    triggered_by: str,
    emit_at_ts: float,
) -> None:
    """Emit mcp.slow_tool_response when a single call crosses the threshold."""
    if duration_seconds < threshold_seconds:
        return
    timeline.add(
        BehavioralEvent(
            type=EVT_MCP_SLOW_TOOL,
            source=SRC_MCP_CLIENT,
            timestamp=emit_at_ts,
            payload={
                "name": tool_name,
                "duration_seconds": round(duration_seconds, 3),
                "threshold_seconds": threshold_seconds,
            },
            triggered_by=triggered_by,
        )
    )


def _summarize_content(content) -> str:
    """One-line summary of a tool's response content, for event payloads."""
    if content is None:
        return "<no content>"
    s = repr(content)
    if len(s) > 120:
        s = s[:117] + "..."
    return s
