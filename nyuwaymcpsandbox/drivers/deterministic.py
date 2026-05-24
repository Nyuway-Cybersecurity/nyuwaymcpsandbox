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
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from nyuwaymcpsandbox.drivers.mcp_client import McpClient, McpTool
from nyuwaymcpsandbox.drivers.synth import synthesize_input
from nyuwaymcpsandbox.sandbox.events import (
    EVT_MCP_TOOL_INVOKE,
    EVT_MCP_TOOL_LIST,
    SRC_MCP_CLIENT,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


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
) -> HarnessSummary:
    """Probe every tool the MCP server declares.

    ``triggered_by`` is typically the container.started event id, so the
    tools/list event is anchored to the lifecycle.

    Errors raised by the client during list_tools are surfaced; per-tool
    invocation errors are recorded into the timeline (as the call's own
    event with an ``error`` payload field) but never raised - one
    broken tool must not stop the harness from probing the rest.
    """
    # tools/list ----------------------------------------------------------
    tools: list[McpTool] = client.list_tools()
    list_event = BehavioralEvent(
        type=EVT_MCP_TOOL_LIST,
        source=SRC_MCP_CLIENT,
        timestamp=time.monotonic() - scan_start,
        payload={
            "tool_count": len(tools),
            "tools": [t.to_dict() for t in tools],
        },
        triggered_by=triggered_by,
    )
    timeline.add(list_event)

    attempted = 0
    failed = 0
    for tool in tools:
        attempted += 1
        arguments = synthesize_input(tool.input_schema)
        # Pre-call event timestamp captured before client.call_tool() so
        # rule evidence reflects when the harness issued the request.
        call_event = BehavioralEvent(
            type=EVT_MCP_TOOL_INVOKE,
            source=SRC_MCP_CLIENT,
            timestamp=time.monotonic() - scan_start,
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
            # Mutate the existing event payload so causal links stay intact.
            call_event.payload["error"] = f"{type(e).__name__}: {e}"
            continue

        if result.error is not None:
            failed += 1
            call_event.payload["error"] = result.error
        else:
            # Capture a short summary of the response; full content is
            # intentionally omitted from the timeline to keep reports
            # readable. Output renderers can inspect detail elsewhere.
            content_summary = _summarize_content(result.content)
            call_event.payload["result_summary"] = content_summary

    return HarnessSummary(
        tool_count=len(tools),
        invocations_attempted=attempted,
        invocations_failed=failed,
    )


def _summarize_content(content) -> str:
    """One-line summary of a tool's response content, for event payloads."""
    if content is None:
        return "<no content>"
    s = repr(content)
    if len(s) > 120:
        s = s[:117] + "..."
    return s
