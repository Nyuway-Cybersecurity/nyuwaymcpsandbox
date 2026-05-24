"""Full-mode LLM driver.

Connects to the running MCP server as a client and exercises it under
adversarial conditions:

1. Load the bundled adversarial prompt library.
2. Get the MCP server's declared tools (so the LLM knows what's callable).
3. For each prompt: send it to the LLM with the tool list available; if
   the LLM requests a tool call, execute it against the MCP server.
4. Record every prompt sent, response received, and tool invocation
   into the BehavioralTimeline with full causal links.

Detection rules can then reason about chains like "outbound HTTP call
-> MCP tool invocation -> LLM response -> adversarial prompt", which
is the signature of tool poisoning surfacing under live LLM control.

For v1 this is a single-turn driver: one prompt -> LLM response with
zero or more tool calls -> tool calls executed -> done. Multi-turn
conversations land in v2 alongside the eBPF tracer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from nyuwaymcpsandbox.drivers.llm_backend import LlmBackend
from nyuwaymcpsandbox.drivers.mcp_client import McpClient
from nyuwaymcpsandbox.drivers.prompt_library import AdversarialPrompt
from nyuwaymcpsandbox.sandbox.events import (
    EVT_LLM_PROMPT_SENT,
    EVT_LLM_RESPONSE,
    EVT_MCP_TOOL_INVOKE,
    SRC_LLM_DRIVER,
    SRC_MCP_CLIENT,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

# Default system message framing the LLM as a tool-using agent. Kept
# intentionally neutral so the adversarial prompts have to do the work.
DEFAULT_SYSTEM_MESSAGE = (
    "You are an autonomous AI assistant with access to MCP tools. "
    "Use tools when the user's request would benefit from them. "
    "Be concise."
)


@dataclass
class LlmDriverSummary:
    """Outcome of one Full-mode driver run."""

    prompts_sent: int
    responses_received: int
    tool_calls_made: int
    backend_errors: int


def run_llm_driver(
    llm: LlmBackend,
    mcp: McpClient,
    prompts: list[AdversarialPrompt],
    timeline: BehavioralTimeline,
    scan_start: float,
    triggered_by: str | None = None,
) -> LlmDriverSummary:
    """Drive the MCP server with the adversarial prompt library.

    ``triggered_by`` is typically the container.started event id so the
    Full-mode events are anchored to the lifecycle.

    Per-prompt failures (backend errors, tool-call failures) are recorded
    as event payload fields but never raised - one bad prompt or one
    broken tool can't stop the rest of the run.
    """
    # Discover tools once at the start so the LLM sees the same surface
    # the deterministic harness saw.
    try:
        tools = mcp.list_tools()
    except Exception as e:
        # Without a tool list, the driver can't function - tools may be
        # mid-init or the MCP transport is broken. Record the failure
        # as a single prompt-error event and return early.
        timeline.add(
            BehavioralEvent(
                type=EVT_LLM_PROMPT_SENT,
                source=SRC_LLM_DRIVER,
                timestamp=time.monotonic() - scan_start,
                payload={
                    "error": f"could not list MCP tools: {type(e).__name__}: {e}",
                },
                triggered_by=triggered_by,
            )
        )
        return LlmDriverSummary(
            prompts_sent=0,
            responses_received=0,
            tool_calls_made=0,
            backend_errors=1,
        )

    prompts_sent = 0
    responses_received = 0
    tool_calls_made = 0
    backend_errors = 0

    for prompt in prompts:
        prompts_sent += 1
        prompt_event = BehavioralEvent(
            type=EVT_LLM_PROMPT_SENT,
            source=SRC_LLM_DRIVER,
            timestamp=time.monotonic() - scan_start,
            payload={
                "prompt_id": prompt.id,
                "category": prompt.category,
                "summary": _summarise(prompt.user_message),
            },
            triggered_by=triggered_by,
        )
        timeline.add(prompt_event)

        system_message = prompt.system_message or DEFAULT_SYSTEM_MESSAGE
        try:
            response = llm.chat(
                user_message=prompt.user_message,
                tools=tools,
                system_message=system_message,
            )
        except Exception as e:
            backend_errors += 1
            # Mutate the prompt event so the error is anchored to the
            # call site instead of a free-floating event.
            prompt_event.payload["error"] = f"backend: {type(e).__name__}: {e}"
            continue

        responses_received += 1
        response_event = BehavioralEvent(
            type=EVT_LLM_RESPONSE,
            source=SRC_LLM_DRIVER,
            timestamp=time.monotonic() - scan_start,
            payload={
                "prompt_id": prompt.id,
                "summary": _summarise(response.text),
                "tool_call_count": len(response.tool_calls),
            },
            triggered_by=prompt_event.event_id,
        )
        timeline.add(response_event)

        # Execute every tool call the LLM requested. Each becomes its
        # own mcp.tool_invocation event triggered_by the LLM response,
        # so detection rules see the full chain.
        for tool_call in response.tool_calls:
            tool_calls_made += 1
            tool_event = BehavioralEvent(
                type=EVT_MCP_TOOL_INVOKE,
                source=SRC_MCP_CLIENT,
                timestamp=time.monotonic() - scan_start,
                payload={
                    "name": tool_call.name,
                    "arguments": dict(tool_call.arguments),
                    "driver": "llm",
                },
                triggered_by=response_event.event_id,
            )
            timeline.add(tool_event)
            try:
                result = mcp.call_tool(tool_call.name, dict(tool_call.arguments))
            except Exception as e:
                tool_event.payload["error"] = f"{type(e).__name__}: {e}"
                continue
            if result.error is not None:
                tool_event.payload["error"] = result.error
            else:
                tool_event.payload["result_summary"] = _summarise(repr(result.content))

    return LlmDriverSummary(
        prompts_sent=prompts_sent,
        responses_received=responses_received,
        tool_calls_made=tool_calls_made,
        backend_errors=backend_errors,
    )


def _summarise(text: str, limit: int = 160) -> str:
    """One-line summary suitable for event payloads."""
    if not text:
        return ""
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 3] + "..."
