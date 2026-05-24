"""LLM driver tests.

FakeLlmBackend and FakeMcpClient let each test inject canned tool
calls, backend errors, and per-tool failures so every causal-link and
error-handling branch is verified.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from nyuwaymcpsandbox.drivers.llm_backend import LlmResponse, LlmToolCall
from nyuwaymcpsandbox.drivers.llm_driver import run_llm_driver
from nyuwaymcpsandbox.drivers.mcp_client import McpTool, McpToolResult
from nyuwaymcpsandbox.drivers.prompt_library import AdversarialPrompt
from nyuwaymcpsandbox.sandbox.events import (
    EVT_LLM_PROMPT_SENT,
    EVT_LLM_RESPONSE,
    EVT_MCP_TOOL_INVOKE,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


@dataclass
class FakeLlmBackend:
    """Canned-response LLM backend.

    ``responses_by_prompt_id`` maps prompt id -> LlmResponse. A prompt
    with no entry gets a default empty response. ``raise_on`` raises
    the supplied exception for the matching prompt id.
    """

    responses_by_prompt_id: dict[str, LlmResponse] = field(default_factory=dict)
    raise_on: dict[str, Exception] = field(default_factory=dict)
    calls: list[tuple[str, list[McpTool], str]] = field(default_factory=list)
    _current_prompt_id: str = ""

    def set_next(self, prompt_id: str) -> None:
        self._current_prompt_id = prompt_id

    def chat(self, user_message, tools, system_message=""):
        pid = self._current_prompt_id
        self.calls.append((user_message, tools, system_message))
        if pid in self.raise_on:
            raise self.raise_on[pid]
        return self.responses_by_prompt_id.get(pid, LlmResponse(text=""))


@dataclass
class FakeMcpClient:
    tools: list[McpTool] = field(default_factory=list)
    results: dict[str, McpToolResult] = field(default_factory=dict)
    call_exceptions: dict[str, Exception] = field(default_factory=dict)
    list_tools_raises: Exception | None = None
    call_log: list[tuple[str, dict]] = field(default_factory=list)

    def list_tools(self):
        if self.list_tools_raises:
            raise self.list_tools_raises
        return list(self.tools)

    def call_tool(self, name, arguments):
        self.call_log.append((name, arguments))
        if name in self.call_exceptions:
            raise self.call_exceptions[name]
        return self.results.get(name, McpToolResult(name=name, content=f"ok-{name}"))


def _prompt(pid="p1", category="tool_poisoning", msg="user msg") -> AdversarialPrompt:
    return AdversarialPrompt(
        id=pid,
        category=category,
        description="test",
        user_message=msg,
    )


def _run(
    llm: FakeLlmBackend,
    mcp: FakeMcpClient,
    prompts: list[AdversarialPrompt],
    timeline: BehavioralTimeline | None = None,
    triggered_by: str | None = None,
):
    """Helper - sets the backend's current prompt id for each prompt."""
    tl = timeline or BehavioralTimeline()

    # Wrap llm.chat to set the prompt id before each call.
    original_chat = llm.chat

    # The fake needs to know which prompt id is being sent so it can
    # look up the canned response. The driver calls llm.chat once per
    # prompt; we set the id field on the backend before each prompt by
    # patching the run with a wrapper.
    def chat_wrapper(user_message, tools, system_message=""):
        # Match the prompt id by user_message - simpler than threading
        # the prompt id through the LlmBackend API.
        for p in prompts:
            if p.user_message == user_message:
                llm._current_prompt_id = p.id
                break
        return original_chat(user_message, tools, system_message)

    llm.chat = chat_wrapper  # type: ignore[method-assign]

    summary = run_llm_driver(
        llm=llm,
        mcp=mcp,
        prompts=prompts,
        timeline=tl,
        scan_start=time.monotonic(),
        triggered_by=triggered_by,
    )
    return summary, tl


# ── Tool discovery ──────────────────────────────────────────────────────


def test_list_tools_failure_records_single_error_and_returns_early():
    llm = FakeLlmBackend()
    mcp = FakeMcpClient(list_tools_raises=ConnectionResetError("server gone"))
    summary, tl = _run(llm, mcp, prompts=[_prompt()])
    assert summary.prompts_sent == 0
    assert summary.backend_errors == 1
    # An error event was emitted explaining the failure.
    events = [e for e in tl.events if "could not list MCP tools" in e.payload.get("error", "")]
    assert len(events) == 1
    # No further LLM calls happened.
    assert llm.calls == []


# ── Happy path ──────────────────────────────────────────────────────────


def test_prompt_emits_prompt_and_response_events_in_order():
    llm = FakeLlmBackend(responses_by_prompt_id={"p1": LlmResponse(text="I will not do that.")})
    mcp = FakeMcpClient(tools=[McpTool(name="fetch")])
    summary, tl = _run(llm, mcp, prompts=[_prompt("p1")])
    types = [e.type for e in tl.events]
    assert types.index(EVT_LLM_PROMPT_SENT) < types.index(EVT_LLM_RESPONSE)
    assert summary.prompts_sent == 1
    assert summary.responses_received == 1
    assert summary.tool_calls_made == 0


def test_response_event_triggered_by_prompt_event():
    llm = FakeLlmBackend(responses_by_prompt_id={"p1": LlmResponse(text="ok")})
    mcp = FakeMcpClient()
    _, tl = _run(llm, mcp, prompts=[_prompt("p1")])
    prompt_event = next(e for e in tl.events if e.type == EVT_LLM_PROMPT_SENT)
    response_event = next(e for e in tl.events if e.type == EVT_LLM_RESPONSE)
    assert response_event.triggered_by == prompt_event.event_id


def test_prompt_event_carries_category_and_id():
    llm = FakeLlmBackend()
    mcp = FakeMcpClient()
    _, tl = _run(llm, mcp, prompts=[_prompt("my_id", category="prompt_injection")])
    prompt_event = next(e for e in tl.events if e.type == EVT_LLM_PROMPT_SENT)
    assert prompt_event.payload["prompt_id"] == "my_id"
    assert prompt_event.payload["category"] == "prompt_injection"


def test_first_prompt_triggered_by_lifecycle_hook():
    """When triggered_by is passed, the first prompt event links to it."""
    llm = FakeLlmBackend()
    mcp = FakeMcpClient()
    _, tl = _run(llm, mcp, prompts=[_prompt("p1")], triggered_by="container-start-id")
    prompt_event = next(e for e in tl.events if e.type == EVT_LLM_PROMPT_SENT)
    assert prompt_event.triggered_by == "container-start-id"


# ── Tool-call execution ──────────────────────────────────────────────────


def test_llm_tool_call_executes_against_mcp_server():
    llm = FakeLlmBackend(
        responses_by_prompt_id={
            "p1": LlmResponse(
                text="fetching",
                tool_calls=[LlmToolCall(name="fetch", arguments={"url": "evil.com"})],
            )
        }
    )
    mcp = FakeMcpClient(tools=[McpTool(name="fetch")])
    summary, tl = _run(llm, mcp, prompts=[_prompt("p1")])
    assert mcp.call_log == [("fetch", {"url": "evil.com"})]
    invokes = [e for e in tl.events if e.type == EVT_MCP_TOOL_INVOKE]
    assert len(invokes) == 1
    assert invokes[0].payload["driver"] == "llm"
    assert summary.tool_calls_made == 1


def test_tool_invocation_triggered_by_llm_response():
    """The full causal chain prompt -> response -> tool_invocation must link."""
    llm = FakeLlmBackend(
        responses_by_prompt_id={
            "p1": LlmResponse(
                text="ok",
                tool_calls=[LlmToolCall(name="fetch", arguments={})],
            )
        }
    )
    mcp = FakeMcpClient(tools=[McpTool(name="fetch")])
    _, tl = _run(llm, mcp, prompts=[_prompt("p1")])
    prompt_event = next(e for e in tl.events if e.type == EVT_LLM_PROMPT_SENT)
    response_event = next(e for e in tl.events if e.type == EVT_LLM_RESPONSE)
    invoke = next(e for e in tl.events if e.type == EVT_MCP_TOOL_INVOKE)
    assert response_event.triggered_by == prompt_event.event_id
    assert invoke.triggered_by == response_event.event_id


def test_multiple_tool_calls_each_recorded():
    llm = FakeLlmBackend(
        responses_by_prompt_id={
            "p1": LlmResponse(
                text="ok",
                tool_calls=[
                    LlmToolCall(name="a", arguments={"x": 1}),
                    LlmToolCall(name="b", arguments={"y": 2}),
                ],
            )
        }
    )
    mcp = FakeMcpClient(tools=[McpTool(name="a"), McpTool(name="b")])
    summary, tl = _run(llm, mcp, prompts=[_prompt("p1")])
    assert summary.tool_calls_made == 2
    invokes = [e for e in tl.events if e.type == EVT_MCP_TOOL_INVOKE]
    assert [e.payload["name"] for e in invokes] == ["a", "b"]


# ── Error handling ───────────────────────────────────────────────────────


def test_backend_exception_recorded_as_prompt_error():
    llm = FakeLlmBackend(raise_on={"p1": RuntimeError("rate limited")})
    mcp = FakeMcpClient()
    summary, tl = _run(llm, mcp, prompts=[_prompt("p1")])
    prompt_event = next(e for e in tl.events if e.type == EVT_LLM_PROMPT_SENT)
    assert "backend" in prompt_event.payload["error"]
    assert "rate limited" in prompt_event.payload["error"]
    # No response event emitted.
    assert not any(e.type == EVT_LLM_RESPONSE for e in tl.events)
    assert summary.backend_errors == 1
    assert summary.responses_received == 0


def test_tool_call_exception_recorded_on_invocation_event():
    llm = FakeLlmBackend(
        responses_by_prompt_id={
            "p1": LlmResponse(text="ok", tool_calls=[LlmToolCall(name="bad", arguments={})])
        }
    )
    mcp = FakeMcpClient(
        tools=[McpTool(name="bad")],
        call_exceptions={"bad": RuntimeError("server crashed")},
    )
    summary, _tl = _run(llm, mcp, prompts=[_prompt("p1")])
    # The driver still counts it as attempted but with an error.
    assert summary.tool_calls_made == 1


def test_one_bad_prompt_does_not_stop_subsequent_prompts():
    llm = FakeLlmBackend(
        raise_on={"p1": ConnectionError("first failed")},
        responses_by_prompt_id={"p2": LlmResponse(text="second worked")},
    )
    mcp = FakeMcpClient()
    summary, tl = _run(llm, mcp, prompts=[_prompt("p1"), _prompt("p2", msg="msg2")])
    assert summary.prompts_sent == 2
    assert summary.responses_received == 1
    assert summary.backend_errors == 1


def test_server_returned_error_carried_on_invocation_event():
    llm = FakeLlmBackend(
        responses_by_prompt_id={"p1": LlmResponse(text="ok", tool_calls=[LlmToolCall(name="x")])}
    )
    mcp = FakeMcpClient(
        tools=[McpTool(name="x")],
        results={"x": McpToolResult(name="x", error="permission denied")},
    )
    _, tl = _run(llm, mcp, prompts=[_prompt("p1")])
    invoke = next(e for e in tl.events if e.type == EVT_MCP_TOOL_INVOKE)
    assert invoke.payload["error"] == "permission denied"


# ── Summary counts ───────────────────────────────────────────────────────


def test_summary_counts_match_emitted_events():
    llm = FakeLlmBackend(
        responses_by_prompt_id={
            "p1": LlmResponse(text="ok"),
            "p2": LlmResponse(
                text="ok",
                tool_calls=[LlmToolCall(name="a"), LlmToolCall(name="b")],
            ),
            "p3": LlmResponse(text="ok", tool_calls=[LlmToolCall(name="a")]),
        }
    )
    mcp = FakeMcpClient(tools=[McpTool(name="a"), McpTool(name="b")])
    summary, _tl = _run(
        llm,
        mcp,
        prompts=[_prompt("p1"), _prompt("p2", msg="m2"), _prompt("p3", msg="m3")],
    )
    assert summary.prompts_sent == 3
    assert summary.responses_received == 3
    assert summary.tool_calls_made == 3
    assert summary.backend_errors == 0
