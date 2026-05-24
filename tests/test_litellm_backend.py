"""Tests for the litellm-backed LLM backend.

All tests inject ``completion_fn`` so no real provider is called.
The fake completion returns response objects in the same shape litellm
produces (choices[0].message.content + .tool_calls); both attribute
and dict-shaped responses are exercised to guard against provider
quirks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from nyuwaymcpsandbox.drivers.litellm_backend import (
    DEFAULT_LOCAL_MODEL,
    LiteLlmBackend,
    mcp_tool_to_litellm_spec,
    resolve_model,
)
from nyuwaymcpsandbox.drivers.llm_backend import LlmBackendError
from nyuwaymcpsandbox.drivers.mcp_client import McpTool

# ── Fake litellm response shape ──────────────────────────────────────────


@dataclass
class _FakeFunction:
    name: str
    arguments: str = "{}"


@dataclass
class _FakeToolCall:
    function: _FakeFunction
    id: str = "tc1"
    type: str = "function"


@dataclass
class _FakeMessage:
    content: str | None = None
    tool_calls: list[_FakeToolCall] | None = None


@dataclass
class _FakeChoice:
    message: _FakeMessage


@dataclass
class _FakeResponse:
    choices: list[_FakeChoice] = field(default_factory=list)


def _response(text: str = "", tool_calls: list[_FakeToolCall] | None = None) -> _FakeResponse:
    return _FakeResponse(choices=[_FakeChoice(_FakeMessage(content=text, tool_calls=tool_calls))])


# ── resolve_model ────────────────────────────────────────────────────────


def test_resolve_model_passes_through_explicit_id():
    assert resolve_model("claude-sonnet-4-5") == "claude-sonnet-4-5"
    assert resolve_model("openai/gpt-4o") == "openai/gpt-4o"


def test_resolve_model_expands_local_alias():
    assert resolve_model("local") == DEFAULT_LOCAL_MODEL


# ── mcp_tool_to_litellm_spec ─────────────────────────────────────────────


def test_tool_spec_carries_name_description_and_parameters():
    tool = McpTool(
        name="fetch",
        description="Fetch a URL",
        input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
    )
    spec = mcp_tool_to_litellm_spec(tool)
    assert spec["type"] == "function"
    assert spec["function"]["name"] == "fetch"
    assert spec["function"]["description"] == "Fetch a URL"
    assert spec["function"]["parameters"]["properties"]["url"] == {"type": "string"}


def test_tool_spec_substitutes_empty_schema_when_missing():
    """A missing input_schema must produce a valid empty-object spec."""
    tool = McpTool(name="noargs", description="", input_schema=None)
    spec = mcp_tool_to_litellm_spec(tool)
    assert spec["function"]["parameters"] == {"type": "object", "properties": {}}


def test_tool_spec_non_dict_schema_treated_as_missing():
    tool = McpTool(name="bad", input_schema="not a dict")  # type: ignore[arg-type]
    spec = mcp_tool_to_litellm_spec(tool)
    assert spec["function"]["parameters"] == {"type": "object", "properties": {}}


# ── LiteLlmBackend construction ──────────────────────────────────────────


def test_empty_model_raises_backend_error():
    with pytest.raises(LlmBackendError, match="non-empty model"):
        LiteLlmBackend(model="")


def test_local_alias_expanded_at_construction():
    backend = LiteLlmBackend(model="local", completion_fn=lambda **kw: _response())
    assert backend.model == DEFAULT_LOCAL_MODEL


def test_construction_preserves_explicit_model_id():
    backend = LiteLlmBackend(model="claude-sonnet-4-5", completion_fn=lambda **kw: _response())
    assert backend.model == "claude-sonnet-4-5"


# ── chat: messages + tools wiring ────────────────────────────────────────


def test_chat_sends_user_message_only_when_no_system():
    captured: dict[str, Any] = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return _response("ok")

    backend = LiteLlmBackend(model="claude-sonnet-4-5", completion_fn=fake)
    backend.chat(user_message="hello", tools=[])
    assert captured["messages"] == [{"role": "user", "content": "hello"}]
    # No tools -> no tools kwarg.
    assert "tools" not in captured
    assert "tool_choice" not in captured


def test_chat_prepends_system_message_when_provided():
    captured: dict[str, Any] = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return _response("ok")

    backend = LiteLlmBackend(model="x", completion_fn=fake)
    backend.chat(user_message="hi", tools=[], system_message="be concise")
    assert captured["messages"][0] == {"role": "system", "content": "be concise"}
    assert captured["messages"][1] == {"role": "user", "content": "hi"}


def test_chat_passes_tool_specs_when_tools_present():
    captured: dict[str, Any] = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return _response("ok")

    backend = LiteLlmBackend(model="x", completion_fn=fake)
    backend.chat(
        user_message="hi",
        tools=[McpTool(name="t1", description="d", input_schema={"type": "object"})],
    )
    assert "tools" in captured
    assert captured["tool_choice"] == "auto"
    assert captured["tools"][0]["function"]["name"] == "t1"


def test_chat_passes_api_key_when_provided():
    captured: dict[str, Any] = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return _response("ok")

    backend = LiteLlmBackend(model="x", api_key="sk-abc", completion_fn=fake)
    backend.chat(user_message="hi", tools=[])
    assert captured["api_key"] == "sk-abc"


def test_chat_omits_api_key_when_not_provided():
    captured: dict[str, Any] = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return _response("ok")

    backend = LiteLlmBackend(model="x", api_key=None, completion_fn=fake)
    backend.chat(user_message="hi", tools=[])
    assert "api_key" not in captured


# ── chat: response parsing ───────────────────────────────────────────────


def test_chat_returns_text_response():
    backend = LiteLlmBackend(model="x", completion_fn=lambda **kw: _response(text="hello world"))
    result = backend.chat(user_message="hi", tools=[])
    assert result.text == "hello world"
    assert result.tool_calls == []


def test_chat_extracts_tool_call_with_parsed_arguments():
    tc = _FakeToolCall(function=_FakeFunction(name="fetch", arguments='{"url":"evil.com"}'))
    backend = LiteLlmBackend(
        model="x", completion_fn=lambda **kw: _response(text="ok", tool_calls=[tc])
    )
    result = backend.chat(user_message="hi", tools=[])
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "fetch"
    assert result.tool_calls[0].arguments == {"url": "evil.com"}


def test_chat_handles_empty_argument_string():
    tc = _FakeToolCall(function=_FakeFunction(name="noargs", arguments=""))
    backend = LiteLlmBackend(
        model="x", completion_fn=lambda **kw: _response(text="ok", tool_calls=[tc])
    )
    result = backend.chat(user_message="hi", tools=[])
    assert result.tool_calls[0].arguments == {}


def test_chat_handles_invalid_argument_json_leniently():
    """Provider quirk: malformed JSON args should degrade to {} not raise."""
    tc = _FakeToolCall(function=_FakeFunction(name="x", arguments="not valid"))
    backend = LiteLlmBackend(
        model="x", completion_fn=lambda **kw: _response(text="ok", tool_calls=[tc])
    )
    result = backend.chat(user_message="hi", tools=[])
    assert result.tool_calls[0].arguments == {}


def test_chat_handles_dict_arguments_directly():
    """Some providers may already pass parsed dict; we should accept it."""

    class _DictArgsToolCall:
        function = type("F", (), {"name": "x", "arguments": {"a": 1}})()

    backend = LiteLlmBackend(
        model="x",
        completion_fn=lambda **kw: _FakeResponse(
            choices=[_FakeChoice(_FakeMessage(content="ok", tool_calls=[_DictArgsToolCall()]))]
        ),
    )
    result = backend.chat(user_message="hi", tools=[])
    assert result.tool_calls[0].arguments == {"a": 1}


def test_chat_handles_multiple_tool_calls():
    tcs = [
        _FakeToolCall(function=_FakeFunction(name="a", arguments='{"x":1}')),
        _FakeToolCall(function=_FakeFunction(name="b", arguments='{"y":2}')),
    ]
    backend = LiteLlmBackend(
        model="x", completion_fn=lambda **kw: _response(text="ok", tool_calls=tcs)
    )
    result = backend.chat(user_message="hi", tools=[])
    assert [c.name for c in result.tool_calls] == ["a", "b"]


def test_chat_drops_tool_call_with_missing_function_name():
    """A malformed tool call from a provider must not crash the driver."""
    bad = _FakeToolCall(function=_FakeFunction(name="", arguments="{}"))
    good = _FakeToolCall(function=_FakeFunction(name="ok", arguments="{}"))
    backend = LiteLlmBackend(
        model="x", completion_fn=lambda **kw: _response(text="hi", tool_calls=[bad, good])
    )
    result = backend.chat(user_message="hi", tools=[])
    assert [c.name for c in result.tool_calls] == ["ok"]


def test_chat_handles_none_content_as_empty_string():
    backend = LiteLlmBackend(model="x", completion_fn=lambda **kw: _response(text=None))
    result = backend.chat(user_message="hi", tools=[])
    assert result.text == ""


def test_chat_handles_response_without_choices():
    """A degenerate response (empty choices) returns an empty LlmResponse."""
    backend = LiteLlmBackend(model="x", completion_fn=lambda **kw: _FakeResponse(choices=[]))
    result = backend.chat(user_message="hi", tools=[])
    assert result.text == ""
    assert result.tool_calls == []


def test_chat_handles_dict_shaped_response():
    """A provider returning a plain dict (rather than attrs) must also parse."""

    def fake(**kwargs):
        return {
            "choices": [
                {
                    "message": {
                        "content": "dict-mode",
                        "tool_calls": [{"function": {"name": "t", "arguments": '{"k":1}'}}],
                    }
                }
            ]
        }

    backend = LiteLlmBackend(model="x", completion_fn=fake)
    result = backend.chat(user_message="hi", tools=[])
    assert result.text == "dict-mode"
    assert result.tool_calls[0].name == "t"
    assert result.tool_calls[0].arguments == {"k": 1}


# ── chat: error mapping ──────────────────────────────────────────────────


def test_chat_wraps_completion_exception_in_backend_error():
    def fake(**kwargs):
        raise RuntimeError("rate limited")

    backend = LiteLlmBackend(model="x", completion_fn=fake)
    with pytest.raises(LlmBackendError, match="rate limited"):
        backend.chat(user_message="hi", tools=[])
