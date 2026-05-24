"""LLM backend powered by litellm.

litellm is a thin provider-agnostic adapter: the same ``completion``
call works against Anthropic, OpenAI, Google, Cohere, local Ollama,
and a long list of others. The model identifier follows litellm's
convention (``provider/model`` for non-default routes, e.g.
``ollama/llama3``).

The MCP tool descriptors emitted by the deterministic harness are
translated into OpenAI-style function-call specs (which every
provider's tool-use surface speaks via litellm normalisation).
Responses are parsed back into the project's LlmResponse / LlmToolCall
types so the LLM driver doesn't care which provider produced them.

Tests inject ``completion_fn`` to skip the real network round-trip.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from nyuwaymcpsandbox.drivers.llm_backend import LlmBackendError, LlmResponse, LlmToolCall
from nyuwaymcpsandbox.drivers.mcp_client import McpTool

# CLI shortcut: --llm local maps to a sensible Ollama default so users
# don't have to remember the litellm prefix.
LOCAL_MODEL_ALIAS = "local"
DEFAULT_LOCAL_MODEL = "ollama/llama3"


def resolve_model(model: str) -> str:
    """Expand short aliases and return the canonical litellm model id."""
    if model == LOCAL_MODEL_ALIAS:
        return DEFAULT_LOCAL_MODEL
    return model


def mcp_tool_to_litellm_spec(tool: McpTool) -> dict:
    """Translate an MCP tool descriptor into an OpenAI-style function spec.

    Every provider's tool-use surface accepts this shape via litellm's
    normalisation. An empty input_schema is allowed; we substitute the
    minimal "object with no properties" schema so providers don't reject
    the call for a missing ``parameters`` field.
    """
    parameters = tool.input_schema if isinstance(tool.input_schema, dict) else None
    if not parameters:
        parameters = {"type": "object", "properties": {}}
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": parameters,
        },
    }


def _parse_tool_call(tc: Any) -> LlmToolCall | None:
    """Convert one litellm/OpenAI tool_call object into our LlmToolCall.

    Returns None if the call is malformed (e.g. missing function.name).
    Argument JSON is parsed leniently: invalid JSON degrades to {}
    rather than raising - one provider's quirky output should not blow
    up the whole prompt loop.
    """
    fn = getattr(tc, "function", None)
    if fn is None and isinstance(tc, dict):
        fn = tc.get("function")
    if fn is None:
        return None
    name = getattr(fn, "name", None) if not isinstance(fn, dict) else fn.get("name")
    if not name:
        return None
    args_raw = getattr(fn, "arguments", None) if not isinstance(fn, dict) else fn.get("arguments")
    arguments: dict
    if isinstance(args_raw, dict):
        arguments = args_raw
    elif isinstance(args_raw, str):
        try:
            parsed = json.loads(args_raw) if args_raw else {}
            arguments = parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            arguments = {}
    else:
        arguments = {}
    return LlmToolCall(name=name, arguments=arguments)


def _extract_message(response: Any) -> Any:
    """Locate the assistant message in a litellm response.

    Litellm mirrors OpenAI's shape: response.choices[0].message. Tests
    can pass plain dicts in the same shape; we handle both attribute
    and item access defensively.
    """
    choices = getattr(response, "choices", None)
    if choices is None and isinstance(response, dict):
        choices = response.get("choices")
    if not choices:
        return None
    first = choices[0]
    message = getattr(first, "message", None)
    if message is None and isinstance(first, dict):
        message = first.get("message")
    return message


def _parse_response(response: Any) -> LlmResponse:
    message = _extract_message(response)
    if message is None:
        return LlmResponse(text="", tool_calls=[], raw=None)
    text = getattr(message, "content", None)
    if text is None and isinstance(message, dict):
        text = message.get("content")
    text = text or ""

    tool_calls_raw = getattr(message, "tool_calls", None)
    if tool_calls_raw is None and isinstance(message, dict):
        tool_calls_raw = message.get("tool_calls")
    tool_calls: list[LlmToolCall] = []
    for tc in tool_calls_raw or []:
        parsed = _parse_tool_call(tc)
        if parsed is not None:
            tool_calls.append(parsed)
    return LlmResponse(text=text, tool_calls=tool_calls, raw=None)


def _lazy_litellm_completion() -> Callable:
    """Import litellm.completion on first use.

    Litellm has a heavy import chain (~seconds), so deferring keeps
    --dry-run runs snappy.
    """
    try:
        from litellm import completion  # type: ignore[import-untyped]
    except ImportError as e:  # pragma: no cover - environment dependent
        raise LlmBackendError(
            "litellm is not installed. Install with `pip install litellm`."
        ) from e
    return completion


class LiteLlmBackend:
    """LlmBackend implementation that routes through litellm.

    Parameters:
        model: litellm model id (e.g. 'claude-sonnet-4-5',
            'openai/gpt-4o', 'ollama/llama3'). The alias 'local' is
            expanded to ``ollama/llama3``.
        api_key: optional override. When None, litellm picks up the
            provider's standard environment variable.
        completion_fn: optional injection point; tests pass a fake.
    """

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        *,
        completion_fn: Callable | None = None,
    ) -> None:
        if not model:
            raise LlmBackendError("LiteLlmBackend requires a non-empty model id")
        self._model = resolve_model(model)
        self._api_key = api_key
        self._completion_fn = completion_fn

    def chat(
        self,
        user_message: str,
        tools: list[McpTool],
        system_message: str = "",
    ) -> LlmResponse:
        completion_fn = self._completion_fn or _lazy_litellm_completion()

        messages: list[dict] = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": user_message})

        kwargs: dict[str, Any] = {"model": self._model, "messages": messages}
        if tools:
            kwargs["tools"] = [mcp_tool_to_litellm_spec(t) for t in tools]
            kwargs["tool_choice"] = "auto"
        if self._api_key:
            kwargs["api_key"] = self._api_key

        try:
            response = completion_fn(**kwargs)
        except Exception as e:
            raise LlmBackendError(f"litellm completion failed: {e}") from e
        return _parse_response(response)

    @property
    def model(self) -> str:
        return self._model
