"""LLM backend Protocol and result types.

The driver is transport-agnostic so tests use a fake backend with
canned responses. The real implementation (litellm: works against any
provider key or local Ollama) lands at CLI wiring.

LLM tool-calling responses can include zero or more tool invocations.
The driver executes each against the MCP server and records the entire
exchange as ``llm.prompt_sent`` / ``llm.response_received`` /
``mcp.tool_invocation`` events with full causal links - so detection
rules can reason about "tool call triggered by adversarial prompt".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from nyuwaymcpsandbox.drivers.mcp_client import McpTool


@dataclass(frozen=True)
class LlmToolCall:
    """A single tool invocation the LLM wants to make."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class LlmResponse:
    """The LLM's reply to one prompt.

    ``text`` is the assistant's free-form output; ``tool_calls`` is the
    list of tool invocations the model requested. ``raw`` is the
    untouched provider response for any downstream inspection.
    """

    text: str = ""
    tool_calls: list[LlmToolCall] = field(default_factory=list)
    raw: dict | None = None


class LlmBackendError(Exception):
    """LLM backend construction or chat call failed."""


class LlmBackend(Protocol):
    """Minimal contract every LLM provider implementation must satisfy."""

    def chat(
        self,
        user_message: str,
        tools: list[McpTool],
        system_message: str = "",
    ) -> LlmResponse:  # pragma: no cover - protocol method
        ...
