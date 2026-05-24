"""MCP client abstractions used by the deterministic harness and LLM driver.

Defines a transport-agnostic Protocol so the orchestration logic can be
tested against a fake client. The concrete stdio implementation that
talks to the container lands when the CLI wires this up against
docker-py's exec API in step 9.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class McpTool:
    """A tool declared by an MCP server, returned from tools/list."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


@dataclass
class McpToolResult:
    """Result of calling a single MCP tool.

    Either ``content`` is set (success) or ``error`` is set (server-side or
    transport-level failure). ``raw`` carries the unparsed response for
    detection rules that want to look at the original JSON-RPC envelope.
    """

    name: str
    content: Any = None
    error: str | None = None
    raw: dict | None = None


class McpClient(Protocol):
    """Minimal MCP transport contract.

    Implementations: stdio (talks JSON-RPC to a process in the container),
    fake (in-memory, for tests), and v1.1 SSE/HTTP.
    """

    def list_tools(self) -> list[McpTool]:  # pragma: no cover - protocol method
        ...

    def call_tool(self, name: str, arguments: dict) -> McpToolResult:  # pragma: no cover
        ...
