"""Demo-only fakes used by --dry-run mode.

When the operator passes --dry-run the CLI skips the real container,
real MCP stdio transport, and real LLM backend - none of which can run
on a Windows dev box without Docker / a Linux MCP server / an LLM key
- and instead injects these canned implementations so the rest of the
pipeline runs end-to-end.

The fakes deliberately exercise patterns the detection rules look for
so a --dry-run produces a realistic-looking report: the fake MCP
server declares a "fetch_data" tool, and the fake LLM responds to
adversarial prompts by attempting tool calls. With the monitor stubs
emitting no events the rules won't fire, but the timeline and report
structure are real.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nyuwaymcpsandbox.drivers.llm_backend import LlmResponse, LlmToolCall
from nyuwaymcpsandbox.drivers.mcp_client import McpTool, McpToolResult


@dataclass
class FakeMcpClient:
    """In-memory MCP server with a single demo tool."""

    tools: list[McpTool] = field(
        default_factory=lambda: [
            McpTool(
                name="fetch_data",
                description="Fetch a URL and return its body",
                input_schema={
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
            )
        ]
    )

    def list_tools(self) -> list[McpTool]:
        return list(self.tools)

    def call_tool(self, name: str, arguments: dict) -> McpToolResult:
        return McpToolResult(
            name=name,
            content={"status": "dry_run", "echo": arguments},
        )


@dataclass
class FakeLlmBackend:
    """Stub backend that requests a single demo tool call for every prompt."""

    def chat(self, user_message: str, tools, system_message: str = "") -> LlmResponse:
        # If a tool exists, ask the LLM to call it - exercises the tool-call
        # branch of the LLM driver. Without tools, just echo the prompt.
        if tools:
            first = tools[0]
            return LlmResponse(
                text="Calling tool to satisfy the request.",
                tool_calls=[
                    LlmToolCall(
                        name=first.name,
                        arguments={"url": "https://nyuway-sandbox-probe.invalid/dry"},
                    )
                ],
            )
        return LlmResponse(text="No tools available; nothing to do.")


# ── Fake Docker client (for --dry-run) ────────────────────────────────────


@dataclass
class _FakeContainer:
    """A container that pretends to start and stop cleanly."""

    id: str = "dry-run-container"
    attrs: dict = field(default_factory=lambda: {"State": {"ExitCode": 0}})

    def stop(self, timeout: int = 5) -> None:
        return None

    def remove(self, force: bool = False) -> None:
        return None


@dataclass
class _FakeContainers:
    def run(self, **kwargs) -> _FakeContainer:
        return _FakeContainer()


@dataclass
class FakeDockerClient:
    """In-memory docker client used by --dry-run.

    The orchestrator's secure-defaults code path still runs (volume mode,
    cap_drop, network_mode, etc are all assembled) - we just don't talk
    to a real docker daemon.
    """

    containers: _FakeContainers = field(default_factory=_FakeContainers)


def fake_docker_client_factory() -> FakeDockerClient:
    return FakeDockerClient()
