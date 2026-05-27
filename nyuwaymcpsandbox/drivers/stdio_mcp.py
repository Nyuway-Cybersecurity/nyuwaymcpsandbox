"""Real MCP client over a stdio JSON-RPC stream.

Implements the MCP protocol's three operational concerns we need today:

1. ``initialize`` handshake (request + notifications/initialized).
2. ``tools/list`` to discover the server's declared tools.
3. ``tools/call`` to invoke a tool with arguments.

The transport is abstracted behind ``StdioStream``: any duplex byte
stream with line-oriented framing satisfies it. Production
implementations include SubprocessStdioStream (host subprocess) and
DockerExecStdioStream (sandboxed via docker exec, lands separately).

The MCP wire format is newline-delimited JSON-RPC 2.0. Each line is
exactly one JSON value; the server's stdout is the response channel,
its stdin is the request channel. We tolerate ``\\r\\n`` and ``\\n``
line endings on read - Windows servers that don't reconfigure stdout
to binary mode would otherwise emit ``\\r\\n``.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from nyuwaymcpsandbox.drivers.mcp_client import McpTool, McpToolResult

PROTOCOL_VERSION = "2024-11-05"


class McpTransportError(Exception):
    """Stdio transport failure: stream closed, bad JSON, write error."""


class McpRpcError(Exception):
    """The MCP server returned a JSON-RPC error response."""

    def __init__(self, code: int, message: str, raw: dict | None = None) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.raw = raw


class StdioStream(Protocol):
    """A duplex byte stream with line-oriented framing.

    ``read_line`` returns the next line as bytes WITHOUT the trailing
    newline. Returning ``b""`` signals EOF. ``write`` accepts raw bytes
    that the caller has already framed with a trailing newline.
    """

    def read_line(self) -> bytes:  # pragma: no cover - protocol method
        ...

    def write(self, data: bytes) -> None:  # pragma: no cover - protocol method
        ...

    def close(self) -> None:  # pragma: no cover - protocol method
        ...


class StdioMcpClient:
    """McpClient implementation over a StdioStream.

    Lazy initialization: list_tools and call_tool both run the
    handshake if it hasn't happened yet. Direct call to initialize()
    is optional and idempotent.

    Concurrency: one request at a time. MCP allows interleaving of
    requests by id, but the v1 drivers are strictly sequential so we
    don't bother with a request map - we just skip lines that don't
    match the expected id.
    """

    def __init__(
        self,
        stream: StdioStream,
        *,
        client_name: str = "nyuwaymcpsandbox",
        client_version: str = "1.0.0",
    ) -> None:
        self._stream = stream
        self._next_id = 1
        self._initialized = False
        self._client_name = client_name
        self._client_version = client_version

    # ── Public API (McpClient) ──────────────────────────────────────────

    def initialize(self) -> dict:
        """Run the MCP initialize handshake. Idempotent."""
        if self._initialized:
            return {}
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": self._client_name,
                    "version": self._client_version,
                },
            },
        )
        # Initialized notification has no id and expects no response.
        self._notify("notifications/initialized")
        self._initialized = True
        return result

    def list_tools(self) -> list[McpTool]:
        if not self._initialized:
            self.initialize()
        result = self._request("tools/list")
        tools: list[McpTool] = []
        for raw in result.get("tools", []) or []:
            tools.append(
                McpTool(
                    name=raw.get("name", ""),
                    description=raw.get("description", "") or "",
                    input_schema=raw.get("inputSchema"),
                )
            )
        return tools

    def call_tool(self, name: str, arguments: dict) -> McpToolResult:
        if not self._initialized:
            self.initialize()
        try:
            result = self._request("tools/call", {"name": name, "arguments": arguments})
        except McpRpcError as e:
            return McpToolResult(name=name, error=e.message, raw=e.raw)
        # MCP's tools/call result has an isError flag that mirrors a
        # tool-level (not transport-level) failure.
        if isinstance(result, dict) and result.get("isError"):
            return McpToolResult(
                name=name,
                error=_extract_error_text(result),
                raw=result,
            )
        return McpToolResult(name=name, content=result.get("content"), raw=result)

    def close(self) -> None:
        try:
            self._stream.close()
        except Exception:
            pass

    # ── JSON-RPC internals ──────────────────────────────────────────────

    def _request(self, method: str, params: dict | None = None) -> dict:
        request_id = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        return self._read_response(request_id)

    def _notify(self, method: str, params: dict | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def _send(self, message: dict) -> None:
        try:
            line = (json.dumps(message) + "\n").encode("utf-8")
            self._stream.write(line)
        except Exception as e:
            raise McpTransportError(f"write failed: {e}") from e

    def _read_response(self, expected_id: int) -> dict:
        while True:
            try:
                line = self._stream.read_line()
            except Exception as e:
                raise McpTransportError(f"read failed: {e}") from e
            if not line:
                raise McpTransportError("stream closed before response")
            # Tolerate stray \r from Windows servers that didn't switch
            # stdout to binary mode.
            line = line.rstrip(b"\r")
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as e:
                raise McpTransportError(f"bad JSON from server: {e}: {line!r}") from e
            # Notifications have no id; responses to other requests will
            # have a different id. Skip both - we'll get our match.
            if not isinstance(msg, dict) or msg.get("id") != expected_id:
                continue
            if "error" in msg:
                err = msg["error"] or {}
                raise McpRpcError(
                    code=int(err.get("code", -1)),
                    message=str(err.get("message", "RPC error")),
                    raw=msg,
                )
            return msg.get("result", {}) or {}


def _extract_error_text(result: dict) -> str:
    """Pull a human-readable string out of an isError tool result."""
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                return str(item.get("text", "tool reported error"))
    return "tool reported error"
