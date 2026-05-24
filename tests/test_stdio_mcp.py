"""Tests for the real stdio MCP transport.

Two layers:

1. Protocol-level tests: StdioMcpClient against a FakeStdioStream that
   scripts canned server responses. Verifies the initialize handshake,
   tools/list parsing, tools/call success/error paths, isError flag,
   line-ending tolerance, and transport error mapping.

2. End-to-end test: SubprocessStdioStream + StdioMcpClient against a
   real in-tree MCP server (tests/fixtures/echo_mcp_server.py). Proves
   the whole stack actually talks to a real MCP server on this OS.
"""

from __future__ import annotations

import json
import sys
from collections import deque
from pathlib import Path

import pytest

from nyuwaymcpsandbox.drivers.stdio_mcp import (
    McpRpcError,
    McpTransportError,
    StdioMcpClient,
)
from nyuwaymcpsandbox.drivers.subprocess_stream import SubprocessStdioStream

FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "echo_mcp_server.py"


# ── Fake stream ──────────────────────────────────────────────────────────


class FakeStdioStream:
    """Scripted stream for protocol-level tests."""

    def __init__(self) -> None:
        self.written: list[bytes] = []
        self._scripted: deque[bytes] = deque()
        self.read_error: Exception | None = None
        self.write_error: Exception | None = None
        self.closed = False

    def script_response(self, msg: dict) -> None:
        self._scripted.append(json.dumps(msg).encode("utf-8"))

    def script_raw(self, data: bytes) -> None:
        self._scripted.append(data)

    def read_line(self) -> bytes:
        if self.read_error:
            raise self.read_error
        if not self._scripted:
            return b""
        return self._scripted.popleft()

    def write(self, data: bytes) -> None:
        if self.write_error:
            raise self.write_error
        self.written.append(data)

    def close(self) -> None:
        self.closed = True

    @property
    def sent(self) -> list[dict]:
        """Parse every line written to the stream as JSON."""
        out: list[dict] = []
        for chunk in self.written:
            for line in chunk.split(b"\n"):
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out


# ── Initialize handshake ─────────────────────────────────────────────────


def test_initialize_sends_init_request_and_initialized_notification():
    s = FakeStdioStream()
    s.script_response(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "x"}},
        }
    )
    client = StdioMcpClient(s, client_name="nyuway-test", client_version="0.0.1")
    client.initialize()
    sent = s.sent
    assert len(sent) == 2
    assert sent[0]["method"] == "initialize"
    assert sent[0]["params"]["clientInfo"]["name"] == "nyuway-test"
    assert sent[0]["params"]["protocolVersion"] == "2024-11-05"
    assert sent[1]["method"] == "notifications/initialized"
    # Notification must not carry an id.
    assert "id" not in sent[1]


def test_initialize_idempotent():
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    client = StdioMcpClient(s)
    client.initialize()
    client.initialize()  # second call should be a no-op
    sent = s.sent
    # Only one initialize request was sent.
    initializes = [m for m in sent if m.get("method") == "initialize"]
    assert len(initializes) == 1


def test_list_tools_triggers_initialize_lazily():
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    s.script_response({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
    client = StdioMcpClient(s)
    client.list_tools()
    methods = [m.get("method") for m in s.sent]
    # init, init-notification, tools/list
    assert methods == ["initialize", "notifications/initialized", "tools/list"]


# ── tools/list ───────────────────────────────────────────────────────────


def test_list_tools_parses_descriptors():
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    s.script_response(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {"name": "a", "description": "A", "inputSchema": {"type": "object"}},
                    {"name": "b"},
                ]
            },
        }
    )
    client = StdioMcpClient(s)
    tools = client.list_tools()
    assert [t.name for t in tools] == ["a", "b"]
    assert tools[0].description == "A"
    assert tools[0].input_schema == {"type": "object"}
    # Missing optional fields don't crash.
    assert tools[1].description == ""
    assert tools[1].input_schema is None


# ── tools/call ───────────────────────────────────────────────────────────


def test_call_tool_returns_content_on_success():
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    s.script_response(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"content": [{"type": "text", "text": "hello"}]},
        }
    )
    client = StdioMcpClient(s)
    result = client.call_tool("echo", {"text": "hello"})
    assert result.error is None
    assert "hello" in repr(result.content)


def test_call_tool_returns_error_on_jsonrpc_error_response():
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    s.script_response(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "error": {"code": -32602, "message": "Invalid params"},
        }
    )
    client = StdioMcpClient(s)
    result = client.call_tool("bad", {})
    assert result.error == "Invalid params"
    assert result.content is None


def test_call_tool_returns_error_on_isError_flag():
    """MCP's isError on tools/call is a tool-level error, not transport."""
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    s.script_response(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [{"type": "text", "text": "permission denied"}],
                "isError": True,
            },
        }
    )
    client = StdioMcpClient(s)
    result = client.call_tool("forbidden", {})
    assert result.error == "permission denied"


def test_call_tool_passes_arguments_through():
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    s.script_response({"jsonrpc": "2.0", "id": 2, "result": {"content": []}})
    client = StdioMcpClient(s)
    client.call_tool("echo", {"text": "abc", "n": 3})
    last_request = s.sent[-1]
    assert last_request["method"] == "tools/call"
    assert last_request["params"]["arguments"] == {"text": "abc", "n": 3}


# ── Transport edge cases ─────────────────────────────────────────────────


def test_unmatched_id_skipped():
    """Notifications and unrelated responses must not be returned as ours."""
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    # A spurious notification between our requests.
    s.script_response({"jsonrpc": "2.0", "method": "notifications/progress"})
    # A response with the wrong id, then the right id.
    s.script_response({"jsonrpc": "2.0", "id": 99, "result": "wrong"})
    s.script_response({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
    client = StdioMcpClient(s)
    tools = client.list_tools()
    assert tools == []


def test_tolerates_crlf_line_endings():
    """Windows-mode stdout emits \\r\\n; the protocol layer must strip it."""
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    s.script_raw(json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}).encode() + b"\r")
    client = StdioMcpClient(s)
    assert client.list_tools() == []


def test_eof_before_response_raises_transport_error():
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    # No second response - stream EOFs.
    client = StdioMcpClient(s)
    with pytest.raises(McpTransportError, match="stream closed"):
        client.list_tools()


def test_bad_json_raises_transport_error():
    s = FakeStdioStream()
    s.script_response({"jsonrpc": "2.0", "id": 1, "result": {}})
    s.script_raw(b"{not valid json")
    client = StdioMcpClient(s)
    with pytest.raises(McpTransportError, match="bad JSON"):
        client.list_tools()


def test_write_error_raises_transport_error():
    s = FakeStdioStream()
    s.write_error = BrokenPipeError("pipe gone")
    client = StdioMcpClient(s)
    with pytest.raises(McpTransportError, match="write failed"):
        client.initialize()


def test_read_error_raises_transport_error():
    class _Stream(FakeStdioStream):
        def read_line(self):
            raise OSError("connection reset")

    bad = _Stream()
    client = StdioMcpClient(bad)
    with pytest.raises(McpTransportError, match="read failed"):
        client.initialize()


def test_rpc_error_class_carries_code_and_raw():
    err = McpRpcError(code=-32602, message="Invalid", raw={"x": 1})
    assert err.code == -32602
    assert err.message == "Invalid"
    assert err.raw == {"x": 1}
    assert "-32602" in str(err)


# ── End-to-end against a real in-tree MCP server ─────────────────────────


def test_subprocess_end_to_end_against_echo_server():
    """Real protocol stack: spawn echo server, talk JSON-RPC, get a result."""
    stream = SubprocessStdioStream([sys.executable, str(FIXTURE_SERVER)])
    client = StdioMcpClient(stream)
    try:
        tools = client.list_tools()
        names = {t.name for t in tools}
        assert "echo" in names
        assert "fail" in names

        result = client.call_tool("echo", {"text": "nyuway-probe"})
        assert result.error is None
        assert "nyuway-probe" in repr(result.content)
    finally:
        client.close()


def test_subprocess_end_to_end_echo_server_tool_error():
    """The fail tool returns isError=true; we should see it as a tool-level error."""
    stream = SubprocessStdioStream([sys.executable, str(FIXTURE_SERVER)])
    client = StdioMcpClient(stream)
    try:
        result = client.call_tool("fail", {})
        assert result.error is not None
        assert "fails on purpose" in result.error
    finally:
        client.close()


def test_subprocess_end_to_end_unknown_tool_returns_rpc_error():
    """A tool name the server doesn't know returns a JSON-RPC error."""
    stream = SubprocessStdioStream([sys.executable, str(FIXTURE_SERVER)])
    client = StdioMcpClient(stream)
    try:
        result = client.call_tool("does_not_exist", {})
        assert result.error is not None
    finally:
        client.close()


def test_subprocess_close_terminates_process():
    stream = SubprocessStdioStream([sys.executable, str(FIXTURE_SERVER)])
    client = StdioMcpClient(stream)
    # Force initialize so the process is fully running.
    client.initialize()
    pid = stream.pid
    assert pid > 0
    client.close()
    assert stream.returncode is not None  # process has exited
