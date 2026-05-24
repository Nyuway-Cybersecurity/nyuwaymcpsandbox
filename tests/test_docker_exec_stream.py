"""Tests for DockerExecStdioStream.

The docker SDK and its socket are replaced with hand-rolled fakes so
these run on every OS - no Docker daemon required. The fakes mimic
docker-py's exec API surface and produce real multiplexed frames so
the framing parser is exercised end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from nyuwaymcpsandbox.drivers.docker_exec_stream import (
    DockerExecStdioStream,
    DockerExecStreamError,
)

# ── Frame helpers ────────────────────────────────────────────────────────

_STDOUT = 1
_STDERR = 2


def _frame(stream_type: int, payload: bytes) -> bytes:
    """Construct one docker exec multiplexed frame."""
    return bytes([stream_type, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload


# ── Fake socket + API ────────────────────────────────────────────────────


@dataclass
class _FakeSocket:
    """Hand-rolled socket double.

    ``serve`` queues a chunk of bytes to be returned by recv. Calls to
    recv return at most one queued chunk at a time, which lets tests
    exercise partial reads and frame boundaries.
    """

    chunks: list[bytes] = field(default_factory=list)
    sent: bytes = b""
    closed: bool = False
    raise_on_recv: Exception | None = None
    raise_on_send: Exception | None = None

    def serve(self, data: bytes) -> None:
        self.chunks.append(data)

    def recv(self, n: int) -> bytes:
        if self.raise_on_recv:
            raise self.raise_on_recv
        if not self.chunks:
            return b""
        head = self.chunks[0]
        if len(head) <= n:
            self.chunks.pop(0)
            return head
        ret, self.chunks[0] = head[:n], head[n:]
        return ret

    def send(self, data) -> int:
        if self.raise_on_send:
            raise self.raise_on_send
        b = bytes(data)
        self.sent += b
        return len(b)

    def close(self) -> None:
        self.closed = True


@dataclass
class _FakeSocketWrapper:
    """Simulates docker-py's SocketIO wrapper that hangs the real sock on _sock."""

    _sock: _FakeSocket


@dataclass
class _FakeApi:
    """docker-py APIClient stand-in: just the two methods we use."""

    socket: _FakeSocket
    exec_create_kwargs: dict = field(default_factory=dict)
    exec_start_kwargs: dict = field(default_factory=dict)
    exec_create_raises: Exception | None = None
    exec_start_raises: Exception | None = None

    def exec_create(self, **kwargs):
        if self.exec_create_raises:
            raise self.exec_create_raises
        self.exec_create_kwargs = kwargs
        return {"Id": "fakeexec-1234"}

    def exec_start(self, **kwargs):
        if self.exec_start_raises:
            raise self.exec_start_raises
        self.exec_start_kwargs = kwargs
        return _FakeSocketWrapper(_sock=self.socket)


def _make_stream(*, command=None, env=None) -> tuple[DockerExecStdioStream, _FakeApi, _FakeSocket]:
    sock = _FakeSocket()
    api = _FakeApi(socket=sock)
    stream = DockerExecStdioStream(
        docker_api=api,
        container_id="container-abc",
        command=command or ["python", "server.py"],
        env=env,
    )
    return stream, api, sock


# ── Construction / exec setup ────────────────────────────────────────────


def test_construction_calls_exec_create_with_expected_params():
    _, api, _ = _make_stream(command=["python", "server.py"])
    kw = api.exec_create_kwargs
    assert kw["container"] == "container-abc"
    assert kw["cmd"] == ["python", "server.py"]
    assert kw["stdin"] is True
    assert kw["stdout"] is True
    assert kw["stderr"] is True
    assert kw["tty"] is False


def test_construction_passes_env_when_provided():
    _, api, _ = _make_stream(env={"FOO": "bar"})
    assert api.exec_create_kwargs["environment"] == {"FOO": "bar"}


def test_construction_no_env_passes_none():
    _, api, _ = _make_stream()
    assert api.exec_create_kwargs.get("environment") is None


def test_exec_start_uses_socket_and_no_tty():
    _, api, _ = _make_stream()
    kw = api.exec_start_kwargs
    assert kw["exec_id"] == "fakeexec-1234"
    assert kw["socket"] is True
    assert kw["tty"] is False


def test_exec_create_failure_raises_stream_error():
    sock = _FakeSocket()
    api = _FakeApi(socket=sock, exec_create_raises=RuntimeError("docker down"))
    with pytest.raises(DockerExecStreamError, match="exec_create"):
        DockerExecStdioStream(api, "c1", ["python"])


def test_exec_start_failure_raises_stream_error():
    sock = _FakeSocket()
    api = _FakeApi(socket=sock, exec_start_raises=RuntimeError("attach refused"))
    with pytest.raises(DockerExecStreamError, match="exec_start"):
        DockerExecStdioStream(api, "c1", ["python"])


def test_exec_id_exposed_for_debugging():
    stream, _, _ = _make_stream()
    assert stream.exec_id == "fakeexec-1234"


# ── Frame parsing: stdout ────────────────────────────────────────────────


def test_read_line_returns_single_framed_line():
    stream, _, sock = _make_stream()
    sock.serve(_frame(_STDOUT, b"hello\n"))
    assert stream.read_line() == b"hello"


def test_read_line_returns_empty_on_eof():
    stream, _, _ = _make_stream()
    # No data served; first read should EOF immediately.
    assert stream.read_line() == b""


def test_multiple_lines_in_one_frame():
    stream, _, sock = _make_stream()
    sock.serve(_frame(_STDOUT, b"first\nsecond\nthird\n"))
    assert stream.read_line() == b"first"
    assert stream.read_line() == b"second"
    assert stream.read_line() == b"third"


def test_line_split_across_two_frames():
    """A long line whose bytes arrive across two frames must reassemble."""
    stream, _, sock = _make_stream()
    sock.serve(_frame(_STDOUT, b"partial-"))
    sock.serve(_frame(_STDOUT, b"completion\n"))
    assert stream.read_line() == b"partial-completion"


def test_trailing_residue_returned_then_eof():
    """A final unterminated line should be returned once before EOF."""
    stream, _, sock = _make_stream()
    sock.serve(_frame(_STDOUT, b"no-newline-here"))
    assert stream.read_line() == b"no-newline-here"
    assert stream.read_line() == b""


def test_stderr_frames_are_dropped():
    """stderr should not appear on read_line."""
    stream, _, sock = _make_stream()
    sock.serve(_frame(_STDERR, b"server crashed\n"))
    sock.serve(_frame(_STDOUT, b"useful output\n"))
    assert stream.read_line() == b"useful output"


def test_empty_payload_frame_is_skipped():
    """A zero-size frame is legal and must not stall the reader."""
    stream, _, sock = _make_stream()
    # Two empty stdout frames, then a real one.
    sock.serve(_frame(_STDOUT, b""))
    sock.serve(_frame(_STDOUT, b""))
    sock.serve(_frame(_STDOUT, b"actual line\n"))
    assert stream.read_line() == b"actual line"


def test_partial_recv_reassembles_header():
    """recv returning fewer bytes than requested must not truncate parsing."""
    stream, _, sock = _make_stream()
    # Split the frame header bytewise across many recvs.
    payload = b"hello\n"
    full_frame = _frame(_STDOUT, payload)
    for byte in full_frame:
        sock.serve(bytes([byte]))
    assert stream.read_line() == b"hello"


# ── Write (stdin) ────────────────────────────────────────────────────────


def test_write_sends_raw_bytes_no_framing():
    stream, _, sock = _make_stream()
    stream.write(b'{"jsonrpc":"2.0"}\n')
    assert sock.sent == b'{"jsonrpc":"2.0"}\n'


def test_write_handles_short_send():
    """A short send must loop until all bytes are written."""
    stream, _, sock = _make_stream()

    # Wrap send to deliver only one byte per call.
    real_send = sock.send

    def slow_send(data):
        b = bytes(data)
        if b:
            return real_send(b[:1])
        return 0

    sock.send = slow_send  # type: ignore[method-assign]
    stream.write(b"abcdef")
    assert sock.sent == b"abcdef"


def test_write_after_close_raises():
    stream, _, _ = _make_stream()
    stream.close()
    with pytest.raises(DockerExecStreamError, match="closed"):
        stream.write(b"x")


def test_write_error_wrapped_in_stream_error():
    stream, _, sock = _make_stream()
    sock.raise_on_send = BrokenPipeError("pipe gone")
    with pytest.raises(DockerExecStreamError, match="write failed"):
        stream.write(b"hello")


# ── Read errors / close ──────────────────────────────────────────────────


def test_recv_failure_wrapped_in_stream_error():
    stream, _, sock = _make_stream()
    sock.raise_on_recv = OSError("connection reset")
    with pytest.raises(DockerExecStreamError, match="recv failed"):
        stream.read_line()


def test_close_is_idempotent():
    stream, _, sock = _make_stream()
    stream.close()
    stream.close()  # second call must be a no-op
    assert sock.closed


def test_close_marks_stream_closed_even_if_socket_close_raises():
    stream, _, sock = _make_stream()

    def bad_close():
        raise RuntimeError("close broke")

    sock.close = bad_close  # type: ignore[assignment]
    stream.close()  # should not raise
    # And subsequent writes correctly report closed state.
    with pytest.raises(DockerExecStreamError, match="closed"):
        stream.write(b"x")


# ── End-to-end against the StdioMcpClient ────────────────────────────────


def test_stdio_mcp_client_can_drive_a_docker_exec_stream():
    """Hand the same stream to StdioMcpClient and verify the round trip."""
    from nyuwaymcpsandbox.drivers.stdio_mcp import StdioMcpClient

    stream, _, sock = _make_stream()

    # Script the server side: init response + tools/list response, both
    # wrapped in docker stdout frames.
    init_response = b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}\n'
    tools_response = b'{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo"}]}}\n'
    sock.serve(_frame(_STDOUT, init_response))
    sock.serve(_frame(_STDOUT, tools_response))

    client = StdioMcpClient(stream)
    tools = client.list_tools()
    assert [t.name for t in tools] == ["echo"]

    # The client should have written both the initialize request and
    # the tools/list request to stdin.
    assert b'"method": "initialize"' in sock.sent
    assert b'"method": "tools/list"' in sock.sent
    assert b'"method": "notifications/initialized"' in sock.sent
