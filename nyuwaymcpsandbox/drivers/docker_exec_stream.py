"""DockerExecStdioStream: drive an MCP server inside our sandboxed container.

The sandboxed counterpart to SubprocessStdioStream. Where the subprocess
transport runs the MCP server on the host (no isolation), this one runs
it inside the secure container the orchestrator already created and
talks JSON-RPC over a docker exec session attached to that container.

The Docker API uses a multiplexed framing protocol when tty=false on a
duplex exec stream:

    [stream_type (1 byte)][0][0][0][size (big-endian uint32)][payload...]

    stream_type: 0=stdin, 1=stdout, 2=stderr

stdin writes are raw bytes - no framing required on the client side.

For v1 stderr frames are silently dropped. v1.1 routes them into a
behavioral event so server-side errors surface in the report.
"""

from __future__ import annotations

# Frame header layout shared by every duplex exec session with tty=false.
_HEADER_SIZE = 8
_STREAM_STDOUT = 1
_STREAM_STDERR = 2  # noqa: F841 - kept as documentation for the protocol


class DockerExecStreamError(Exception):
    """Underlying docker exec stream raised, closed, or returned malformed data."""


class DockerExecStdioStream:
    """Run an MCP server inside an existing container; speak stdio to it.

    Caller owns the container lifecycle (handled by the orchestrator's
    container_session). This class only manages the exec session.

    Parameters:
        docker_api: low-level docker-py APIClient. Tests inject a fake.
        container_id: the running container's id.
        command: argv to run inside the container (e.g. ["python", "server.py"]).
        env: optional environment overrides for the exec'd process.
    """

    def __init__(
        self,
        docker_api,
        container_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
    ) -> None:
        try:
            exec_info = docker_api.exec_create(
                container=container_id,
                cmd=list(command),
                stdin=True,
                stdout=True,
                stderr=True,
                tty=False,
                environment=dict(env) if env else None,
            )
        except Exception as e:
            raise DockerExecStreamError(f"exec_create failed: {e}") from e

        self._exec_id = exec_info["Id"]

        try:
            socket_wrapper = docker_api.exec_start(
                exec_id=self._exec_id,
                socket=True,
                tty=False,
            )
        except Exception as e:
            raise DockerExecStreamError(f"exec_start failed: {e}") from e

        # docker-py wraps the raw socket; some versions expose ._sock,
        # others return it directly. Probe gently.
        self._socket = socket_wrapper
        self._raw = getattr(socket_wrapper, "_sock", None) or socket_wrapper

        self._stdout_buffer: bytes = b""
        self._closed = False

    # ── StdioStream API ─────────────────────────────────────────────────

    def read_line(self) -> bytes:
        """Return the next stdout line (without trailing newline).

        Returns ``b""`` on EOF. Frames addressed to stderr are dropped.
        If the server closes stdout with trailing data that isn't
        newline-terminated, that residue is returned once and then
        subsequent calls return EOF.
        """
        while True:
            if b"\n" in self._stdout_buffer:
                line, _, rest = self._stdout_buffer.partition(b"\n")
                self._stdout_buffer = rest
                return line
            if not self._read_one_frame():
                if self._stdout_buffer:
                    last = self._stdout_buffer
                    self._stdout_buffer = b""
                    return last
                return b""

    def write(self, data: bytes) -> None:
        """Write to the exec'd process's stdin (no framing needed)."""
        if self._closed:
            raise DockerExecStreamError("stream is closed")
        try:
            self._send_all(data)
        except Exception as e:
            raise DockerExecStreamError(f"write failed: {e}") from e

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for closer in ("close", "shutdown"):
            try:
                fn = getattr(self._raw, closer, None)
                if callable(fn):
                    fn()
                    break
            except Exception:
                pass

    @property
    def exec_id(self) -> str:
        return self._exec_id

    # ── Framing internals ───────────────────────────────────────────────

    def _read_one_frame(self) -> bool:
        """Pull one docker-multiplexed frame off the socket.

        Returns True if a frame (possibly empty payload) was read, False
        on EOF. stdout payloads are appended to the buffer; stderr is
        dropped silently for v1.
        """
        header = self._recv_exact(_HEADER_SIZE)
        if header is None:
            return False
        stream_type = header[0]
        size = int.from_bytes(header[4:8], "big")
        if size == 0:
            return True
        payload = self._recv_exact(size)
        if payload is None:
            return False
        if stream_type == _STREAM_STDOUT:
            self._stdout_buffer += payload
        return True

    def _recv_exact(self, n: int) -> bytes | None:
        """Read exactly ``n`` bytes from the socket. Return None on EOF."""
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            try:
                chunk = self._raw.recv(remaining)
            except Exception as e:
                raise DockerExecStreamError(f"recv failed: {e}") from e
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _send_all(self, data: bytes) -> None:
        """Write every byte of ``data`` to the socket."""
        view = memoryview(data)
        sent = 0
        while sent < len(view):
            n = self._raw.send(view[sent:])
            if n == 0:
                raise BrokenPipeError("docker exec stdin closed")
            sent += n
