"""SubprocessStdioStream: drive an MCP server as a host subprocess.

Cross-platform stdio transport. The MCP server runs as a child of the
sandbox process with its stdin/stdout piped, exactly as the official
MCP SDK does. This is the dev / no-sandbox transport: useful for
testing the protocol stack and for running fully-trusted MCP servers
locally without Docker.

The sandboxed counterpart is DockerExecStdioStream, which runs the
MCP server inside our orchestrator's container with real isolation.
The Protocol surface is identical so the rest of the pipeline doesn't
care which transport is in play.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# Time we allow the child process to wind down after stdin is closed
# before escalating to terminate / kill.
_STOP_TIMEOUT_SECONDS = 5


class SubprocessStdioStream:
    """Spawn an MCP server as a host subprocess; talk stdio to it."""

    def __init__(
        self,
        command: list[str],
        *,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        # stderr is intentionally inherited so server-side errors show
        # up in the operator's terminal during debugging. In v1.1 the
        # capture pipeline will redirect stderr to a behavioral event.
        self._proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
        self._closed = False

    # ── StdioStream API ─────────────────────────────────────────────────

    def read_line(self) -> bytes:
        if self._proc.stdout is None:
            return b""
        line = self._proc.stdout.readline()
        # Empty bytes signals EOF (the child closed stdout). Strip the
        # trailing newline; the protocol layer tolerates leftover \r.
        if not line:
            return b""
        return line.rstrip(b"\n")

    def write(self, data: bytes) -> None:
        if self._proc.stdin is None:
            raise BrokenPipeError("subprocess stdin is not writable")
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Step 1: close stdin so the server can exit gracefully when it
        # detects EOF on its input channel.
        try:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
        except Exception:
            pass
        # Step 2: wait briefly for clean exit.
        try:
            self._proc.wait(timeout=_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            # Step 3: terminate, then escalate to kill if still alive.
            try:
                self._proc.terminate()
                self._proc.wait(timeout=_STOP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        except Exception:
            pass
        # Step 4: close stdout/stderr handles.
        for handle in (self._proc.stdout, self._proc.stderr):
            try:
                if handle is not None:
                    handle.close()
            except Exception:
                pass

    # ── Inspection ─────────────────────────────────────────────────────

    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def returncode(self) -> int | None:
        return self._proc.returncode
