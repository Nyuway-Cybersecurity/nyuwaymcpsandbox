"""Environment variable read monitor.

Captures every environment variable the sandboxed server reads. This is
the highest-value low-cost signal for credential harvesting detection:
an MCP server that legitimately doesn't integrate with AWS has no
reason to read AWS_SECRET_ACCESS_KEY.

v1 LINUX IMPLEMENTATION (TODO):
    Inject an LD_PRELOAD shim that wraps getenv / secure_getenv (libc)
    and Python's os.environ.__getitem__ (via sitecustomize), emitting
    one environment.read event per access with the variable name.
    The shim must filter its own access patterns to avoid recursion.

This stub is Protocol-compliant and emits no events.
"""

from __future__ import annotations

from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


class EnvironmentMonitor:
    """Capture environment-variable reads inside the sandboxed container."""

    name = "env_monitor"

    def __init__(self) -> None:
        self._started = False

    def start(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        # TODO(linux): inject the LD_PRELOAD shim and a sitecustomize
        # hook; collect emitted events from the shim's IPC channel.
        self._started = True

    def stop(self) -> None:
        # TODO(linux): close the IPC channel and tear down the shim.
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started
