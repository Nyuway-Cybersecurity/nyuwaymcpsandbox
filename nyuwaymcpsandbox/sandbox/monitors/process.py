"""Process / subprocess capture monitor.

Captures every subprocess the sandboxed server spawns: the argv, the
working directory, and the exit code. This is the load-bearing signal
for shell_exec_in_tool detection - a server with no declared
process-execution capability has no business spawning shells.

v1 LINUX IMPLEMENTATION (TODO):
    Walk /proc periodically inside the container's PID namespace and
    diff against the previous snapshot to detect new PIDs; for each
    new PID read /proc/<pid>/cmdline. Optionally complement with
    ptrace(PTRACE_SEIZE) on the container's init PID to catch
    short-lived processes between polls. Each spawn becomes a
    process.spawn event with argv + pid; each exit becomes
    process.exit with the exit code.

This stub is Protocol-compliant and emits no events.
"""

from __future__ import annotations

from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


class ProcessMonitor:
    """Capture subprocess spawns and exits inside the sandboxed container."""

    name = "process_monitor"

    def __init__(self) -> None:
        self._started = False

    def start(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        # TODO(linux): start the /proc poller thread (and optionally
        # ptrace attachment) to capture process lifecycle.
        self._started = True

    def stop(self) -> None:
        # TODO(linux): join the poller thread and detach ptrace.
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started
