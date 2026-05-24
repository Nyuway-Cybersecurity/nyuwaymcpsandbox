"""Monitor abstraction + runner.

A Monitor watches one facet of the sandboxed container (network, file
system, environment, process tree) and emits BehavioralEvent records
into the shared timeline. Each capture engine implements this Protocol;
the runner coordinates their lifecycle for the duration of a session.

Lifecycle:

    runner.start_all(handle, timeline, scan_start)   # spawn each monitor
    # drivers run here, monitors observe in parallel
    runner.stop_all()                                # stop each monitor

The runner is fault-tolerant: a monitor that fails to start records an
error event but does not block the rest. A monitor that fails to stop
likewise records an error but does not raise - the sandbox always
returns a usable report.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Protocol

from nyuwaymcpsandbox.sandbox.events import (
    EVT_CONTAINER_ERROR,
    SRC_CONTAINER,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


class Monitor(Protocol):
    """The contract every capture engine implements.

    name is a short identifier (e.g. "network_monitor") used in error
    events so the operator can see which monitor misbehaved.
    """

    name: str

    def start(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:  # pragma: no cover - protocol method
        ...

    def stop(self) -> None:  # pragma: no cover - protocol method
        ...


class MonitorRunner:
    """Coordinates a set of monitors over a single container session."""

    def __init__(self, monitors: list[Monitor]) -> None:
        self._monitors = list(monitors)
        # Track which monitors actually started so we don't try to stop
        # ones that errored during startup.
        self._started: list[Monitor] = []

    @property
    def monitors(self) -> list[Monitor]:
        return list(self._monitors)

    def start_all(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        """Start every monitor. Per-monitor failures record an error event."""
        for monitor in self._monitors:
            try:
                monitor.start(container_handle, timeline, scan_start)
            except Exception as e:
                timeline.add(
                    BehavioralEvent(
                        type=EVT_CONTAINER_ERROR,
                        source=SRC_CONTAINER,
                        timestamp=time.monotonic() - scan_start,
                        payload={
                            "message": (
                                f"monitor {getattr(monitor, 'name', '?')!r} "
                                f"failed to start: {type(e).__name__}: {e}"
                            )
                        },
                    )
                )
                continue
            self._started.append(monitor)

    def stop_all(self, timeline: BehavioralTimeline, scan_start: float) -> None:
        """Stop every monitor that started. Failures are recorded, not raised.

        Stops run in reverse start order so layered monitors (e.g. a
        process monitor that consumes a network monitor's output) tear
        down cleanly.
        """
        for monitor in reversed(self._started):
            try:
                monitor.stop()
            except Exception as e:
                timeline.add(
                    BehavioralEvent(
                        type=EVT_CONTAINER_ERROR,
                        source=SRC_CONTAINER,
                        timestamp=time.monotonic() - scan_start,
                        payload={
                            "message": (
                                f"monitor {getattr(monitor, 'name', '?')!r} "
                                f"failed to stop: {type(e).__name__}: {e}"
                            )
                        },
                    )
                )
        self._started.clear()


@contextmanager
def monitor_session(
    monitors: list[Monitor],
    container_handle: object,
    timeline: BehavioralTimeline,
    scan_start: float,
):
    """Run a set of monitors for the duration of a container session.

    Driver code inside the `with` block runs while monitors observe in
    parallel. All monitors are guaranteed to stop on exit even if the
    driver raises.
    """
    runner = MonitorRunner(monitors)
    runner.start_all(container_handle, timeline, scan_start)
    try:
        yield runner
    finally:
        runner.stop_all(timeline, scan_start)
