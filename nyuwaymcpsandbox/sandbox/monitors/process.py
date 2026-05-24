"""Process / subprocess capture monitor.

Polls ``docker container.top()`` to read the process table inside the
sandboxed container's PID namespace, diffs consecutive snapshots, and
emits ``process.spawn`` / ``process.exit`` events for the PIDs that
appear or disappear between ticks.

This is the load-bearing signal for the shell_exec_in_tool detection
rule: a server with no declared process-execution capability has no
business spawning shells. Catching short-lived processes (a curl exec
that runs in <100ms) is best-effort under polling - eBPF-backed
tracing in v2 plugs that gap.

Cross-platform by design: docker-py handles the daemon round trip, the
``Titles``/``Processes`` shape is uniform across Linux container hosts.
On hosts where the container handle has no ``.top`` method (mocked
orchestrator, --dry-run) the monitor is a silent no-op.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from nyuwaymcpsandbox.sandbox.events import (
    EVT_PROCESS_EXIT,
    EVT_PROCESS_SPAWN,
    SRC_PROCESS,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

# Default poll cadence. Tight enough to catch most "spawn-then-exit
# within a tool call" subprocesses (typical curl/shell exec is 50-500
# ms), loose enough that the cost is invisible. Tests inject smaller
# intervals to keep total test wall time low.
_DEFAULT_POLL_INTERVAL_SECONDS = 0.1


def _parse_top(snapshot: dict | None) -> dict[str, dict[str, Any]]:
    """Translate docker container.top() output into ``{pid: info}``.

    ``info`` carries an ``argv`` list (best-effort whitespace split on
    the CMD column) and a ``ppid`` if the snapshot exposes it.

    Snapshots from different bases use different column names: classic
    ``ps`` uses CMD, BusyBox uses COMMAND. Missing columns degrade to
    empty values rather than raising.
    """
    if not isinstance(snapshot, dict):
        return {}
    titles = snapshot.get("Titles") or []
    processes = snapshot.get("Processes") or []

    def _col(name: str) -> int | None:
        try:
            return titles.index(name)
        except ValueError:
            return None

    pid_idx = _col("PID")
    if pid_idx is None:
        return {}
    ppid_idx = _col("PPID")
    cmd_idx = _col("CMD")
    if cmd_idx is None:
        cmd_idx = _col("COMMAND")

    result: dict[str, dict[str, Any]] = {}
    for row in processes:
        if not isinstance(row, list) or pid_idx >= len(row):
            continue
        pid = str(row[pid_idx])
        cmd_raw = row[cmd_idx] if cmd_idx is not None and cmd_idx < len(row) else ""
        argv = str(cmd_raw).split() if cmd_raw else []
        ppid = str(row[ppid_idx]) if ppid_idx is not None and ppid_idx < len(row) else None
        result[pid] = {"argv": argv, "ppid": ppid}
    return result


class ProcessMonitor:
    """Capture subprocess spawns and exits inside the sandboxed container."""

    name = "process_monitor"

    def __init__(self, poll_interval: float = _DEFAULT_POLL_INTERVAL_SECONDS) -> None:
        self._poll_interval = poll_interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started = False
        # PID -> info dict; only ever touched by the poller thread.
        self._known: dict[str, dict[str, Any]] = {}

    # ── Monitor Protocol ────────────────────────────────────────────────

    def start(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        top_fn = self._resolve_top_fn(container_handle)
        if top_fn is None:
            # No way to read the container's process table; treat as
            # successful no-op so the runner doesn't flag a start
            # failure on the cleanest happy path.
            self._started = True
            return

        self._stop.clear()
        self._known = {}
        thread = threading.Thread(
            target=self._poll_loop,
            args=(top_fn, timeline, scan_start),
            name="process_monitor",
            daemon=True,
        )
        thread.start()
        self._thread = thread
        self._started = True

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            try:
                thread.join(timeout=5)
            except Exception:
                pass
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started

    # ── Internals ───────────────────────────────────────────────────────

    @staticmethod
    def _resolve_top_fn(container_handle: object):
        """Return container.top (callable) or None when unavailable."""
        container = getattr(container_handle, "container", None)
        if container is None:
            return None
        top = getattr(container, "top", None)
        if not callable(top):
            return None
        return top

    def _poll_loop(self, top_fn, timeline: BehavioralTimeline, scan_start: float) -> None:
        # Best-effort: one fatal error in top() (container died, daemon
        # blip) ends the loop quietly. The runner reports overall
        # session state; individual capture errors don't propagate.
        while not self._stop.is_set():
            try:
                snapshot = top_fn()
            except Exception:
                return
            try:
                current = _parse_top(snapshot)
            except Exception:
                current = {}
            self._diff_and_emit(current, timeline, scan_start)
            # wait() returns True when stop is signalled, so this is
            # also our cancellable sleep.
            if self._stop.wait(self._poll_interval):
                return

    def _diff_and_emit(
        self,
        current: dict[str, dict[str, Any]],
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        now = time.monotonic() - scan_start

        # Spawns: pids in current but not in known.
        for pid, info in current.items():
            if pid in self._known:
                continue
            timeline.add(
                BehavioralEvent(
                    type=EVT_PROCESS_SPAWN,
                    source=SRC_PROCESS,
                    timestamp=now,
                    payload={
                        "pid": pid,
                        "argv": list(info.get("argv") or []),
                        "ppid": info.get("ppid"),
                    },
                )
            )

        # Exits: pids in known but not in current.
        for pid in list(self._known.keys()):
            if pid not in current:
                timeline.add(
                    BehavioralEvent(
                        type=EVT_PROCESS_EXIT,
                        source=SRC_PROCESS,
                        timestamp=now,
                        payload={"pid": pid},
                    )
                )

        self._known = current
