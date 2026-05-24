"""Tests for the real ProcessMonitor.

The container's ``top`` method is faked with a scripted queue of
snapshots; each call returns the next snapshot in order. This lets us
exercise spawn / exit detection deterministically without a real
Docker daemon.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from nyuwaymcpsandbox.sandbox.events import (
    EVT_PROCESS_EXIT,
    EVT_PROCESS_SPAWN,
)
from nyuwaymcpsandbox.sandbox.monitors.process import ProcessMonitor, _parse_top
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

# Tight poll interval keeps tests fast. The monitor's internal stop()
# wait period is the upper bound on how long a clean shutdown takes.
_FAST_POLL = 0.02
_WAIT_TIMEOUT = 3.0
_WAIT_TICK = 0.02


def _wait_for(predicate, timeout: float = _WAIT_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(_WAIT_TICK)
    return predicate()


# ── Fakes ────────────────────────────────────────────────────────────────


@dataclass
class _FakeContainer:
    """Scripted container.top() responses."""

    queue: deque = field(default_factory=deque)
    # If non-None, raise this on the next call to top().
    raise_on_top: Exception | None = None
    call_count: int = 0

    def push(self, snapshot: dict) -> None:
        self.queue.append(snapshot)

    def top(self) -> dict:
        self.call_count += 1
        if self.raise_on_top is not None:
            raise self.raise_on_top
        if not self.queue:
            # Mimic docker: once container exits, top() raises. We just
            # return an empty snapshot for simplicity in tests.
            return {"Titles": ["PID", "PPID", "CMD"], "Processes": []}
        # Hold the last snapshot when the queue runs out so the poller
        # has stable state between assertions.
        if len(self.queue) == 1:
            return self.queue[0]
        return self.queue.popleft()


@dataclass
class _FakeHandle:
    container: _FakeContainer


def _snapshot(*rows: tuple[str, str, str]) -> dict:
    """Build a top() snapshot. Each row is (pid, ppid, cmd)."""
    return {
        "Titles": ["PID", "PPID", "CMD"],
        "Processes": [list(row) for row in rows],
    }


# ── _parse_top ───────────────────────────────────────────────────────────


def test_parse_top_basic_snapshot():
    snap = _snapshot(("1", "0", "python server.py"), ("42", "1", "sh -c curl evil"))
    parsed = _parse_top(snap)
    assert set(parsed.keys()) == {"1", "42"}
    assert parsed["1"]["argv"] == ["python", "server.py"]
    assert parsed["1"]["ppid"] == "0"
    assert parsed["42"]["argv"] == ["sh", "-c", "curl", "evil"]


def test_parse_top_falls_back_to_COMMAND_column():
    """BusyBox / Alpine ps reports the column as COMMAND, not CMD."""
    snap = {
        "Titles": ["PID", "PPID", "COMMAND"],
        "Processes": [["7", "1", "/bin/sh"]],
    }
    parsed = _parse_top(snap)
    assert parsed["7"]["argv"] == ["/bin/sh"]


def test_parse_top_missing_pid_column_returns_empty():
    snap = {"Titles": ["USER", "CMD"], "Processes": [["root", "/bin/sh"]]}
    assert _parse_top(snap) == {}


def test_parse_top_handles_non_dict_input():
    assert _parse_top(None) == {}
    assert _parse_top("not a dict") == {}  # type: ignore[arg-type]
    assert _parse_top([]) == {}  # type: ignore[arg-type]


def test_parse_top_empty_processes():
    snap = {"Titles": ["PID", "CMD"], "Processes": []}
    assert _parse_top(snap) == {}


def test_parse_top_skips_malformed_rows():
    snap = {
        "Titles": ["PID", "CMD"],
        "Processes": [
            ["1", "good"],
            "not a row",  # malformed
            [],  # empty
            ["2", "ok"],
        ],
    }
    parsed = _parse_top(snap)
    assert set(parsed.keys()) == {"1", "2"}


def test_parse_top_missing_cmd_column_gives_empty_argv():
    snap = {"Titles": ["PID", "PPID"], "Processes": [["3", "1"]]}
    parsed = _parse_top(snap)
    assert parsed["3"]["argv"] == []


# ── Lifecycle no-ops ─────────────────────────────────────────────────────


def test_start_with_no_top_method_is_noop():
    """A container handle without .top() must not crash; treat as no-op."""

    class _NoTop:
        pass

    timeline = BehavioralTimeline()
    monitor = ProcessMonitor()
    monitor.start(_NoTop(), timeline, time.monotonic())
    assert monitor.is_running
    monitor.stop()
    assert timeline.events == []


def test_start_with_no_container_attribute_is_noop():
    timeline = BehavioralTimeline()
    monitor = ProcessMonitor()
    monitor.start("not-a-handle", timeline, time.monotonic())
    assert monitor.is_running
    monitor.stop()
    assert timeline.events == []


# ── Spawn / exit detection ───────────────────────────────────────────────


def test_first_snapshot_emits_spawn_for_every_pid():
    """First tick: all observed PIDs are 'new' relative to empty state."""
    container = _FakeContainer()
    container.push(_snapshot(("1", "0", "python server.py")))
    timeline = BehavioralTimeline()
    monitor = ProcessMonitor(poll_interval=_FAST_POLL)
    monitor.start(_FakeHandle(container=container), timeline, time.monotonic())
    try:
        assert _wait_for(lambda: any(e.type == EVT_PROCESS_SPAWN for e in timeline.events))
        spawn = next(e for e in timeline.events if e.type == EVT_PROCESS_SPAWN)
        assert spawn.payload["pid"] == "1"
        assert spawn.payload["argv"] == ["python", "server.py"]
        assert spawn.payload["ppid"] == "0"
    finally:
        monitor.stop()


def test_new_process_between_ticks_emits_spawn():
    container = _FakeContainer()
    container.push(_snapshot(("1", "0", "python server.py")))
    container.push(_snapshot(("1", "0", "python server.py"), ("99", "1", "sh -c curl evil")))
    timeline = BehavioralTimeline()
    monitor = ProcessMonitor(poll_interval=_FAST_POLL)
    monitor.start(_FakeHandle(container=container), timeline, time.monotonic())
    try:
        assert _wait_for(
            lambda: any(
                e.type == EVT_PROCESS_SPAWN and e.payload["pid"] == "99" for e in timeline.events
            )
        )
        spawn_99 = next(
            e for e in timeline.events if e.type == EVT_PROCESS_SPAWN and e.payload["pid"] == "99"
        )
        assert spawn_99.payload["argv"] == ["sh", "-c", "curl", "evil"]
    finally:
        monitor.stop()


def test_disappeared_process_emits_exit():
    container = _FakeContainer()
    container.push(_snapshot(("1", "0", "python server.py"), ("99", "1", "curl evil")))
    container.push(_snapshot(("1", "0", "python server.py")))
    timeline = BehavioralTimeline()
    monitor = ProcessMonitor(poll_interval=_FAST_POLL)
    monitor.start(_FakeHandle(container=container), timeline, time.monotonic())
    try:
        assert _wait_for(
            lambda: any(
                e.type == EVT_PROCESS_EXIT and e.payload["pid"] == "99" for e in timeline.events
            )
        )
    finally:
        monitor.stop()


def test_stable_pid_set_emits_no_extra_events():
    container = _FakeContainer()
    snap = _snapshot(("1", "0", "python server.py"))
    container.push(snap)
    container.push(snap)
    timeline = BehavioralTimeline()
    monitor = ProcessMonitor(poll_interval=_FAST_POLL)
    monitor.start(_FakeHandle(container=container), timeline, time.monotonic())
    try:
        # Let at least one full poll cycle happen.
        time.sleep(_FAST_POLL * 4)
        # Exactly one spawn for PID 1; no exits, no duplicates.
        spawns = [e for e in timeline.events if e.type == EVT_PROCESS_SPAWN]
        exits = [e for e in timeline.events if e.type == EVT_PROCESS_EXIT]
        assert len(spawns) == 1
        assert exits == []
    finally:
        monitor.stop()


# ── Error tolerance ─────────────────────────────────────────────────────


def test_top_raising_stops_loop_quietly():
    """If container.top() raises, the poll thread exits silently."""
    container = _FakeContainer(raise_on_top=RuntimeError("container died"))
    timeline = BehavioralTimeline()
    monitor = ProcessMonitor(poll_interval=_FAST_POLL)
    monitor.start(_FakeHandle(container=container), timeline, time.monotonic())
    # Give the thread a moment to discover the failure and exit.
    time.sleep(_FAST_POLL * 5)
    # No events, no exception escaped, stop() still works cleanly.
    assert timeline.events == []
    monitor.stop()


# ── Threading lifecycle ─────────────────────────────────────────────────


def test_stop_is_idempotent():
    container = _FakeContainer()
    timeline = BehavioralTimeline()
    monitor = ProcessMonitor(poll_interval=_FAST_POLL)
    monitor.start(_FakeHandle(container=container), timeline, time.monotonic())
    monitor.stop()
    monitor.stop()  # second call must be safe
    assert not monitor.is_running


def test_no_events_after_stop():
    """Events from polls after stop() must not appear on the timeline."""
    container = _FakeContainer()
    container.push(_snapshot(("1", "0", "python server.py")))
    timeline = BehavioralTimeline()
    monitor = ProcessMonitor(poll_interval=_FAST_POLL)
    monitor.start(_FakeHandle(container=container), timeline, time.monotonic())
    # Wait for the initial spawn.
    assert _wait_for(lambda: any(e.type == EVT_PROCESS_SPAWN for e in timeline.events))
    monitor.stop()
    pre_count = len(timeline.events)
    # Push more data; nothing should land because the poller is stopped.
    container.push(_snapshot(("1", "0", "python server.py"), ("77", "1", "evil")))
    time.sleep(_FAST_POLL * 5)
    assert len(timeline.events) == pre_count


def test_stop_joins_thread_within_timeout():
    """stop() must not hang even if the poller is mid-wait."""
    container = _FakeContainer()
    timeline = BehavioralTimeline()
    # Long poll interval - if stop() didn't signal the wait Event,
    # join() would block for the full interval.
    monitor = ProcessMonitor(poll_interval=5.0)
    monitor.start(_FakeHandle(container=container), timeline, time.monotonic())
    start = time.monotonic()
    monitor.stop()
    elapsed = time.monotonic() - start
    # Stopping should be near-instant once the Event fires.
    assert elapsed < 1.0


def test_poller_thread_is_daemon():
    """A non-daemon poller would prevent process exit if stop is missed."""
    container = _FakeContainer()
    timeline = BehavioralTimeline()
    monitor = ProcessMonitor(poll_interval=_FAST_POLL)
    monitor.start(_FakeHandle(container=container), timeline, time.monotonic())
    try:
        # Find the live process_monitor thread.
        matches = [t for t in threading.enumerate() if t.name == "process_monitor"]
        assert matches, "process_monitor thread did not start"
        assert matches[0].daemon
    finally:
        monitor.stop()
