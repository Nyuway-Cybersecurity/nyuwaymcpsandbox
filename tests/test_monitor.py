"""Tests for the Monitor protocol, MonitorRunner, and monitor_session."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import pytest

from nyuwaymcpsandbox.sandbox.events import EVT_CONTAINER_ERROR
from nyuwaymcpsandbox.sandbox.monitor import MonitorRunner, monitor_session
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


@dataclass
class FakeMonitor:
    """Records start/stop calls and can raise on either."""

    name: str = "fake_monitor"
    start_raises: Exception | None = None
    stop_raises: Exception | None = None
    started: bool = False
    stopped: bool = False
    start_count: int = 0
    stop_count: int = 0
    # When set, records the order in which start/stop fired across a set.
    start_order: list[str] = field(default_factory=list)
    stop_order: list[str] = field(default_factory=list)

    def start(self, container_handle, timeline, scan_start):
        self.start_count += 1
        self.start_order.append(self.name)
        if self.start_raises:
            raise self.start_raises
        self.started = True

    def stop(self):
        self.stop_count += 1
        self.stop_order.append(self.name)
        if self.stop_raises:
            raise self.stop_raises
        self.stopped = True


def _scan_start() -> float:
    return time.monotonic()


# ── MonitorRunner: happy path ────────────────────────────────────────────


def test_runner_starts_every_monitor():
    a, b, c = FakeMonitor("a"), FakeMonitor("b"), FakeMonitor("c")
    runner = MonitorRunner([a, b, c])
    timeline = BehavioralTimeline()
    runner.start_all("handle", timeline, _scan_start())
    assert a.started and b.started and c.started
    assert a.start_count == 1


def test_runner_stops_in_reverse_start_order():
    """Layered monitors tear down in LIFO order."""
    shared_order: list[str] = []
    a = FakeMonitor("a", stop_order=shared_order)
    b = FakeMonitor("b", stop_order=shared_order)
    c = FakeMonitor("c", stop_order=shared_order)
    runner = MonitorRunner([a, b, c])
    timeline = BehavioralTimeline()
    runner.start_all("handle", timeline, _scan_start())
    runner.stop_all(timeline, _scan_start())
    assert shared_order == ["c", "b", "a"]


# ── MonitorRunner: error tolerance ───────────────────────────────────────


def test_one_start_failure_does_not_block_others():
    a = FakeMonitor("a")
    bad = FakeMonitor("bad", start_raises=RuntimeError("nfqueue gone"))
    c = FakeMonitor("c")
    timeline = BehavioralTimeline()
    runner = MonitorRunner([a, bad, c])
    runner.start_all("handle", timeline, _scan_start())
    assert a.started
    assert c.started
    assert not bad.started


def test_start_failure_records_error_event_with_monitor_name():
    bad = FakeMonitor("bad", start_raises=RuntimeError("nfqueue gone"))
    timeline = BehavioralTimeline()
    runner = MonitorRunner([bad])
    runner.start_all("handle", timeline, _scan_start())
    errors = [e for e in timeline.events if e.type == EVT_CONTAINER_ERROR]
    assert len(errors) == 1
    msg = errors[0].payload["message"]
    assert "'bad'" in msg
    assert "failed to start" in msg
    assert "nfqueue gone" in msg


def test_failed_start_monitor_is_not_stopped():
    """A monitor that errored during start must not have stop() called."""
    a = FakeMonitor("a")
    bad = FakeMonitor("bad", start_raises=RuntimeError("boom"))
    timeline = BehavioralTimeline()
    runner = MonitorRunner([a, bad])
    runner.start_all("handle", timeline, _scan_start())
    runner.stop_all(timeline, _scan_start())
    assert a.stop_count == 1
    assert bad.stop_count == 0


def test_stop_failure_recorded_as_error_event():
    bad = FakeMonitor("bad", stop_raises=RuntimeError("inotify leak"))
    timeline = BehavioralTimeline()
    runner = MonitorRunner([bad])
    runner.start_all("handle", timeline, _scan_start())
    runner.stop_all(timeline, _scan_start())
    errors = [e for e in timeline.events if e.type == EVT_CONTAINER_ERROR]
    assert any("failed to stop" in e.payload["message"] for e in errors)


def test_stop_failure_does_not_prevent_other_stops():
    a = FakeMonitor("a")
    bad = FakeMonitor("bad", stop_raises=RuntimeError("boom"))
    c = FakeMonitor("c")
    timeline = BehavioralTimeline()
    runner = MonitorRunner([a, bad, c])
    runner.start_all("handle", timeline, _scan_start())
    runner.stop_all(timeline, _scan_start())
    # All three had stop() called; only bad raised, but a and c still ran.
    assert a.stop_count == 1
    assert c.stop_count == 1
    assert a.stopped and c.stopped


def test_stop_all_clears_started_list_so_double_stop_is_safe():
    a = FakeMonitor("a")
    timeline = BehavioralTimeline()
    runner = MonitorRunner([a])
    runner.start_all("handle", timeline, _scan_start())
    runner.stop_all(timeline, _scan_start())
    runner.stop_all(timeline, _scan_start())  # second call - should be a no-op
    assert a.stop_count == 1


# ── monitor_session context manager ──────────────────────────────────────


def test_session_starts_and_stops_monitors():
    a = FakeMonitor("a")
    timeline = BehavioralTimeline()
    with monitor_session([a], "handle", timeline, _scan_start()):
        assert a.started
    assert a.stopped


def test_session_stops_monitors_when_body_raises():
    a = FakeMonitor("a")
    timeline = BehavioralTimeline()
    with pytest.raises(RuntimeError, match="driver boom"):
        with monitor_session([a], "handle", timeline, _scan_start()):
            raise RuntimeError("driver boom")
    assert a.stopped


def test_session_yields_runner_for_inspection():
    a = FakeMonitor("a")
    timeline = BehavioralTimeline()
    with monitor_session([a], "handle", timeline, _scan_start()) as runner:
        assert isinstance(runner, MonitorRunner)
        assert a in runner.monitors


def test_empty_monitor_list_is_valid():
    """A session with no monitors is degenerate but should not crash."""
    timeline = BehavioralTimeline()
    with monitor_session([], "handle", timeline, _scan_start()):
        pass
    # No events recorded; no exception raised.
    assert timeline.events == []
