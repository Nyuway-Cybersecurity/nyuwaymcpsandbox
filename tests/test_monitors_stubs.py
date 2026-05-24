"""Tests for the four built-in monitor stubs.

These verify the Protocol contract today. Real Linux-only behaviour
(NFQUEUE attach, inotify watch, etc.) lands at Linux CI integration.
"""

import time

from nyuwaymcpsandbox.sandbox.monitor import MonitorRunner
from nyuwaymcpsandbox.sandbox.monitors import (
    EnvironmentMonitor,
    FilesystemMonitor,
    NetworkMonitor,
    ProcessMonitor,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


def _all_stub_monitors():
    return [
        NetworkMonitor(),
        FilesystemMonitor(),
        EnvironmentMonitor(),
        ProcessMonitor(),
    ]


def test_every_stub_has_a_name():
    """A monitor's name is used in error events; never blank."""
    for m in _all_stub_monitors():
        assert getattr(m, "name", "")


def test_every_stub_starts_and_reports_running():
    timeline = BehavioralTimeline()
    for m in _all_stub_monitors():
        m.start("handle", timeline, time.monotonic())
        assert m.is_running


def test_every_stub_stops_and_reports_not_running():
    timeline = BehavioralTimeline()
    for m in _all_stub_monitors():
        m.start("handle", timeline, time.monotonic())
        m.stop()
        assert not m.is_running


def test_stubs_emit_no_events():
    """Stubs are placeholders; the real implementations land on Linux."""
    timeline = BehavioralTimeline()
    for m in _all_stub_monitors():
        m.start("handle", timeline, time.monotonic())
        m.stop()
    assert timeline.events == []


def test_runner_orchestrates_full_stub_set():
    """End-to-end: all four stubs through MonitorRunner without errors."""
    timeline = BehavioralTimeline()
    runner = MonitorRunner(_all_stub_monitors())
    runner.start_all("handle", timeline, time.monotonic())
    runner.stop_all(timeline, time.monotonic())
    # No error events recorded.
    assert timeline.events == []


def test_monitor_names_unique():
    """Reports use names as keys; collisions would be confusing."""
    names = [m.name for m in _all_stub_monitors()]
    assert len(names) == len(set(names))
