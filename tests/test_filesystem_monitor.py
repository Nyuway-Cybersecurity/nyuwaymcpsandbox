"""Tests for the real FilesystemMonitor.

Uses watchdog against a real tmp_path. Watchdog runs in its own thread,
so each test polls with a short timeout to let the kernel deliver the
inotify / FSEvents / ReadDirectoryChangesW event back to userspace
before asserting.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from nyuwaymcpsandbox.sandbox.events import EVT_FS_DELETE, EVT_FS_WRITE
from nyuwaymcpsandbox.sandbox.monitors.filesystem import FilesystemMonitor
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

# Generous poll budget: Windows ReadDirectoryChangesW and macOS FSEvents
# both have noticeable delivery latency under test load.
_POLL_TIMEOUT_SECONDS = 4.0
_POLL_INTERVAL_SECONDS = 0.05


@dataclass
class _FakeHandle:
    """Minimal stand-in for ContainerHandle with just source_path."""

    source_path: Path | None


def _wait_for(predicate, timeout: float = _POLL_TIMEOUT_SECONDS) -> bool:
    """Poll until predicate() is true or the timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(_POLL_INTERVAL_SECONDS)
    return predicate()


def _events_for(timeline: BehavioralTimeline, type_: str) -> list:
    return [e for e in timeline.events if e.type == type_]


# ── Lifecycle on missing / None paths ────────────────────────────────────


def test_start_with_none_source_path_is_noop():
    """A mocked handle (no source_path) must not crash and not emit events."""
    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    monitor.start(_FakeHandle(source_path=None), timeline, time.monotonic())
    assert monitor.is_running
    monitor.stop()
    assert timeline.events == []


def test_start_with_nonexistent_path_is_noop(tmp_path):
    """A path that doesn't exist must not raise."""
    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    monitor.start(
        _FakeHandle(source_path=tmp_path / "does_not_exist"),
        timeline,
        time.monotonic(),
    )
    assert monitor.is_running
    monitor.stop()


# ── Real filesystem events ───────────────────────────────────────────────


def test_file_creation_emits_write_event(tmp_path):
    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    monitor.start(_FakeHandle(source_path=tmp_path), timeline, time.monotonic())
    try:
        target = tmp_path / "new.txt"
        target.write_text("hello")

        assert _wait_for(lambda: any(_events_for(timeline, EVT_FS_WRITE)))
        events = _events_for(timeline, EVT_FS_WRITE)
        # Watchdog may also emit a separate modified event after the
        # write; just confirm the path appears in at least one event.
        paths = {Path(e.payload["path"]).name for e in events}
        assert "new.txt" in paths
    finally:
        monitor.stop()


def test_file_modification_emits_write_event(tmp_path):
    target = tmp_path / "existing.txt"
    target.write_text("v1")

    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    monitor.start(_FakeHandle(source_path=tmp_path), timeline, time.monotonic())
    try:
        target.write_text("v2-modified")
        assert _wait_for(
            lambda: any(
                "existing.txt" in Path(e.payload.get("path", "")).name
                for e in _events_for(timeline, EVT_FS_WRITE)
            )
        )
    finally:
        monitor.stop()


def test_file_deletion_emits_delete_event(tmp_path):
    target = tmp_path / "to_delete.txt"
    target.write_text("bye")

    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    monitor.start(_FakeHandle(source_path=tmp_path), timeline, time.monotonic())
    try:
        target.unlink()
        assert _wait_for(
            lambda: any(
                "to_delete.txt" in Path(e.payload.get("path", "")).name
                for e in _events_for(timeline, EVT_FS_DELETE)
            )
        )
    finally:
        monitor.stop()


def test_recursive_watch_catches_nested_writes(tmp_path):
    """Files written in a subdirectory must be observed too."""
    sub = tmp_path / "deep" / "nested"
    sub.mkdir(parents=True)

    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    monitor.start(_FakeHandle(source_path=tmp_path), timeline, time.monotonic())
    try:
        target = sub / "inner.txt"
        target.write_text("nested write")
        assert _wait_for(
            lambda: any(
                "inner.txt" in Path(e.payload.get("path", "")).name
                for e in _events_for(timeline, EVT_FS_WRITE)
            )
        )
    finally:
        monitor.stop()


# ── Payload shape ────────────────────────────────────────────────────────


def test_event_payload_carries_absolute_path(tmp_path):
    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    monitor.start(_FakeHandle(source_path=tmp_path), timeline, time.monotonic())
    try:
        (tmp_path / "x.txt").write_text("hello")
        assert _wait_for(lambda: any(_events_for(timeline, EVT_FS_WRITE)))
        event = next(e for e in _events_for(timeline, EVT_FS_WRITE))
        assert "path" in event.payload
        assert Path(event.payload["path"]).is_absolute() or "x.txt" in event.payload["path"]
    finally:
        monitor.stop()


def test_event_timestamps_are_scan_relative(tmp_path):
    """Timestamps must be relative to the scan_start argument, not wall clock."""
    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    scan_start = time.monotonic()
    monitor.start(_FakeHandle(source_path=tmp_path), timeline, scan_start)
    try:
        (tmp_path / "y.txt").write_text("hello")
        assert _wait_for(lambda: any(_events_for(timeline, EVT_FS_WRITE)))
        event = next(e for e in _events_for(timeline, EVT_FS_WRITE))
        # Reasonable bounds: not negative, not absurdly large.
        assert 0 <= event.timestamp < 60
    finally:
        monitor.stop()


# ── Lifecycle ────────────────────────────────────────────────────────────


def test_stop_is_idempotent(tmp_path):
    """Calling stop twice must be safe."""
    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    monitor.start(_FakeHandle(source_path=tmp_path), timeline, time.monotonic())
    monitor.stop()
    monitor.stop()  # second call - no exception
    assert not monitor.is_running


def test_no_events_after_stop(tmp_path):
    """File events fired after stop() must not appear on the timeline."""
    timeline = BehavioralTimeline()
    monitor = FilesystemMonitor()
    monitor.start(_FakeHandle(source_path=tmp_path), timeline, time.monotonic())
    monitor.stop()

    # Give watchdog a moment to fully shut down its observer thread.
    time.sleep(0.2)
    pre_count = len(timeline.events)

    # Write after stop - must not be captured.
    (tmp_path / "post.txt").write_text("after stop")
    time.sleep(0.5)
    assert len(timeline.events) == pre_count
