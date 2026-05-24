"""Filesystem capture monitor.

Watches the source tree the orchestrator bind-mounted into the
container and emits a BehavioralEvent for every file create / modify /
delete / move. Implemented via ``watchdog`` so the same code runs on
every host OS:

    Linux       - inotify (the kernel mechanism the v1 spec calls for)
    macOS       - FSEvents
    Windows     - ReadDirectoryChangesW

Scope note: this watches the *host's* view of the source mount. Writes
inside the container's overlay filesystem (anonymous tmpfs, app
runtime state) are not visible here. The sandbox-internal filesystem
monitor that catches those writes ships in v1.1 as a sidecar inotify
watcher inside the container. For the current detection rules - which
key off file writes to the bind-mounted source - the host-side
watcher is sufficient.

File-read events are deferred until v1.1 when we use the raw inotify
API directly: watchdog's cross-platform abstraction doesn't expose
IN_ACCESS uniformly, and none of the v1 detection rules depend on
read events.
"""

from __future__ import annotations

import time
from pathlib import Path

from nyuwaymcpsandbox.sandbox.events import (
    EVT_FS_DELETE,
    EVT_FS_WRITE,
    SRC_FILESYSTEM,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


def _emit(timeline: BehavioralTimeline, type_: str, path: str, scan_start: float) -> None:
    timeline.add(
        BehavioralEvent(
            type=type_,
            source=SRC_FILESYSTEM,
            timestamp=time.monotonic() - scan_start,
            payload={"path": path},
        )
    )


class FilesystemMonitor:
    """Capture filesystem writes / deletes inside the sandboxed container."""

    name = "filesystem_monitor"

    def __init__(self) -> None:
        self._observer = None
        self._started = False

    def start(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        # Resolve what to watch. Source path can be None when the
        # orchestrator is mocked (tests / dry-run); treat that as a
        # successful no-op rather than a start failure.
        source_path = getattr(container_handle, "source_path", None)
        if source_path is None:
            self._started = True
            return

        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            # watchdog wheel missing for the platform: keep the Monitor
            # contract by no-opping rather than raising.
            self._started = True
            return

        path = Path(source_path)
        if not path.exists():
            self._started = True
            return

        # Closure-captured handler so the watchdog dependency stays
        # confined to start().
        class _Handler(FileSystemEventHandler):
            def on_created(self_inner, event):
                if not event.is_directory:
                    _emit(timeline, EVT_FS_WRITE, event.src_path, scan_start)

            def on_modified(self_inner, event):
                if not event.is_directory:
                    _emit(timeline, EVT_FS_WRITE, event.src_path, scan_start)

            def on_deleted(self_inner, event):
                if not event.is_directory:
                    _emit(timeline, EVT_FS_DELETE, event.src_path, scan_start)

            def on_moved(self_inner, event):
                # Move = delete at source + write at destination.
                if not event.is_directory:
                    _emit(timeline, EVT_FS_DELETE, event.src_path, scan_start)
                    if getattr(event, "dest_path", None):
                        _emit(timeline, EVT_FS_WRITE, event.dest_path, scan_start)

        observer = Observer()
        observer.schedule(_Handler(), str(path), recursive=True)
        observer.start()
        self._observer = observer
        self._started = True

    def stop(self) -> None:
        observer = self._observer
        self._observer = None
        self._started = False
        if observer is None:
            return
        try:
            observer.stop()
            observer.join(timeout=5)
        except Exception:
            # Cleanup failures are intentionally swallowed - the runner
            # records them as container.error via its own try/except.
            pass

    @property
    def is_running(self) -> bool:
        return self._started
