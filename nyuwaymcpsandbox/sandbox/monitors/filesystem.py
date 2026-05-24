"""Filesystem capture monitor.

Watches every file read, write, delete, and permission change made by
processes inside the sandboxed container. Each observed event is
emitted into the BehavioralTimeline.

v1 LINUX IMPLEMENTATION (TODO):
    Attach inotify watchers (IN_ACCESS, IN_MODIFY, IN_CLOSE_WRITE,
    IN_DELETE, IN_ATTRIB) recursively on the container's writeable
    mount points and the host's view of the source mount. Each event
    becomes a filesystem.read / .write / .delete / .chmod with the
    full path in the payload.

This stub is Protocol-compliant; it emits no events. The Linux
implementation slots in without changing the Monitor interface.
"""

from __future__ import annotations

from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline


class FilesystemMonitor:
    """Capture filesystem activity inside the sandboxed container."""

    name = "filesystem_monitor"

    def __init__(self) -> None:
        self._started = False

    def start(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        # TODO(linux): attach inotify watchers to the container's
        # filesystem and start the event drain thread.
        self._started = True

    def stop(self) -> None:
        # TODO(linux): close inotify fds and join the drain thread.
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started
