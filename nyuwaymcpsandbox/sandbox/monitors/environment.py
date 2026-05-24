"""Environment variable read monitor (Python servers, v1 scope).

Captures every environment variable the sandboxed server reads. This
is the highest-value low-cost signal for credential-harvesting
detection: an MCP server that doesn't legitimately integrate with AWS
has no reason to read AWS_SECRET_ACCESS_KEY.

Implementation: drop a ``sitecustomize.py`` shim into ``/nyuway_runtime``
inside the container, then tail ``/nyuway_runtime/env_reads.log`` via
``docker exec``. The shim patches ``os._Environ`` so every
``os.environ[...]``, ``os.environ.get(...)``, and ``os.getenv(...)``
appends a JSON line to the log. Each line becomes one
``environment.read`` BehavioralEvent on the host.

Scope notes:

- The shim only catches Python servers. Servers in other languages
  read env vars through libc ``getenv``, which Python sitecustomize
  cannot intercept. An LD_PRELOAD-based shim that covers libc readers
  lands in v1.1.
- The shim only activates when the server is started with
  ``PYTHONPATH=/nyuway_runtime`` (or that path included). Pass it via
  ``--mcp-command`` for now, e.g.::

      --mcp-command "env PYTHONPATH=/nyuway_runtime python server.py"

  Future versions wire this into the orchestrator so it's automatic.
- On hosts where the docker client isn't available (mocked, --dry-run)
  the monitor is a silent no-op.
"""

from __future__ import annotations

import io
import json
import tarfile
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from nyuwaymcpsandbox.sandbox.events import (
    EVT_ENV_READ,
    SRC_ENV,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

# Path inside the container where we install the shim + drop the log.
RUNTIME_DIR_IN_CONTAINER = "/nyuway_runtime"
LOG_PATH_IN_CONTAINER = f"{RUNTIME_DIR_IN_CONTAINER}/env_reads.log"

# Read the shim source from the package once at startup time. Tests
# inject ``shim_source`` to avoid touching the real file.
_SHIM_SOURCE_PATH = Path(__file__).resolve().parent.parent / "preload" / "sitecustomize.py"


def _load_shim_source() -> str:
    try:
        return _SHIM_SOURCE_PATH.read_text(encoding="utf-8")
    except Exception:
        return ""


def _build_shim_tar(shim_source: str) -> bytes:
    """Wrap the shim in a single-file tar archive for docker put_archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = shim_source.encode("utf-8")
        info = tarfile.TarInfo(name="sitecustomize.py")
        info.size = len(data)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _parse_env_log_line(line: str) -> str | None:
    """Return the env-var name from a shim log line, or None if malformed."""
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    name = record.get("name") if isinstance(record, dict) else None
    if isinstance(name, str) and name:
        return name
    return None


class EnvironmentMonitor:
    """Capture env-variable reads inside the sandboxed Python server."""

    name = "env_monitor"

    def __init__(
        self,
        *,
        shim_source: str | None = None,
        log_source_factory: Callable[[], Iterable] | None = None,
    ) -> None:
        """
        Parameters:
            shim_source: override the shim contents (tests). Default
                reads from the bundled file at construction time.
            log_source_factory: test injection. When provided, bypasses
                docker entirely and uses the factory's iterable as the
                log line source.
        """
        self._shim_source = shim_source if shim_source is not None else _load_shim_source()
        self._log_source_factory = log_source_factory
        self._reader_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started = False
        # Set when the docker exec install path actually ran.
        self._install_attempted = False
        self._install_succeeded = False

    # ── Monitor Protocol ────────────────────────────────────────────────

    def start(
        self,
        container_handle: object,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        if self._log_source_factory is not None:
            log_source = self._log_source_factory()
        else:
            log_source = self._install_and_tail(container_handle)

        if log_source is None:
            self._started = True
            return

        self._stop.clear()
        thread = threading.Thread(
            target=self._reader_loop,
            args=(log_source, timeline, scan_start),
            name="env_monitor",
            daemon=True,
        )
        thread.start()
        self._reader_thread = thread
        self._started = True

    def stop(self) -> None:
        self._stop.set()
        thread = self._reader_thread
        self._reader_thread = None
        if thread is not None:
            try:
                thread.join(timeout=5)
            except Exception:
                pass
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started

    # ── Inspection (for tests) ──────────────────────────────────────────

    @property
    def install_attempted(self) -> bool:
        return self._install_attempted

    @property
    def install_succeeded(self) -> bool:
        return self._install_succeeded

    # ── Docker setup ────────────────────────────────────────────────────

    def _install_and_tail(self, container_handle: object):
        """Drop the shim into the container and return a log-line stream.

        Returns None on any failure - the monitor becomes a no-op.
        """
        api = _resolve_docker_api(container_handle)
        if api is None:
            return None
        container_id = getattr(container_handle, "container_id", None)
        if not container_id:
            container = getattr(container_handle, "container", None)
            container_id = getattr(container, "id", None) if container else None
        if not container_id:
            return None
        if not self._shim_source:
            # Can't install anything useful without source bytes.
            return None

        self._install_attempted = True

        # Step 1: create the runtime dir + touch the log so tail -F has
        # something to attach to immediately. Errors here are fatal -
        # without the dir, put_archive fails too.
        try:
            mk = api.exec_create(
                container_id,
                cmd=[
                    "sh",
                    "-c",
                    f"mkdir -p {RUNTIME_DIR_IN_CONTAINER} && touch {LOG_PATH_IN_CONTAINER}",
                ],
            )
            api.exec_start(mk["Id"])
        except Exception:
            return None

        # Step 2: drop the shim file into the runtime dir.
        try:
            tar_bytes = _build_shim_tar(self._shim_source)
            api.put_archive(container_id, RUNTIME_DIR_IN_CONTAINER, tar_bytes)
        except Exception:
            return None

        # Step 3: start streaming the log via tail -F. tty=True so
        # output isn't docker-multiplexed - we get plain bytes.
        try:
            tail = api.exec_create(
                container_id,
                cmd=["tail", "-n", "0", "-F", LOG_PATH_IN_CONTAINER],
                stdout=True,
                stderr=False,
                tty=True,
            )
            stream = api.exec_start(exec_id=tail["Id"], stream=True, tty=True)
        except Exception:
            return None

        self._install_succeeded = True
        return stream

    # ── Reader loop ─────────────────────────────────────────────────────

    def _reader_loop(
        self,
        log_source: Iterable,
        timeline: BehavioralTimeline,
        scan_start: float,
    ) -> None:
        buffer = b""
        try:
            for chunk in log_source:
                if self._stop.is_set():
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                if not chunk:
                    continue
                buffer += chunk
                while b"\n" in buffer:
                    line_bytes, _, buffer = buffer.partition(b"\n")
                    name = _parse_env_log_line(line_bytes.decode("utf-8", errors="replace"))
                    if name is None:
                        continue
                    timeline.add(
                        BehavioralEvent(
                            type=EVT_ENV_READ,
                            source=SRC_ENV,
                            timestamp=time.monotonic() - scan_start,
                            payload={"name": name},
                        )
                    )
        except Exception:
            return


def _resolve_docker_api(container_handle: object):
    """Return the low-level docker API client, or None when unavailable."""
    container = getattr(container_handle, "container", None)
    if container is None:
        return None
    client = getattr(container, "client", None)
    if client is None:
        return None
    api = getattr(client, "api", None)
    if api is None:
        return None
    # exec_create / exec_start / put_archive must all be callable.
    for method in ("exec_create", "exec_start", "put_archive"):
        if not callable(getattr(api, method, None)):
            return None
    return api
