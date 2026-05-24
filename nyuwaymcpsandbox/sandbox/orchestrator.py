"""Docker container orchestrator.

Wraps docker-py with the secure-by-default lifecycle the sandbox needs:

- Network mode 'none' by default (sinkholed). The --allow-network CLI flag
  is the only way to grant real outbound egress.
- Read-only root filesystem so a compromised server can't persist payloads.
- Resource limits: memory cap, CPU quota, pid count, so a misbehaving
  server can't exhaust the host.
- Capability drop ALL plus no-new-privileges so an unexpected privileged
  binary inside the image can't escalate.
- Source mounted read-only at /src; nothing the container writes there
  survives, nothing under the host source tree is at risk.
- Lifecycle events (container.started, container.stopped, container.error)
  are emitted to the supplied BehavioralTimeline so the detection engine
  can reason about the run.

Docker-py is the only dependency; tests mock it end-to-end so this module
imports cleanly on Windows even without Docker installed.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from nyuwaymcpsandbox.sandbox.events import (
    EVT_CONTAINER_ERROR,
    EVT_CONTAINER_STARTED,
    EVT_CONTAINER_STOPPED,
    SRC_CONTAINER,
    BehavioralEvent,
)
from nyuwaymcpsandbox.sandbox.timeline import BehavioralTimeline

# Docker-py is loaded lazily so this module imports on Windows without
# the docker package installed (tests inject a fake client).
try:  # pragma: no cover - import guard, not behaviour
    import docker  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    docker = None  # type: ignore[assignment]


class OrchestratorError(Exception):
    """Container lifecycle failed."""


@dataclass(frozen=True)
class ContainerConfig:
    """Inputs for a single container detonation.

    image and source_path are required. command is the entry point the
    sandbox runs inside the container (e.g. ["python", "server.py"]).
    """

    image: str
    source_path: Path
    command: list[str] = field(default_factory=list)
    working_dir: str = "/src"
    mem_limit: str = "512m"
    cpu_quota: float = 1.0  # whole CPUs
    pids_limit: int = 100
    timeout_seconds: int = 120
    allow_network: bool = False
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class ContainerHandle:
    """Live container the drivers can poke at while it runs."""

    container: object  # docker-py Container; opaque to keep tests light
    container_id: str
    image: str
    started_event_id: str
    # Host-side path the container has bind-mounted at /src. Capture
    # monitors (e.g. FilesystemMonitor) watch this path on the host's
    # view of the volume. None when the orchestrator is mocked.
    source_path: Path | None = None


def _build_run_kwargs(config: ContainerConfig) -> dict:
    """Produce the docker-py keyword arguments for a secure run."""
    return {
        "image": config.image,
        "command": list(config.command) if config.command else None,
        "detach": True,
        "working_dir": config.working_dir,
        "volumes": {
            str(Path(config.source_path).resolve()): {
                "bind": config.working_dir,
                "mode": "ro",
            }
        },
        "network_mode": "bridge" if config.allow_network else "none",
        "mem_limit": config.mem_limit,
        "nano_cpus": int(config.cpu_quota * 1_000_000_000),
        "pids_limit": config.pids_limit,
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "environment": dict(config.env),
        "stdout": True,
        "stderr": True,
    }


def _get_client(client_factory=None):
    """Return a docker client. Tests inject a factory to stub the SDK."""
    if client_factory is not None:
        return client_factory()
    if docker is None:
        raise OrchestratorError("docker-py is not installed. Install it with `pip install docker`.")
    try:
        return docker.from_env()
    except Exception as e:  # pragma: no cover - environment dependent
        raise OrchestratorError(f"Could not initialise docker client: {e}") from e


@contextmanager
def container_session(
    config: ContainerConfig,
    timeline: BehavioralTimeline,
    scan_start: float,
    client_factory=None,
):
    """Start a container, yield a ContainerHandle, clean up on exit.

    Lifecycle events are emitted to ``timeline``. Stop / remove errors on
    cleanup are recorded as ``container.error`` events but never raised -
    the sandbox always returns a usable report.
    """
    client = _get_client(client_factory)

    started_at_wall = time.monotonic()
    run_kwargs = _build_run_kwargs(config)

    try:
        container = client.containers.run(**run_kwargs)
    except Exception as e:
        timeline.add(
            BehavioralEvent(
                type=EVT_CONTAINER_ERROR,
                source=SRC_CONTAINER,
                timestamp=time.monotonic() - scan_start,
                payload={"message": f"container.run failed: {e}"},
            )
        )
        raise OrchestratorError(f"Could not start container: {e}") from e

    started_event = BehavioralEvent(
        type=EVT_CONTAINER_STARTED,
        source=SRC_CONTAINER,
        timestamp=time.monotonic() - scan_start,
        payload={
            "image": config.image,
            "container_id": getattr(container, "id", "?"),
            "network_mode": run_kwargs["network_mode"],
            "command": run_kwargs["command"] or [],
        },
    )
    timeline.add(started_event)

    handle = ContainerHandle(
        container=container,
        container_id=getattr(container, "id", "?"),
        image=config.image,
        started_event_id=started_event.event_id,
        source_path=Path(config.source_path).resolve() if config.source_path else None,
    )

    try:
        yield handle
    finally:
        # Best-effort stop. Container may already be dead; that's fine.
        try:
            container.stop(timeout=5)
        except Exception as e:
            timeline.add(
                BehavioralEvent(
                    type=EVT_CONTAINER_ERROR,
                    source=SRC_CONTAINER,
                    timestamp=time.monotonic() - scan_start,
                    payload={"message": f"container.stop failed: {e}"},
                )
            )
        # Best-effort remove. force=True so paused / stuck containers
        # don't leave host artefacts behind.
        try:
            container.remove(force=True)
        except Exception as e:
            timeline.add(
                BehavioralEvent(
                    type=EVT_CONTAINER_ERROR,
                    source=SRC_CONTAINER,
                    timestamp=time.monotonic() - scan_start,
                    payload={"message": f"container.remove failed: {e}"},
                )
            )

        duration = time.monotonic() - started_at_wall
        # Try to capture exit code if docker-py exposed it.
        exit_code = None
        try:
            attrs = getattr(container, "attrs", None) or {}
            state = attrs.get("State") or {}
            exit_code = state.get("ExitCode")
        except Exception:
            pass

        timeline.add(
            BehavioralEvent(
                type=EVT_CONTAINER_STOPPED,
                source=SRC_CONTAINER,
                timestamp=time.monotonic() - scan_start,
                payload={
                    "container_id": handle.container_id,
                    "duration_seconds": round(duration, 3),
                    "exit_code": exit_code,
                },
                triggered_by=started_event.event_id,
            )
        )
