"""nyuway env-read shim, executed inside the sandboxed container.

Python auto-imports any ``sitecustomize`` module reachable on
``PYTHONPATH`` at interpreter start. The host EnvironmentMonitor drops
this file into ``/nyuway_runtime/sitecustomize.py`` inside the
container and the operator runs the MCP server with
``PYTHONPATH=/nyuway_runtime`` so Python loads it before the server
process starts.

Once loaded, the module monkey-patches ``os._Environ`` so every
``os.environ[KEY]``, ``os.environ.get(KEY)``, and ``os.getenv(KEY)``
appends a JSON line to ``/nyuway_runtime/env_reads.log``. The monitor
tails that log via ``docker exec`` and translates each line into a
``environment.read`` BehavioralEvent.

This file must be self-contained: it ships into a container that does
not have the nyuwaymcpsandbox package available. No external imports
beyond the stdlib.
"""

from __future__ import annotations

import json
import os
import time

_LOG_PATH = "/nyuway_runtime/env_reads.log"
# Skip internal-runtime vars so we don't trip our own monitor.
_FILTER_PREFIXES = ("NYUWAY_",)
# Sentinel attribute that flags "already patched" so re-importing
# (test harnesses, multi-interpreter setups) is a no-op.
_PATCHED_FLAG = "_nyuway_env_patched"


def _should_log(name) -> bool:
    if not isinstance(name, str) or not name:
        return False
    return not name.startswith(_FILTER_PREFIXES)


def _emit(name: str) -> None:
    """Append one JSON line; never raise."""
    try:
        record = {"name": name, "t": time.monotonic()}
        with open(_LOG_PATH, "a", buffering=1, encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        # Swallow everything: the shim must never break the host server.
        pass


def install() -> bool:
    """Apply the os._Environ patches. Idempotent. Returns True on first install."""
    cls = type(os.environ)
    if getattr(cls, _PATCHED_FLAG, False):
        return False

    orig_getitem = cls.__getitem__
    orig_get = cls.get

    def _patched_getitem(self, key):  # noqa: ANN001 - mirrors stdlib signature
        if _should_log(key):
            _emit(key)
        return orig_getitem(self, key)

    def _patched_get(self, key, default=None):  # noqa: ANN001
        if _should_log(key):
            _emit(key)
        return orig_get(self, key, default)

    try:
        cls.__getitem__ = _patched_getitem
        cls.get = _patched_get
        setattr(cls, _PATCHED_FLAG, True)
    except Exception:
        return False

    # os.getenv is a thin wrapper around os.environ.get in CPython, so
    # patching the type covers it. Patch the function too for the rare
    # alternate implementation that doesn't dispatch through the type.
    try:
        orig_getenv = os.getenv

        def _patched_getenv(key, default=None):
            if _should_log(key):
                _emit(key)
            return orig_getenv(key, default)

        os.getenv = _patched_getenv
    except Exception:
        pass

    return True


# Execute at import time so the very next env-var read in the container
# is captured. Sitecustomize runs before user code per the Python docs.
install()
