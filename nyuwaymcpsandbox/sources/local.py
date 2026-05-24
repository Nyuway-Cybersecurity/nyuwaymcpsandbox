"""Local filesystem source: no-op resolver."""

from contextlib import contextmanager
from pathlib import Path


@contextmanager
def fetch_local(path: str):
    """Yield the path unchanged. No cleanup needed for local sources."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Local path not found: {path}")
    yield p
