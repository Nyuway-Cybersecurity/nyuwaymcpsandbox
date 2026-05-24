"""Image selection for sandboxed MCP server execution.

Inspects the source tree to pick a base container image. Node servers
get a node image; Python servers get a python image; anything else
falls back to Python (most MCP server samples are Python today).
"""

from __future__ import annotations

from pathlib import Path

DEFAULT_PYTHON_IMAGE = "python:3.12-slim"
DEFAULT_NODE_IMAGE = "node:20-slim"

# Files that indicate the language of an MCP server source tree.
_NODE_MARKERS = ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")
_PYTHON_MARKERS = ("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile")


def select_image(source_path: Path | str) -> str:
    """Return the base image to use for the given source tree.

    Node markers win when both are present (uncommon, but `setup.py` in
    a primarily-node tree shouldn't switch the image).
    """
    p = Path(source_path)
    if not p.exists():
        return DEFAULT_PYTHON_IMAGE
    if p.is_file():
        # Single-file targets: pick by extension.
        suffix = p.suffix.lower()
        if suffix in (".js", ".mjs", ".ts", ".tsx"):
            return DEFAULT_NODE_IMAGE
        return DEFAULT_PYTHON_IMAGE
    if any((p / m).is_file() for m in _NODE_MARKERS):
        return DEFAULT_NODE_IMAGE
    if any((p / m).is_file() for m in _PYTHON_MARKERS):
        return DEFAULT_PYTHON_IMAGE
    return DEFAULT_PYTHON_IMAGE
