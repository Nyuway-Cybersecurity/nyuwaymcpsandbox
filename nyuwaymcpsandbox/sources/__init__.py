"""Source dispatch.

Maps a target spec to a context manager that yields a local Path containing
the resolved source tree. Supported prefixes:

    ./path/to/dir            local directory or file
    github:owner/repo[@ref]   GitHub repository tarball
    npm:package[@version]    npm registry tarball
    pypi:package[@version]   PyPI sdist (or wheel as fallback)

The Path yielded by every fetcher is safe for the sandbox to mount or copy
into a container. Tempdirs are removed automatically when the context
manager exits.
"""

from nyuwaymcpsandbox.sources.github import GitHubFetchError, fetch_github
from nyuwaymcpsandbox.sources.local import fetch_local
from nyuwaymcpsandbox.sources.npm import NpmFetchError, fetch_npm
from nyuwaymcpsandbox.sources.pypi import PyPIFetchError, fetch_pypi


class UnsupportedSource(Exception):
    """Source prefix is not recognised."""


def resolve(spec: str):
    """Return a context manager that yields a local Path for the given spec."""
    if spec.startswith("github:"):
        return fetch_github(spec)
    if spec.startswith("npm:"):
        return fetch_npm(spec)
    if spec.startswith("pypi:"):
        return fetch_pypi(spec)
    if ":" in spec and not _looks_like_windows_path(spec):
        prefix = spec.split(":", 1)[0]
        raise UnsupportedSource(
            f"Unknown source prefix: {prefix!r}. Supported: github:, npm:, pypi:, or a local path."
        )
    return fetch_local(spec)


def _looks_like_windows_path(spec: str) -> bool:
    """Heuristic: 'C:\\foo' is a local path, not an unsupported source."""
    return len(spec) >= 2 and spec[1] == ":" and spec[0].isalpha()


__all__ = [
    "GitHubFetchError",
    "NpmFetchError",
    "PyPIFetchError",
    "UnsupportedSource",
    "resolve",
]
