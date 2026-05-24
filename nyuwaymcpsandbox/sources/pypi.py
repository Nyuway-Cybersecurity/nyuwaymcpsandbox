"""PyPI package source fetcher.

Resolves ``pypi:pkg`` (latest) or ``pypi:pkg@version`` via the PyPI JSON
API, prefers the sdist (.tar.gz), falls back to wheel (.whl) when no
sdist exists, and safely extracts the archive.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

import requests

from nyuwaymcpsandbox.sources._archive import safe_extract_tar, safe_extract_zip

PYPI_JSON_URL = "https://pypi.org/pypi/{pkg}/json"
PYPI_JSON_URL_VERSIONED = "https://pypi.org/pypi/{pkg}/{version}/json"
DOWNLOAD_TIMEOUT = 60
MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024
CHUNK_SIZE = 64 * 1024

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]+$")
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9_.+\-]+$")


class PyPIFetchError(Exception):
    """Could not fetch the specified PyPI package."""


def _parse_spec(spec: str) -> tuple[str, str | None]:
    body = spec[len("pypi:") :] if spec.startswith("pypi:") else spec
    if "@" in body:
        name, version = body.split("@", 1)
    else:
        name, version = body, None
    if not _NAME_PATTERN.match(name):
        raise PyPIFetchError(f"Invalid PyPI package name: {name!r}")
    if version is not None and not _VERSION_PATTERN.match(version):
        raise PyPIFetchError(f"Invalid PyPI version: {version!r}")
    return name, version


def _pick_distribution(urls: list[dict]) -> dict:
    """Prefer sdist, fall back to wheel."""
    sdists = [u for u in urls if u.get("packagetype") == "sdist"]
    if sdists:
        return sdists[0]
    wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
    if wheels:
        return wheels[0]
    raise PyPIFetchError("No sdist or wheel distribution available")


def _resolve_distribution(name: str, version: str | None) -> dict:
    url = (
        PYPI_JSON_URL_VERSIONED.format(pkg=name, version=version)
        if version
        else PYPI_JSON_URL.format(pkg=name)
    )
    try:
        resp = requests.get(url, timeout=DOWNLOAD_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise PyPIFetchError(f"PyPI metadata lookup failed for {name!r}: {e}") from e
    urls = data.get("urls") or []
    if not urls:
        raise PyPIFetchError(f"No distributions listed for {name!r}")
    return _pick_distribution(urls)


def _download(url: str, dest: Path) -> None:
    try:
        with requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT, allow_redirects=True) as resp:
            resp.raise_for_status()
            written = 0
            with dest.open("wb") as f:
                for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > MAX_DOWNLOAD_BYTES:
                        raise PyPIFetchError(
                            f"Distribution exceeds size cap ({MAX_DOWNLOAD_BYTES} bytes)"
                        )
                    f.write(chunk)
    except requests.RequestException as e:
        raise PyPIFetchError(f"PyPI distribution download failed: {e}") from e


@contextmanager
def fetch_pypi(spec: str):
    name, version = _parse_spec(spec)
    dist = _resolve_distribution(name, version)
    url = dist.get("url")
    filename = dist.get("filename", "")
    if not url:
        raise PyPIFetchError(f"PyPI distribution metadata missing 'url' for {name!r}")

    workdir = Path(tempfile.mkdtemp(prefix="nyuway_sb_pypi_"))
    try:
        archive = workdir / filename
        _download(url, archive)
        extract_dir = workdir / "extracted"
        if filename.endswith((".whl", ".zip")):
            safe_extract_zip(archive, extract_dir)
        else:
            safe_extract_tar(archive, extract_dir)
        # sdist tarballs contain a single top-level "pkg-version/" dir.
        children = [p for p in extract_dir.iterdir() if p.is_dir()]
        yield children[0] if len(children) == 1 else extract_dir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
