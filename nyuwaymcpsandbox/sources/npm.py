"""npm package source fetcher.

Resolves ``npm:pkg`` (latest) or ``npm:pkg@version`` via the npm registry,
downloads the tarball, and safely extracts it into a temp directory.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

import requests

from nyuwaymcpsandbox.sources._archive import safe_extract_tar

REGISTRY_URL = "https://registry.npmjs.org/{pkg}"
DOWNLOAD_TIMEOUT = 60
MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024
CHUNK_SIZE = 64 * 1024

# Allow scoped names like @scope/name and plain names.
_NAME_PATTERN = re.compile(r"^(@[A-Za-z0-9_.\-]+/)?[A-Za-z0-9_.\-]+$")
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9_.+\-]+$")


class NpmFetchError(Exception):
    """Could not fetch the specified npm package."""


def _parse_spec(spec: str) -> tuple[str, str | None]:
    body = spec[len("npm:") :] if spec.startswith("npm:") else spec
    if body.startswith("@"):
        # scoped: @scope/name[@version]
        if "/" not in body:
            raise NpmFetchError(f"Invalid scoped npm spec: {spec!r}")
        slash = body.index("/")
        rest = body[slash + 1 :]
        if "@" in rest:
            name_tail, version = rest.split("@", 1)
            name = body[: slash + 1] + name_tail
        else:
            name, version = body, None
    elif "@" in body:
        name, version = body.split("@", 1)
    else:
        name, version = body, None

    if not _NAME_PATTERN.match(name):
        raise NpmFetchError(f"Invalid npm package name: {name!r}")
    if version is not None and not _VERSION_PATTERN.match(version):
        raise NpmFetchError(f"Invalid npm version: {version!r}")
    return name, version


def _resolve_tarball_url(name: str, version: str | None) -> str:
    try:
        resp = requests.get(REGISTRY_URL.format(pkg=name), timeout=DOWNLOAD_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise NpmFetchError(f"npm registry lookup failed for {name!r}: {e}") from e

    if version is None:
        version = (data.get("dist-tags") or {}).get("latest")
        if not version:
            raise NpmFetchError(f"No 'latest' tag for {name!r}")

    versions = data.get("versions") or {}
    info = versions.get(version)
    if not info:
        raise NpmFetchError(f"Version {version!r} not found for {name!r}")
    url = (info.get("dist") or {}).get("tarball")
    if not url:
        raise NpmFetchError(f"No tarball URL for {name!r}@{version}")
    return str(url)


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
                        raise NpmFetchError(
                            f"Tarball exceeds size cap ({MAX_DOWNLOAD_BYTES} bytes)"
                        )
                    f.write(chunk)
    except requests.RequestException as e:
        raise NpmFetchError(f"npm tarball download failed: {e}") from e


@contextmanager
def fetch_npm(spec: str):
    name, version = _parse_spec(spec)
    url = _resolve_tarball_url(name, version)
    workdir = Path(tempfile.mkdtemp(prefix="nyuway_sb_npm_"))
    try:
        tarball = workdir / "pkg.tgz"
        _download(url, tarball)
        extract_dir = workdir / "extracted"
        safe_extract_tar(tarball, extract_dir)
        # npm tarballs contain a "package/" top-level dir.
        pkg_dir = extract_dir / "package"
        yield pkg_dir if pkg_dir.is_dir() else extract_dir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
