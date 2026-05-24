"""GitHub source fetcher.

Resolves ``github:owner/repo`` and ``github:owner/repo@ref`` into a local
temporary directory containing the repository tarball, safely extracted.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

import requests

from nyuwaymcpsandbox.sources._archive import safe_extract_tar

DOWNLOAD_TIMEOUT = 60  # seconds
MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024  # 250 MiB tarball cap (before extraction)
CHUNK_SIZE = 64 * 1024

CODELOAD_URL = "https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"

_REF_PATTERN = re.compile(r"^([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)(?:@([A-Za-z0-9_./\-]+))?$")


class GitHubFetchError(Exception):
    """Could not fetch the specified GitHub source."""


def _parse_spec(spec: str) -> tuple[str, str, str]:
    """Return (owner, repo, ref). ref defaults to 'HEAD'."""
    body = spec[len("github:") :] if spec.startswith("github:") else spec
    match = _REF_PATTERN.match(body)
    if not match:
        raise GitHubFetchError(
            f"Invalid GitHub spec: {spec!r}. "
            "Expected 'github:owner/repo' or 'github:owner/repo@ref'."
        )
    owner, repo, ref = match.group(1), match.group(2), match.group(3) or "HEAD"
    return owner, repo, ref


def _download_tarball(url: str, dest: Path) -> None:
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
                        raise GitHubFetchError(
                            f"Tarball exceeds size cap ({MAX_DOWNLOAD_BYTES} bytes)"
                        )
                    f.write(chunk)
    except requests.RequestException as e:
        raise GitHubFetchError(f"GitHub tarball download failed: {e}") from e


@contextmanager
def fetch_github(spec: str):
    """Yield a local path to the extracted GitHub source. Cleans up on exit."""
    owner, repo, ref = _parse_spec(spec)
    url = CODELOAD_URL.format(owner=owner, repo=repo, ref=ref)

    workdir = Path(tempfile.mkdtemp(prefix="nyuway_sb_gh_"))
    try:
        tarball = workdir / "src.tar.gz"
        _download_tarball(url, tarball)
        extract_dir = workdir / "extracted"
        safe_extract_tar(tarball, extract_dir)
        # GitHub tarballs contain a single top-level dir like "owner-repo-sha".
        children = [p for p in extract_dir.iterdir() if p.is_dir()]
        yield children[0] if len(children) == 1 else extract_dir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
