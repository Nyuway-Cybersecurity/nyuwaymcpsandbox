"""Safe archive extraction shared by all source fetchers.

Archive extraction is a known attack surface (tar/zip slip via ``..``
entries, absolute paths, symlinks, zip bombs). Three guards are enforced:

1. Every entry's resolved destination must remain inside the target dir.
2. Symlinks, hardlinks, and device entries are skipped.
3. Per-file and total uncompressed sizes are capped.

``UnsafeArchive`` is raised on any guard violation; callers must treat
it as a hard failure (do not retry, do not partially extract).
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

MAX_TOTAL_BYTES = 200 * 1024 * 1024  # 200 MiB uncompressed total
MAX_ENTRY_BYTES = 50 * 1024 * 1024  # 50 MiB per file


class UnsafeArchive(Exception):
    """Archive contains entries that would escape the target dir or exceed size caps."""


def _is_within(base: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def safe_extract_tar(archive_path: Path, dest: Path) -> None:
    """Extract a tar/tar.gz/tar.bz2 archive into ``dest`` with safety checks."""
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    with tarfile.open(archive_path, mode="r:*") as tar:
        for member in tar.getmembers():
            if member.islnk() or member.issym():
                continue  # Skip any link entry; they cannot bypass guards.
            if member.isdev():
                continue
            target_path = (dest / member.name).resolve()
            if not _is_within(dest, target_path):
                raise UnsafeArchive(f"Archive entry escapes target dir: {member.name!r}")
            if member.size is not None and member.size > MAX_ENTRY_BYTES:
                raise UnsafeArchive(
                    f"Archive entry too large ({member.size} bytes): {member.name!r}"
                )
            total += max(0, member.size or 0)
            if total > MAX_TOTAL_BYTES:
                raise UnsafeArchive(f"Archive total size exceeds cap ({total} > {MAX_TOTAL_BYTES})")
            tar.extract(member, path=dest, filter="data")


def safe_extract_zip(archive_path: Path, dest: Path) -> None:
    """Extract a zip archive into ``dest`` with safety checks."""
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if name.startswith("/") or "\x00" in name:
                raise UnsafeArchive(f"Archive entry has unsafe name: {name!r}")
            target_path = (dest / name).resolve()
            if not _is_within(dest, target_path):
                raise UnsafeArchive(f"Archive entry escapes target dir: {name!r}")
            if info.file_size > MAX_ENTRY_BYTES:
                raise UnsafeArchive(f"Archive entry too large ({info.file_size} bytes): {name!r}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise UnsafeArchive(f"Archive total size exceeds cap ({total} > {MAX_TOTAL_BYTES})")
            zf.extract(info, path=dest)
