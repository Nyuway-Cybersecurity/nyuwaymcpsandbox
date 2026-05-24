"""Source resolver tests.

All network calls are mocked. The archive safety tests exercise the
real ``tarfile``/``zipfile`` machinery against fixture archives built
in-process - no external assets required.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from nyuwaymcpsandbox.sources import (
    GitHubFetchError,
    NpmFetchError,
    PyPIFetchError,
    UnsupportedSource,
    resolve,
)
from nyuwaymcpsandbox.sources._archive import (
    UnsafeArchive,
    safe_extract_tar,
    safe_extract_zip,
)
from nyuwaymcpsandbox.sources.github import _parse_spec as _gh_parse
from nyuwaymcpsandbox.sources.local import fetch_local
from nyuwaymcpsandbox.sources.npm import _parse_spec as _npm_parse
from nyuwaymcpsandbox.sources.pypi import _parse_spec as _pypi_parse

# ── Dispatch ─────────────────────────────────────────────────────────────


def test_resolve_unknown_prefix_raises():
    with pytest.raises(UnsupportedSource, match="weird"):
        with resolve("weird:foo/bar"):
            pass


def test_resolve_windows_path_is_local(tmp_path, monkeypatch):
    """C:\\foo should resolve as local, not be rejected as a bad source prefix."""
    monkeypatch.chdir(tmp_path)
    spec = str(tmp_path)
    with resolve(spec) as p:
        assert Path(p).exists()


def test_resolve_local_path_yields_same_path(tmp_path):
    with resolve(str(tmp_path)) as p:
        assert Path(p).resolve() == tmp_path.resolve()


def test_resolve_local_missing_raises():
    with pytest.raises(FileNotFoundError):
        with resolve("/nonexistent/path/should/fail"):
            pass


# ── Local ────────────────────────────────────────────────────────────────


def test_fetch_local_yields_path(tmp_path):
    with fetch_local(str(tmp_path)) as p:
        assert Path(p) == tmp_path


def test_fetch_local_missing_raises():
    with pytest.raises(FileNotFoundError, match="not found"):
        with fetch_local("/this/does/not/exist/at/all"):
            pass


# ── GitHub spec parsing ──────────────────────────────────────────────────


def test_github_parse_owner_repo():
    owner, repo, ref = _gh_parse("github:foo/bar")
    assert (owner, repo, ref) == ("foo", "bar", "HEAD")


def test_github_parse_with_ref():
    owner, repo, ref = _gh_parse("github:foo/bar@v1.2.3")
    assert (owner, repo, ref) == ("foo", "bar", "v1.2.3")


def test_github_parse_invalid_raises():
    with pytest.raises(GitHubFetchError, match="Invalid"):
        _gh_parse("github:not-a-valid-spec")


# ── npm spec parsing ─────────────────────────────────────────────────────


def test_npm_parse_simple():
    assert _npm_parse("npm:requests") == ("requests", None)


def test_npm_parse_versioned():
    assert _npm_parse("npm:foo@1.2.3") == ("foo", "1.2.3")


def test_npm_parse_scoped():
    assert _npm_parse("npm:@scope/pkg") == ("@scope/pkg", None)


def test_npm_parse_scoped_versioned():
    assert _npm_parse("npm:@scope/pkg@2.0.0") == ("@scope/pkg", "2.0.0")


def test_npm_parse_invalid_scoped_no_slash_raises():
    with pytest.raises(NpmFetchError, match="scoped"):
        _npm_parse("npm:@nopackage")


def test_npm_parse_invalid_name_raises():
    with pytest.raises(NpmFetchError, match="package name"):
        _npm_parse("npm:bad name with spaces")


# ── PyPI spec parsing ────────────────────────────────────────────────────


def test_pypi_parse_simple():
    assert _pypi_parse("pypi:requests") == ("requests", None)


def test_pypi_parse_versioned():
    assert _pypi_parse("pypi:requests@2.31.0") == ("requests", "2.31.0")


def test_pypi_parse_invalid_name_raises():
    with pytest.raises(PyPIFetchError, match="package name"):
        _pypi_parse("pypi:bad name")


# ── Safe archive extraction: tar ─────────────────────────────────────────


def _build_tar_bytes(entries: dict[str, bytes]) -> bytes:
    """Build an in-memory tar.gz with the given filename -> content map."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_safe_extract_tar_extracts_valid_archive(tmp_path):
    archive = tmp_path / "ok.tar.gz"
    archive.write_bytes(_build_tar_bytes({"hello.txt": b"world"}))
    dest = tmp_path / "out"
    safe_extract_tar(archive, dest)
    assert (dest / "hello.txt").read_text() == "world"


def test_safe_extract_tar_rejects_path_traversal(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    archive.write_bytes(_build_tar_bytes({"../escape.txt": b"x"}))
    dest = tmp_path / "out"
    with pytest.raises(UnsafeArchive, match="escapes"):
        safe_extract_tar(archive, dest)


def test_safe_extract_tar_rejects_oversize_entry(tmp_path, monkeypatch):
    """Cap-lowered so a 1 KiB payload trips the per-entry guard."""
    from nyuwaymcpsandbox.sources import _archive

    monkeypatch.setattr(_archive, "MAX_ENTRY_BYTES", 100)
    archive = tmp_path / "big.tar.gz"
    archive.write_bytes(_build_tar_bytes({"big.bin": b"A" * 1024}))
    with pytest.raises(UnsafeArchive, match="too large"):
        safe_extract_tar(archive, tmp_path / "out")


def test_safe_extract_tar_rejects_total_size_cap(tmp_path, monkeypatch):
    """Many small files summing past MAX_TOTAL_BYTES must be rejected."""
    from nyuwaymcpsandbox.sources import _archive

    monkeypatch.setattr(_archive, "MAX_TOTAL_BYTES", 500)
    archive = tmp_path / "total.tar.gz"
    archive.write_bytes(_build_tar_bytes({f"f{i}.bin": b"X" * 100 for i in range(10)}))
    with pytest.raises(UnsafeArchive, match="total size"):
        safe_extract_tar(archive, tmp_path / "out")


def test_safe_extract_tar_skips_symlinks(tmp_path):
    """Symlink entries must be skipped, not extracted."""
    archive = tmp_path / "sym.tar.gz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
        # Real file alongside should still extract.
        real = tarfile.TarInfo(name="real.txt")
        real.size = 3
        tar.addfile(real, io.BytesIO(b"ok\n"))
    archive.write_bytes(buf.getvalue())
    dest = tmp_path / "out"
    safe_extract_tar(archive, dest)
    assert (dest / "real.txt").exists()
    assert not (dest / "link").exists()


# ── Safe archive extraction: zip ─────────────────────────────────────────


def _build_zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_safe_extract_zip_extracts_valid_archive(tmp_path):
    archive = tmp_path / "ok.zip"
    archive.write_bytes(_build_zip_bytes({"hello.txt": b"world"}))
    dest = tmp_path / "out"
    safe_extract_zip(archive, dest)
    assert (dest / "hello.txt").read_text() == "world"


def test_safe_extract_zip_rejects_absolute_path(tmp_path):
    archive = tmp_path / "evil.zip"
    archive.write_bytes(_build_zip_bytes({"/etc/passwd": b"x"}))
    with pytest.raises(UnsafeArchive, match="unsafe name"):
        safe_extract_zip(archive, tmp_path / "out")


def test_safe_extract_zip_rejects_path_traversal(tmp_path):
    archive = tmp_path / "evil.zip"
    archive.write_bytes(_build_zip_bytes({"../../etc/passwd": b"x"}))
    with pytest.raises(UnsafeArchive, match="escapes"):
        safe_extract_zip(archive, tmp_path / "out")


# ── npm fetcher mocked end-to-end ────────────────────────────────────────


class _FakeResponse:
    def __init__(self, payload=None, content=b"", status=200):
        self._payload = payload
        self._content = content
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise __import__("requests").HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload

    def iter_content(self, chunk_size=8192):
        yield self._content

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_npm_resolve_tarball_404_raises(tmp_path):
    from nyuwaymcpsandbox.sources import npm as npm_mod

    def fake_get(url, *a, **kw):
        return _FakeResponse(status=404)

    with patch.object(npm_mod.requests, "get", side_effect=fake_get):
        with pytest.raises(NpmFetchError, match="registry lookup"):
            with npm_mod.fetch_npm("npm:does-not-exist"):
                pass


def test_npm_registry_missing_latest_raises():
    from nyuwaymcpsandbox.sources import npm as npm_mod

    def fake_get(url, *a, **kw):
        return _FakeResponse(payload={"versions": {}})

    with patch.object(npm_mod.requests, "get", side_effect=fake_get):
        with pytest.raises(NpmFetchError, match="'latest'"):
            with npm_mod.fetch_npm("npm:no-latest"):
                pass


# ── PyPI fetcher mocked metadata only ────────────────────────────────────


def test_pypi_resolve_no_distributions_raises():
    from nyuwaymcpsandbox.sources import pypi as pypi_mod

    def fake_get(url, *a, **kw):
        return _FakeResponse(payload={"urls": []})

    with patch.object(pypi_mod.requests, "get", side_effect=fake_get):
        with pytest.raises(PyPIFetchError, match="No distributions"):
            with pypi_mod.fetch_pypi("pypi:empty-pkg"):
                pass


def test_pypi_pick_distribution_prefers_sdist():
    from nyuwaymcpsandbox.sources.pypi import _pick_distribution

    urls = [
        {"packagetype": "bdist_wheel", "url": "wheel.whl", "filename": "x.whl"},
        {"packagetype": "sdist", "url": "src.tar.gz", "filename": "x.tar.gz"},
    ]
    picked = _pick_distribution(urls)
    assert picked["packagetype"] == "sdist"


def test_pypi_pick_distribution_falls_back_to_wheel():
    from nyuwaymcpsandbox.sources.pypi import _pick_distribution

    urls = [{"packagetype": "bdist_wheel", "url": "wheel.whl", "filename": "x.whl"}]
    picked = _pick_distribution(urls)
    assert picked["packagetype"] == "bdist_wheel"


def test_pypi_pick_distribution_no_supported_raises():
    from nyuwaymcpsandbox.sources.pypi import _pick_distribution

    with pytest.raises(PyPIFetchError):
        _pick_distribution([{"packagetype": "bdist_egg"}])
