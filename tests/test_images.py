"""Tests for image selection."""

from nyuwaymcpsandbox.sandbox.images import (
    DEFAULT_NODE_IMAGE,
    DEFAULT_PYTHON_IMAGE,
    select_image,
)


def test_node_picked_for_package_json(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    assert select_image(tmp_path) == DEFAULT_NODE_IMAGE


def test_node_picked_for_pnpm_lock(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: 6")
    assert select_image(tmp_path) == DEFAULT_NODE_IMAGE


def test_python_picked_for_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'")
    assert select_image(tmp_path) == DEFAULT_PYTHON_IMAGE


def test_python_picked_for_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0")
    assert select_image(tmp_path) == DEFAULT_PYTHON_IMAGE


def test_node_wins_when_both_markers_present(tmp_path):
    """A polyglot tree with package.json + setup.py should pick Node."""
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "setup.py").write_text("from setuptools import setup; setup()")
    assert select_image(tmp_path) == DEFAULT_NODE_IMAGE


def test_unknown_tree_falls_back_to_python(tmp_path):
    (tmp_path / "README.md").write_text("# nothing here")
    assert select_image(tmp_path) == DEFAULT_PYTHON_IMAGE


def test_missing_path_returns_python_default(tmp_path):
    """select_image should not crash on a path that doesn't exist."""
    assert select_image(tmp_path / "does_not_exist") == DEFAULT_PYTHON_IMAGE


def test_single_python_file_picks_python(tmp_path):
    f = tmp_path / "server.py"
    f.write_text("print('mcp')")
    assert select_image(f) == DEFAULT_PYTHON_IMAGE


def test_single_js_file_picks_node(tmp_path):
    f = tmp_path / "server.js"
    f.write_text("console.log('mcp')")
    assert select_image(f) == DEFAULT_NODE_IMAGE


def test_single_typescript_file_picks_node(tmp_path):
    f = tmp_path / "server.ts"
    f.write_text("export {}")
    assert select_image(f) == DEFAULT_NODE_IMAGE
