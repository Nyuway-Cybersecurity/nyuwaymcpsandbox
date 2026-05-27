"""CLI smoke tests.

Verify that the CLI entry point wires correctly and that --dry-run
produces a real end-to-end report. The pipeline itself is tested
exhaustively in test_pipeline.py.
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nyuwaymcpsandbox import __version__
from nyuwaymcpsandbox.cli.main import cli


def test_cli_version_flag_emits_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_version_consistency():
    """__init__.__version__ must match the version declared in pyproject.toml.

    Catches the common drift where one file is updated but the other is not.
    """
    import tomllib  # stdlib 3.11+

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    with pyproject.open("rb") as fh:
        data = tomllib.load(fh)
    toml_version = data["project"]["version"]
    assert __version__ == toml_version, (
        f"nyuwaymcpsandbox/__init__.py has __version__ = {__version__!r} "
        f"but pyproject.toml has version = {toml_version!r}. "
        "Update both files together."
    )


def test_cli_help_lists_commands():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "detonate" in result.output
    assert "setup" in result.output


def test_detonate_rejects_invalid_mode():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "./x", "--mode", "warp"])
    assert result.exit_code != 0


def test_detonate_rejects_invalid_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "./x", "--output", "yaml"])
    assert result.exit_code != 0


def test_setup_docker_unreachable_exits_nonzero(monkeypatch):
    """setup exits 1 and prints a hint when Docker is not reachable."""
    import nyuwaymcpsandbox.cli.main as cli_mod

    class _FakeDockerSdk:
        @staticmethod
        def from_env():
            raise OSError("Cannot connect to Docker daemon")

    monkeypatch.setattr(cli_mod, "_docker_sdk_for_setup", lambda: _FakeDockerSdk)
    runner = CliRunner()
    result = runner.invoke(cli, ["setup"])
    assert result.exit_code == 1
    assert "Docker" in result.output


def test_setup_pulls_all_images_and_exits_zero(monkeypatch):
    """setup pulls all three images and exits 0 on success."""
    import nyuwaymcpsandbox.cli.main as cli_mod

    pulled: list[str] = []

    class _FakeImages:
        def pull(self, image: str):
            pulled.append(image)

    class _FakeClient:
        images = _FakeImages()

        def ping(self):
            return True

    class _FakeDockerSdk:
        @staticmethod
        def from_env():
            return _FakeClient()

    monkeypatch.setattr(cli_mod, "_docker_sdk_for_setup", lambda: _FakeDockerSdk)
    runner = CliRunner()
    result = runner.invoke(cli, ["setup"])
    assert result.exit_code == 0, result.output
    assert "python:3.12-slim" in pulled
    assert "node:20-slim" in pulled
    assert "nicolaka/netshoot" in pulled
    assert "Setup complete" in result.output


def test_setup_pull_failure_exits_nonzero(monkeypatch):
    """setup exits 1 when any image pull fails."""
    import nyuwaymcpsandbox.cli.main as cli_mod

    class _FakeImages:
        def pull(self, image: str):
            if image == "nicolaka/netshoot":
                raise OSError("pull failed: network timeout")

    class _FakeClient:
        images = _FakeImages()

        def ping(self):
            return True

    class _FakeDockerSdk:
        @staticmethod
        def from_env():
            return _FakeClient()

    monkeypatch.setattr(cli_mod, "_docker_sdk_for_setup", lambda: _FakeDockerSdk)
    runner = CliRunner()
    result = runner.invoke(cli, ["setup"])
    assert result.exit_code == 1
    assert "nicolaka/netshoot" in result.output


def test_detonate_dry_run_against_tmp_dir_emits_report(tmp_path):
    """End-to-end smoke: --dry-run renders a real report with no Docker."""
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", str(tmp_path), "--dry-run"])
    # No findings expected with the empty source dir + stub monitors,
    # so the verdict is PASS and the exit code is 0.
    assert result.exit_code == 0, result.output
    assert "nyuwaymcpsandbox" in result.output
    assert "PASS" in result.output


def test_detonate_dry_run_json_output_parses(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", str(tmp_path), "--dry-run", "--output", "json"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["tool"] == "nyuwaymcpsandbox"
    assert parsed["target"] == str(tmp_path)


def test_detonate_dry_run_sarif_output_parses(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", str(tmp_path), "--dry-run", "--output", "sarif"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["version"] == "2.1.0"


def test_detonate_dry_run_full_mode_runs_llm_driver(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        cli, ["detonate", str(tmp_path), "--dry-run", "--mode", "full", "--output", "json"]
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    types = [e["type"] for e in parsed["timeline"]["events"]]
    # Full mode adds the LLM driver events.
    assert "llm.prompt_sent" in types


def test_detonate_without_dry_run_reports_not_ready(tmp_path):
    """Real MCP stdio transport isn't wired yet - the CLI must say so clearly."""
    runner = CliRunner()
    # Use a fake source path so source resolution doesn't fail first.
    result = runner.invoke(cli, ["detonate", str(tmp_path)])
    # Exit code 2 = configuration / pipeline-not-ready error.
    assert result.exit_code == 2
    # The user-facing error must mention the workaround.
    assert "dry-run" in result.output.lower()


def test_detonate_unknown_source_prefix_exits_2():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "weird:foo/bar", "--dry-run"])
    assert result.exit_code == 2
    assert "weird" in result.output


def test_detonate_local_path_not_found_exits_2():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "/does/not/exist/anywhere", "--dry-run"])
    assert result.exit_code == 2


def test_detonate_subprocess_transport_against_real_echo_server(tmp_path):
    """Real protocol stack end-to-end via the CLI - no Docker, no fakes for MCP."""
    import shlex
    import sys
    from pathlib import Path

    fixture = Path(__file__).parent / "fixtures" / "echo_mcp_server.py"
    # Quote properly so Windows paths with spaces survive shlex.split.
    command = shlex.join([sys.executable, str(fixture)])
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "detonate",
            str(tmp_path),
            "--mcp-transport",
            "subprocess",
            "--mcp-command",
            command,
            "--output",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    invocations = [
        e["payload"]["name"]
        for e in parsed["timeline"]["events"]
        if e["type"] == "mcp.tool_invocation"
    ]
    assert "echo" in invocations
    assert "fail" in invocations


def test_detonate_subprocess_transport_without_command_exits_2(tmp_path):
    """Real MCP transport without --mcp-command must produce a clear error."""
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", str(tmp_path), "--mcp-transport", "subprocess"])
    assert result.exit_code == 2
    assert "mcp-command" in result.output.lower()


def test_detonate_invalid_mcp_transport_rejected():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "./x", "--mcp-transport", "telnet", "--dry-run"])
    assert result.exit_code != 0


def test_detonate_mcp_arg_tokens_take_precedence_over_mcp_command(tmp_path):
    """--mcp-arg tokens are used as-is and override --mcp-command when both given."""
    import sys
    from pathlib import Path

    fixture = Path(__file__).parent / "fixtures" / "echo_mcp_server.py"
    runner = CliRunner()
    # --mcp-arg avoids shlex parsing entirely; even if --mcp-command is also
    # present, the --mcp-arg tokens win.
    result = runner.invoke(
        cli,
        [
            "detonate",
            str(tmp_path),
            "--mcp-transport",
            "subprocess",
            "--mcp-arg",
            sys.executable,
            "--mcp-arg",
            str(fixture),
            "--mcp-command",
            "should-be-ignored",
            "--output",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    import json

    parsed = json.loads(result.output)
    invocations = [
        e["payload"]["name"]
        for e in parsed["timeline"]["events"]
        if e["type"] == "mcp.tool_invocation"
    ]
    assert "echo" in invocations


def test_detonate_mcp_arg_alone_works(tmp_path):
    """--mcp-arg without --mcp-command launches the server correctly."""
    import sys
    from pathlib import Path

    fixture = Path(__file__).parent / "fixtures" / "echo_mcp_server.py"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "detonate",
            str(tmp_path),
            "--mcp-transport",
            "subprocess",
            "--mcp-arg",
            sys.executable,
            "--mcp-arg",
            str(fixture),
            "--output",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output


def test_detonate_mcp_command_fallback_when_no_mcp_arg(tmp_path):
    """--mcp-command is used when no --mcp-arg tokens are given.

    Uses shlex.join to produce a properly quoted command string so the
    round-trip through shlex.split is lossless on all platforms.
    """
    import shlex as _shlex
    import sys
    from pathlib import Path as _Path

    fixture = _Path(__file__).parent / "fixtures" / "echo_mcp_server.py"
    # shlex.join quotes each token so the round-trip through shlex.split
    # is safe on Linux/macOS. Windows users with backslash paths should
    # use --mcp-arg instead (which bypasses shlex entirely).
    command = _shlex.join([sys.executable, str(fixture)])
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "detonate",
            str(tmp_path),
            "--mcp-transport",
            "subprocess",
            "--mcp-command",
            command,
            "--output",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output


# --- --env-file flag tests -------------------------------------------------


def test_load_env_file_parses_typical_dotenv(tmp_path):
    """The .env parser handles the common shapes: KEY=value, quotes, comments."""
    from nyuwaymcpsandbox.cli.main import _load_env_file

    env_file = tmp_path / "creds.env"
    env_file.write_text(
        "# This is a comment\n"
        "\n"
        "GITHUB_TOKEN=ghp_FakeToken123\n"
        '  SLACK_BOT_TOKEN  =  "xoxb-FakeToken"  \n'
        'DOUBLE_QUOTED="hello world"\n'
        "SINGLE_QUOTED='single value'\n"
        "export EXPORTED_KEY=also_fine\n"
        "EMPTY_VALUE=\n"
        "NO_EQUALS_LINE_IS_IGNORED\n",
        encoding="utf-8",
    )
    parsed = _load_env_file(str(env_file))
    assert parsed["GITHUB_TOKEN"] == "ghp_FakeToken123"
    assert parsed["SLACK_BOT_TOKEN"] == "xoxb-FakeToken"
    assert parsed["DOUBLE_QUOTED"] == "hello world"
    assert parsed["SINGLE_QUOTED"] == "single value"
    assert parsed["EXPORTED_KEY"] == "also_fine"
    assert parsed["EMPTY_VALUE"] == ""
    assert "NO_EQUALS_LINE_IS_IGNORED" not in parsed


def test_load_env_file_missing_path_raises():
    from nyuwaymcpsandbox.cli.main import _load_env_file

    with pytest.raises(FileNotFoundError):
        _load_env_file("/path/does/not/exist.env")


def test_detonate_rejects_invalid_env_file_path(tmp_path):
    """Click validates the path before our code runs - exit non-zero."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "detonate",
            str(tmp_path),
            "--dry-run",
            "--env-file",
            str(tmp_path / "does_not_exist.env"),
        ],
    )
    assert result.exit_code != 0


def test_detonate_env_file_loaded_and_passed_through_config(tmp_path):
    """End-to-end: --env-file populates PipelineConfig.env_extra."""
    env_file = tmp_path / "creds.env"
    env_file.write_text("FOO=bar\nBAZ=qux\n", encoding="utf-8")

    captured: dict = {}
    import nyuwaymcpsandbox.cli.main as cli_mod

    original_run = cli_mod.run_pipeline

    def _spy(config, deps=None):
        captured["env_extra"] = dict(config.env_extra)
        return original_run(config, deps)

    cli_mod.run_pipeline = _spy
    try:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "detonate",
                str(tmp_path),
                "--dry-run",
                "--env-file",
                str(env_file),
            ],
        )
    finally:
        cli_mod.run_pipeline = original_run

    assert result.exit_code == 0, result.output
    assert captured["env_extra"] == {"FOO": "bar", "BAZ": "qux"}


def test_detonate_without_env_file_yields_empty_env_extra(tmp_path):
    """Omitting --env-file leaves env_extra as an empty dict (no surprises)."""
    captured: dict = {}
    import nyuwaymcpsandbox.cli.main as cli_mod

    original_run = cli_mod.run_pipeline

    def _spy(config, deps=None):
        captured["env_extra"] = dict(config.env_extra)
        return original_run(config, deps)

    cli_mod.run_pipeline = _spy
    try:
        runner = CliRunner()
        result = runner.invoke(cli, ["detonate", str(tmp_path), "--dry-run"])
    finally:
        cli_mod.run_pipeline = original_run

    assert result.exit_code == 0, result.output
    assert captured["env_extra"] == {}
