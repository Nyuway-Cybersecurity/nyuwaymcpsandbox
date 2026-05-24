"""CLI smoke tests - verify entry point wires correctly."""

from click.testing import CliRunner

from nyuwaymcpsandbox import __version__
from nyuwaymcpsandbox.cli.main import cli


def test_cli_version_flag_emits_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_help_lists_commands():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "detonate" in result.output
    assert "setup" in result.output


def test_detonate_stub_exits_nonzero_with_hint():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "./some-server"])
    assert result.exit_code == 2
    assert "pre-release" in result.output


def test_detonate_rejects_invalid_mode():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "./x", "--mode", "warp"])
    assert result.exit_code != 0


def test_detonate_rejects_invalid_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "./x", "--output", "yaml"])
    assert result.exit_code != 0


def test_setup_stub_exits_nonzero_with_hint():
    runner = CliRunner()
    result = runner.invoke(cli, ["setup"])
    assert result.exit_code == 2
    assert "pre-release" in result.output
