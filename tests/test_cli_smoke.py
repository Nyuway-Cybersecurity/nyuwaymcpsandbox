"""CLI smoke tests.

Verify that the CLI entry point wires correctly and that --dry-run
produces a real end-to-end report. The pipeline itself is tested
exhaustively in test_pipeline.py.
"""

import json

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


def test_detonate_rejects_invalid_mode():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "./x", "--mode", "warp"])
    assert result.exit_code != 0


def test_detonate_rejects_invalid_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["detonate", "./x", "--output", "yaml"])
    assert result.exit_code != 0


def test_setup_exits_zero_with_instructions():
    runner = CliRunner()
    result = runner.invoke(cli, ["setup"])
    assert result.exit_code == 0
    assert "Docker" in result.output


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
