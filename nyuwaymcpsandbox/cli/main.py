"""nyuwaymcpsandbox CLI entry point.

The CLI is thin: it parses options, builds a PipelineConfig and
PipelineDeps, calls run_pipeline(), prints the rendered output, and
exits with the appropriate code.

Real stdio MCP transport and real LLM backend land separately. Until
then, --dry-run wires in FakeMcpClient and FakeLlmBackend so the rest
of the pipeline (sources, container session, monitors, harness,
detection rules, verdict, output) is end-to-end exercised.
"""

from __future__ import annotations

import click

from nyuwaymcpsandbox import __version__
from nyuwaymcpsandbox.drivers.fakes import (
    FakeLlmBackend,
    FakeMcpClient,
    fake_docker_client_factory,
)
from nyuwaymcpsandbox.pipeline import (
    VALID_MODES,
    VALID_OUTPUTS,
    PipelineConfig,
    PipelineDeps,
    PipelineNotReady,
    exit_code_for,
    run_pipeline,
)
from nyuwaymcpsandbox.sandbox.orchestrator import OrchestratorError
from nyuwaymcpsandbox.sources import (
    GitHubFetchError,
    NpmFetchError,
    PyPIFetchError,
    UnsupportedSource,
)

SEVERITY_CHOICES = ("low", "medium", "high", "critical")


@click.group()
@click.version_option(__version__, prog_name="nyuwaymcpsandbox")
def cli():
    """nyuwaymcpsandbox - Behavioral sandbox for MCP servers."""


@cli.command()
@click.argument("target")
@click.option(
    "--mode",
    type=click.Choice(VALID_MODES),
    default="fast",
    show_default=True,
    help="Detonation mode. 'fast' = deterministic harness only. 'full' = with LLM driver.",
)
@click.option(
    "--output",
    type=click.Choice(VALID_OUTPUTS),
    default="timeline",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_CHOICES),
    default=None,
    help="Exit non-zero when any finding meets or exceeds this severity.",
)
@click.option(
    "--api-key",
    default=None,
    envvar="NYUWAY_LLM_API_KEY",
    help="LLM API key for Full mode (or set NYUWAY_LLM_API_KEY env var).",
)
@click.option(
    "--llm",
    "llm_model",
    default=None,
    help="LLM driver target. 'local' uses local Ollama; otherwise a litellm model identifier.",
)
@click.option(
    "--allow-network",
    is_flag=True,
    help="Permit real outbound egress from the sandbox (default: sinkholed).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Run the pipeline with in-memory fakes instead of real Docker / MCP / LLM transports. "
    "Useful for verifying CLI plumbing without external dependencies.",
)
def detonate(target, mode, output, fail_on, api_key, llm_model, allow_network, dry_run):
    """Detonate an MCP server in a sandboxed container and record behavior.

    TARGET may be a local path, github:owner/repo, npm:package, or pypi:package.
    """
    config = PipelineConfig(
        target=target,
        mode=mode,
        output=output,
        fail_on=fail_on,
        api_key=api_key,
        llm_model=llm_model,
        allow_network=allow_network,
    )

    deps = PipelineDeps()
    if dry_run:
        # Replace the real-but-not-yet-wired transports with in-memory
        # fakes. The docker client is also faked so the orchestrator's
        # secure-defaults code path still exercises, just without
        # talking to a real daemon.
        deps.mcp_client_factory = lambda _container: FakeMcpClient()
        deps.llm_backend_factory = lambda _model, _key: FakeLlmBackend()
        deps.docker_client_factory = fake_docker_client_factory

    try:
        result = run_pipeline(config, deps)
    except PipelineNotReady as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(2) from e
    except OrchestratorError as e:
        click.echo(f"Error: {e}", err=True)
        click.echo(
            "Hint: pass --dry-run to exercise the pipeline without a running Docker daemon.",
            err=True,
        )
        raise SystemExit(2) from e
    except (UnsupportedSource, GitHubFetchError, NpmFetchError, PyPIFetchError) as e:
        click.echo(f"Error fetching source {target!r}: {e}", err=True)
        raise SystemExit(2) from e
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(2) from e

    click.echo(result.rendered)
    raise SystemExit(exit_code_for(result.report, fail_on))


@cli.command()
def setup():
    """One-time setup: verify Docker availability and pull base images."""
    click.echo("nyuwaymcpsandbox setup is pre-release.")
    click.echo("Required: Docker (Desktop on Windows / native on Linux + macOS).")
    click.echo("Base images: python:3.12-slim, node:20-slim.")
    click.echo("Pull them now with:")
    click.echo("  docker pull python:3.12-slim")
    click.echo("  docker pull node:20-slim")
    raise SystemExit(0)


if __name__ == "__main__":
    cli()
