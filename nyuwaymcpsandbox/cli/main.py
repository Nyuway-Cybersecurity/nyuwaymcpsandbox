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

import shlex

import click

from nyuwaymcpsandbox import __version__
from nyuwaymcpsandbox.drivers.fakes import (
    FakeLlmBackend,
    FakeMcpClient,
    fake_docker_client_factory,
)
from nyuwaymcpsandbox.pipeline import (
    VALID_MCP_TRANSPORTS,
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


def _docker_sdk_for_setup():
    """Return the docker SDK module. Extracted so tests can monkeypatch it."""
    try:
        import docker as _docker  # type: ignore[import-not-found]

        return _docker
    except ImportError:
        return None


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
    "--mcp-transport",
    type=click.Choice(VALID_MCP_TRANSPORTS),
    default="docker",
    show_default=True,
    help="How to talk to the MCP server. 'docker' runs it inside the sandboxed container "
    "via docker exec; 'subprocess' runs it as a host subprocess (no sandbox).",
)
@click.option(
    "--mcp-command",
    default=None,
    help='Command to launch the MCP server, e.g. "python server.py". '
    "Parsed with shell quoting (POSIX rules on Linux/macOS; Windows-aware on Windows). "
    "Use --mcp-arg for Windows paths with backslashes. Required unless --dry-run is set.",
)
@click.option(
    "--mcp-arg",
    "mcp_args",
    multiple=True,
    help="Alternative to --mcp-command: pass each token as a separate flag. "
    "Avoids shell-quoting issues with Windows backslash paths. "
    'Example: --mcp-arg python --mcp-arg "C:\\Users\\me\\server.py"',
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Run the pipeline with in-memory fakes instead of real Docker / MCP / LLM transports. "
    "Useful for verifying CLI plumbing without external dependencies.",
)
def detonate(
    target,
    mode,
    output,
    fail_on,
    api_key,
    llm_model,
    allow_network,
    mcp_transport,
    mcp_command,
    mcp_args,
    dry_run,
):
    """Detonate an MCP server in a sandboxed container and record behavior.

    TARGET may be a local path, github:owner/repo, npm:package, or pypi:package.
    """
    # --mcp-arg tokens take precedence over --mcp-command string. When neither
    # is provided the list is empty and the real transport raises PipelineNotReady.
    #
    # Windows note: shlex.split uses POSIX mode which strips backslashes from
    # native Windows paths (C:\Users\... becomes C:Users\...). Use --mcp-arg
    # to pass each token separately and bypass shell parsing entirely.
    if mcp_args:
        resolved_command = list(mcp_args)
    elif mcp_command:
        resolved_command = shlex.split(mcp_command)
    else:
        resolved_command = []

    config = PipelineConfig(
        target=target,
        mode=mode,
        output=output,
        fail_on=fail_on,
        api_key=api_key,
        llm_model=llm_model,
        allow_network=allow_network,
        mcp_transport=mcp_transport,
        mcp_command=resolved_command,
    )

    deps = PipelineDeps()
    if dry_run:
        # Replace the real transports with in-memory fakes. The docker
        # client is also faked so the orchestrator's secure-defaults
        # code path still exercises, just without talking to a daemon.
        deps.mcp_client_factory = lambda _container, _config, _source: FakeMcpClient()
        deps.llm_backend_factory = lambda _model, _key: FakeLlmBackend()
        deps.docker_client_factory = fake_docker_client_factory
    elif mcp_transport == "subprocess":
        # Subprocess transport means the MCP server runs on the host,
        # not in a container. There's no real container to create, so
        # fake the docker client. The orchestrator's secure-defaults
        # code path still exercises - just without daemon traffic.
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
    # Images required by the sandbox. Pull order: smallest first so a
    # partial run still leaves the most-used images ready.
    images = [
        ("python:3.12-slim", "MCP server sandbox (Python servers)"),
        ("node:20-slim", "MCP server sandbox (Node.js servers)"),
        ("nicolaka/netshoot", "NetworkMonitor DNS-capture sidecar"),
    ]

    # Step 1: verify Docker is reachable before attempting any pulls.
    click.echo("nyuwaymcpsandbox setup")
    click.echo("=" * 40)
    click.echo()
    click.echo("Checking Docker availability...", nl=False)
    try:
        docker_sdk = _docker_sdk_for_setup()
        if docker_sdk is None:
            raise ImportError("docker-py not installed")
        client = docker_sdk.from_env()
        client.ping()
        click.echo(" OK")
    except ImportError as exc:
        click.echo(" FAILED", err=True)
        click.echo(
            "Error: docker-py is not installed. Run: pip install docker", err=True
        )
        raise SystemExit(1) from exc
    except Exception as e:
        click.echo(" FAILED", err=True)
        click.echo(f"Error: could not connect to Docker daemon: {e}", err=True)
        click.echo(
            "Hint: start Docker Desktop (Windows/macOS) or the Docker daemon (Linux).",
            err=True,
        )
        raise SystemExit(1) from e

    # Step 2: pull each image, reporting progress per image.
    click.echo()
    click.echo("Pulling sandbox images (this may take a few minutes on first run)...")
    click.echo()

    failed: list[str] = []
    for image, description in images:
        click.echo(f"  {image}")
        click.echo(f"    {description}")
        click.echo("    Pulling...", nl=False)
        try:
            client.images.pull(image)
            click.echo(" done")
        except Exception as e:
            click.echo(f" FAILED: {e}", err=True)
            failed.append(image)
        click.echo()

    # Step 3: summary.
    if failed:
        click.echo(f"Setup incomplete. Failed to pull: {', '.join(failed)}", err=True)
        click.echo("Check your internet connection and Docker daemon logs.", err=True)
        raise SystemExit(1)

    click.echo("Setup complete. All images are ready.")
    click.echo()
    click.echo("Quick start:")
    click.echo(
        "  nyuwaymcpsandbox detonate . --mcp-transport subprocess"
        ' --mcp-command "python server.py"'
    )
    raise SystemExit(0)


if __name__ == "__main__":
    cli()
