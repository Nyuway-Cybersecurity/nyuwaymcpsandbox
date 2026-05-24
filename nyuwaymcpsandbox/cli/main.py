"""nyuwaymcpsandbox CLI entry point.

Skeleton for v1.0. Commands declared here; implementations land in
subsequent commits as the orchestrator, drivers, and detection engine
come online.
"""

from __future__ import annotations

import click

from nyuwaymcpsandbox import __version__

MODE_CHOICES = ("fast", "full")
OUTPUT_CHOICES = ("timeline", "json", "sarif")
SEVERITY_CHOICES = ("low", "medium", "high", "critical")


@click.group()
@click.version_option(__version__, prog_name="nyuwaymcpsandbox")
def cli():
    """nyuwaymcpsandbox - Behavioral sandbox for MCP servers."""


@cli.command()
@click.argument("target")
@click.option(
    "--mode",
    type=click.Choice(MODE_CHOICES),
    default="fast",
    show_default=True,
    help="Detonation mode. 'fast' = deterministic harness only. 'full' = with LLM driver.",
)
@click.option(
    "--output",
    type=click.Choice(OUTPUT_CHOICES),
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
    default=None,
    help="LLM driver target. 'local' uses local Ollama; otherwise litellm model identifier.",
)
@click.option(
    "--allow-network",
    is_flag=True,
    help="Permit real outbound egress from the sandbox (default: sinkholed).",
)
def detonate(target, mode, output, fail_on, api_key, llm, allow_network):
    """Detonate an MCP server in a sandboxed container and record behavior.

    TARGET may be a local path, github:owner/repo, npm:package, or pypi:package.
    """
    click.echo(
        "nyuwaymcpsandbox is pre-release. The detonate orchestrator is not yet wired.",
        err=True,
    )
    click.echo(f"  target:        {target}", err=True)
    click.echo(f"  mode:          {mode}", err=True)
    click.echo(f"  output:        {output}", err=True)
    click.echo(f"  fail-on:       {fail_on or '(unset)'}", err=True)
    click.echo(f"  llm:           {llm or '(unset)'}", err=True)
    click.echo(f"  api-key:       {'set' if api_key else 'unset'}", err=True)
    click.echo(f"  allow-network: {allow_network}", err=True)
    raise SystemExit(2)


@cli.command()
def setup():
    """One-time setup: pull base container images and verify Docker availability."""
    click.echo(
        "nyuwaymcpsandbox is pre-release. Setup orchestrator is not yet wired.",
        err=True,
    )
    raise SystemExit(2)


if __name__ == "__main__":
    cli()
