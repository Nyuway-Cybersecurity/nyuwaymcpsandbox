"""Run the v1.1 research campaign against a curated list of public MCP servers.

For each server in ``server_list.yaml``, this script:

  1. Invokes ``nyuwaymcpsandbox detonate ...`` with the right transport,
     command, environment file, and LLM driver
  2. Parses the JSON report from stdout
  3. Saves the raw per-server report to ``--output-dir/<server-id>.json``
  4. Aggregates: verdict, findings, tool count, duration, error
  5. Writes a single ``--output-dir/campaign_summary.json`` that the
     analysis step can pivot from

Usage:
    python tools/research_campaign.py \\
        --server-list tools/server_list.yaml \\
        --env-file tools/dummy-creds-template.env \\
        --output-dir campaign_results/ \\
        --llm groq/llama-3.3-70b-versatile

Resumable: re-running skips any server whose per-server report already
exists. Delete the file to force re-detonation of one server.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# yaml is not a runtime dependency of the package - we pull it from the
# dev extras (pyyaml). If missing, fall back to a tiny built-in loader.
try:
    import yaml  # type: ignore[import-not-found]

    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False


def load_server_list(path: Path) -> list[dict]:
    """Load the server list. Each entry has: id, source, transport, command, mode."""
    text = path.read_text(encoding="utf-8")
    if _HAVE_YAML:
        data = yaml.safe_load(text)
    else:
        # Minimal fallback parser. Not robust; tells the user to install pyyaml.
        raise RuntimeError(
            "pyyaml is required to parse the server list. "
            "Install with: pip install pyyaml"
        )
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a top-level YAML list of server entries.")
    return data


def build_command(entry: dict, args: argparse.Namespace) -> list[str]:
    """Translate a server-list entry + CLI args into a detonate invocation."""
    cmd = [
        "nyuwaymcpsandbox",
        "detonate",
        entry["source"],
        "--mcp-transport",
        entry.get("transport", "docker"),
        "--mode",
        entry.get("mode", "full"),
        "--output",
        "json",
    ]
    # --mcp-arg tokens (list) vs --mcp-command (string).
    if "mcp_args" in entry:
        for token in entry["mcp_args"]:
            cmd.extend(["--mcp-arg", token])
    elif "mcp_command" in entry:
        cmd.extend(["--mcp-command", entry["mcp_command"]])

    if entry.get("container_image"):
        cmd.extend(["--container-image", entry["container_image"]])

    if args.env_file and entry.get("inject_credentials", True):
        cmd.extend(["--env-file", str(args.env_file)])

    if entry.get("mode", "full") == "full":
        if entry.get("llm") or args.llm:
            cmd.extend(["--llm", entry.get("llm") or args.llm])
        if entry.get("api_key_env"):
            key = os.environ.get(entry["api_key_env"])
            if key:
                cmd.extend(["--api-key", key])
        elif args.api_key:
            cmd.extend(["--api-key", args.api_key])

    if entry.get("allow_network"):
        cmd.append("--allow-network")

    return cmd


def detonate_one(entry: dict, args: argparse.Namespace) -> dict:
    """Run one server through the sandbox; return a summary dict."""
    sid = entry["id"]
    cmd = build_command(entry, args)
    started = time.monotonic()
    started_iso = datetime.now(UTC).isoformat(timespec="seconds")

    print(f"[{sid}] starting: {' '.join(cmd)}", flush=True)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=entry.get("timeout", args.per_server_timeout),
            check=False,
        )
        duration = time.monotonic() - started
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started
        print(f"[{sid}] TIMEOUT after {duration:.1f}s", flush=True)
        return {
            "id": sid,
            "source": entry["source"],
            "started_at": started_iso,
            "duration_seconds": round(duration, 1),
            "status": "timeout",
            "verdict": None,
            "score": None,
            "findings": [],
            "tool_count": 0,
            "exit_code": None,
            "error": f"timeout after {entry.get('timeout', args.per_server_timeout)}s",
            "raw_stdout_first_500": (exc.stdout or "")[:500] if isinstance(exc.stdout, str) else "",
            "raw_stderr_first_500": (exc.stderr or "")[:500] if isinstance(exc.stderr, str) else "",
        }

    if proc.returncode not in (0, 1):  # 0=clean, 1=findings-met-threshold
        print(f"[{sid}] FAILED (exit {proc.returncode}) in {duration:.1f}s", flush=True)
        return {
            "id": sid,
            "source": entry["source"],
            "started_at": started_iso,
            "duration_seconds": round(duration, 1),
            "status": "error",
            "verdict": None,
            "score": None,
            "findings": [],
            "tool_count": 0,
            "exit_code": proc.returncode,
            "error": (proc.stderr or "").strip()[:500] or "no stderr",
            "raw_stdout_first_500": (proc.stdout or "")[:500],
        }

    # Parse the JSON report. Skip any leading non-JSON lines (litellm
    # sometimes emits warnings to stdout on import).
    try:
        idx = proc.stdout.index("{")
        report = json.loads(proc.stdout[idx:])
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"[{sid}] JSON parse failed: {exc}", flush=True)
        return {
            "id": sid,
            "source": entry["source"],
            "started_at": started_iso,
            "duration_seconds": round(duration, 1),
            "status": "parse_error",
            "verdict": None,
            "score": None,
            "findings": [],
            "tool_count": 0,
            "exit_code": proc.returncode,
            "error": str(exc),
            "raw_stdout_first_500": (proc.stdout or "")[:500],
        }

    # Persist the full per-server report for downstream analysis.
    per_server_path = args.output_dir / f"{sid}.json"
    per_server_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    findings = report.get("findings", [])
    verdict_block = report.get("verdict", {})
    tools_evt = next(
        (e for e in report.get("timeline", {}).get("events", []) if e["type"] == "mcp.tool_list"),
        None,
    )
    tool_count = (
        len(tools_evt["payload"].get("tools", [])) if tools_evt and "payload" in tools_evt else 0
    )

    summary = {
        "id": sid,
        "source": entry["source"],
        "started_at": started_iso,
        "duration_seconds": round(duration, 1),
        "status": "ok",
        "verdict": verdict_block.get("tier"),
        "score": verdict_block.get("score"),
        "findings": [
            {
                "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "title": f.get("title"),
                "match_count": len(f.get("matched_event_ids", [])),
            }
            for f in findings
        ],
        "tool_count": tool_count,
        "exit_code": proc.returncode,
        "error": None,
    }
    print(
        f"[{sid}] {summary['verdict']} (score {summary['score']}, "
        f"{len(findings)} findings, {tool_count} tools) in {duration:.1f}s",
        flush=True,
    )
    return summary


def run_campaign(args: argparse.Namespace) -> None:
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.output_dir / "campaign_summary.json"
    server_list = load_server_list(args.server_list)
    print(f"Loaded {len(server_list)} servers from {args.server_list}", flush=True)

    # Resume: load any existing summary so we can skip already-done servers.
    existing: dict[str, dict] = {}
    if summary_path.exists() and args.resume:
        try:
            existing = {
                e["id"]: e for e in json.loads(summary_path.read_text(encoding="utf-8"))["servers"]
            }
        except (OSError, json.JSONDecodeError, KeyError):
            existing = {}

    results: list[dict] = []
    for entry in server_list:
        sid = entry["id"]
        if args.resume and sid in existing and existing[sid].get("status") == "ok":
            print(f"[{sid}] skipping (already done; --no-resume to re-run)", flush=True)
            results.append(existing[sid])
            continue
        if args.only and sid not in args.only:
            continue
        try:
            results.append(detonate_one(entry, args))
        except KeyboardInterrupt:
            print("\nInterrupted. Saving partial results...", flush=True)
            break
        except Exception as exc:  # noqa: BLE001
            print(f"[{sid}] UNEXPECTED ERROR: {exc}", flush=True)
            results.append(
                {
                    "id": sid,
                    "source": entry.get("source", "?"),
                    "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
                    "duration_seconds": 0.0,
                    "status": "harness_error",
                    "verdict": None,
                    "score": None,
                    "findings": [],
                    "tool_count": 0,
                    "exit_code": None,
                    "error": str(exc),
                }
            )

        # Flush summary after every server so the campaign is robust to
        # interruptions (laptop sleep, etc.).
        summary_path.write_text(
            json.dumps(
                {
                    "campaign_run_at": datetime.now(UTC).isoformat(timespec="seconds"),
                    "total_servers": len(server_list),
                    "completed": len(results),
                    "servers": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    # Final aggregate stats.
    counts = {"PASS": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "ERROR": 0}
    for r in results:
        v = r.get("verdict") or "ERROR"
        counts[v] = counts.get(v, 0) + 1
    print("\n=== Campaign complete ===")
    for tier, n in counts.items():
        print(f"  {tier:9s} {n}")
    print(f"\nSummary written to: {summary_path}")
    print(f"Per-server reports in: {args.output_dir}/")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server-list", type=Path, required=True)
    p.add_argument("--env-file", type=Path, default=None)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--llm", default="groq/llama-3.3-70b-versatile")
    p.add_argument("--api-key", default=os.environ.get("NYUWAY_LLM_API_KEY"))
    p.add_argument(
        "--per-server-timeout",
        type=int,
        default=600,
        help="Max seconds per server before we kill the detonation (default: 600).",
    )
    p.add_argument(
        "--only",
        nargs="+",
        help="Only run these server IDs (space-separated). Useful for re-running a single server.",
    )
    p.add_argument(
        "--no-resume",
        action="store_false",
        dest="resume",
        help="Don't skip servers already in campaign_summary.json. Default is to resume.",
    )
    args = p.parse_args()
    try:
        run_campaign(args)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
