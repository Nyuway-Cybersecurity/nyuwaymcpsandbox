# nyuwaymcpsandbox

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Open-source behavioral sandbox for Model Context Protocol (MCP) servers.**

Detonate any MCP server in a controlled, instrumented environment. Watch what it actually does at runtime - every network call, file access, environment variable read, subprocess spawn, and tool invocation. Verifiable behavioral evidence, not inferred intent.

> Status: pre-release. v1.0 in active development - core working end-to-end on Linux + macOS + Windows. See [CHANGELOG.md](CHANGELOG.md) for what shipped, [ROADMAP.md](ROADMAP.md) for what's deferred.

---

## Why a behavioral sandbox?

Static scanners read source code. They catch what code looks like, not what code does. A class of malicious MCP behavior exists outside what static analysis can see:

- Runtime-triggered exfiltration that only fires on specific inputs
- HTTPS-encrypted data theft to endpoints computed at runtime
- Environment variable harvesting hidden inside otherwise benign-looking handlers
- Subprocess hijacking with dynamically constructed commands
- Tool poisoning that only manifests when a real LLM drives the server

nyuwaymcpsandbox observes behavior directly. The output is not inference - it's evidence.

---

## How it fits in

nyuwaymcpsandbox is the middle layer of the Nyuway MCP security trilogy:

| Phase | Product | Question |
|---|---|---|
| Pre-deployment static | [nyuwaymcpscanner](https://github.com/Nyuway-Cybersecurity/nyuwaymcpscanner) | What does the code say this server does? |
| Pre-deployment dynamic | **nyuwaymcpsandbox** | What does this server actually do when it runs? |
| Production runtime | A2SP | How do I govern its behavior continuously in production? |

---

## Two scan modes

**Fast mode** - deterministic harness only. Container detonation, exercise every declared tool with synthetic inputs, capture all behavior. No LLM in the loop.

**Full mode** - deterministic harness plus a live LLM driver that probes the server with a curated adversarial prompt library. Catches tool poisoning and prompt-injection-triggered behavior that the deterministic harness cannot.

---

## Quick start

```bash
pip install nyuwaymcpsandbox

# One-time setup: verify Docker, pull base images
nyuwaymcpsandbox setup

# Verify CLI plumbing without Docker (uses in-memory fakes)
nyuwaymcpsandbox detonate ./my-server --dry-run

# Fast mode against a real local Python MCP server (no Docker, no sandbox)
nyuwaymcpsandbox detonate ./my-server \
  --mcp-transport subprocess \
  --mcp-command "python server.py"

# Full mode inside the sandbox, with an LLM driver
nyuwaymcpsandbox detonate github:owner/repo \
  --mode full \
  --mcp-transport docker \
  --mcp-command "env PYTHONPATH=/nyuway_runtime python server.py" \
  --llm claude-sonnet-4-5 \
  --api-key $ANTHROPIC_API_KEY

# Air-gapped: local Ollama for the LLM driver
nyuwaymcpsandbox detonate ./my-server --mode full --llm local

# CI gate
nyuwaymcpsandbox detonate ./server --mode fast --fail-on high --output sarif > results.sarif
```

---

## Targets

Pass any of these as the `TARGET` argument:

| Form | Source |
|---|---|
| `./path/to/server` | local directory or file |
| `github:owner/repo` (optional `@ref`) | GitHub tarball |
| `npm:package` (optional `@version`) | npm registry |
| `pypi:package` (optional `@version`) | PyPI (sdist preferred, wheel fallback) |

---

## MCP transports

| Transport | When to use | Sandbox? |
|---|---|---|
| `--mcp-transport docker` (default) | Production: real isolation via `docker exec` inside the orchestrator's hardened container | yes |
| `--mcp-transport subprocess` | Dev / protocol validation: server runs as a host subprocess (the same pattern the official MCP SDK uses) | no |

Both transports speak the same JSON-RPC 2.0 over stdio. Both go through the same downstream pipeline (capture monitors, detection rules, verdict, output).

---

## LLM backend (Full mode)

`--llm` accepts any [litellm](https://docs.litellm.ai/) model identifier. Examples:

| `--llm` value | Routes to |
|---|---|
| `claude-sonnet-4-5` | Anthropic (needs `ANTHROPIC_API_KEY`) |
| `openai/gpt-4o` | OpenAI (needs `OPENAI_API_KEY`) |
| `ollama/llama3` | Local Ollama daemon |
| `local` | Alias for `ollama/llama3` (air-gapped default) |

The API key is picked up from the provider's standard env var unless `--api-key` is explicitly passed.

---

## What gets captured

All four capture monitors run in parallel during the detonation. Each implements the same `Monitor` Protocol so the wiring is uniform.

| Layer | Mechanism | What lands on the timeline |
|---|---|---|
| Container | `docker container.run` lifecycle | `container.started`, `container.stopped`, `container.error` |
| MCP protocol | Real stdio JSON-RPC client | `mcp.tool_list`, `mcp.tool_invocation` (with result summary / error) |
| Filesystem | watchdog (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows) | `filesystem.write`, `filesystem.delete` |
| Process | `docker container.top()` polling | `process.spawn` (with argv + ppid), `process.exit` |
| Network (DNS) | `tcpdump` sidecar in the target's network namespace | `network.dns_lookup` |
| Environment | `sitecustomize.py` shim + `docker exec tail` (Python servers only in v1) | `environment.read` |
| LLM driver (Full mode only) | litellm + adversarial prompt library | `llm.prompt_sent`, `llm.response_received` |

Every event is causally linked via `triggered_by` so detection rules can express patterns like "outbound DNS lookup triggered by an MCP tool invocation triggered by an adversarial prompt."

---

## Detection rules

5 bundled rules ship in `nyuwaymcpsandbox/detection/builtin/`:

| Rule | Severity | Fires on |
|---|---|---|
| `shell_exec_in_tool` | HIGH | Subprocess spawn caused by an MCP tool invocation |
| `outbound_network_from_tool` | HIGH | Any outbound network event caused by an MCP tool invocation |
| `credential_env_access` | MEDIUM | Read of an env var matching AWS_/AZURE_/GCP_/GITHUB_/OPENAI_/ANTHROPIC_/SLACK_/`*_SECRET`/`*_TOKEN`/`*_API_KEY` |
| `suspicious_dns_tld` | MEDIUM | DNS lookup for a domain on `.tk`/`.gq`/`.ml`/`.cf`/`.xyz`/`.top`/`.click`/`.loan`/`.work` |
| `file_write_outside_workdir` | MEDIUM | Write to `/etc`/`/usr`/`/var`/`/root`/`/home`/`/Users`/`/private`/`/Library`/Windows system paths caused by an MCP tool |

Rules are pure YAML, schema-validated, with both exact and regex payload matching plus dotted payload key paths. See [`docs/detection-rules.md`](docs/detection-rules.md) (TBD) for the schema, or [`detection/rules.py`](nyuwaymcpsandbox/detection/rules.py) for the docstring.

---

## Verdicts

Score = `min(100, max(sum_of_finding_weights, severity_floor))`. A single CRITICAL finding raises the score to at least 60 (HIGH minimum).

| Verdict | Score range | Action |
|---|---|---|
| PASS | 0-19 | Deploy. No suspicious behaviour. |
| LOW | 20-39 | Deploy with monitoring. |
| MEDIUM | 40-59 | Review before deployment. |
| HIGH | 60-79 | Block deployment. |
| CRITICAL | 80-100 | Do not deploy. |

---

## Output formats

```bash
--output timeline   # Rich terminal view (default, ASCII-safe for cp1252 consoles)
--output json       # Stable JSON schema for scripting / dashboards
--output sarif      # SARIF 2.1.0 for GitHub Advanced Security / VS Code Problems / any SARIF-aware CI
```

`--fail-on low|medium|high|critical` returns a non-zero exit code when any finding meets or exceeds the threshold - drop-in for CI pipelines.

---

## Architecture

```
TARGET
  └─ source resolver         (local / github: / npm: / pypi:)
       └─ Docker orchestrator   (secure-by-default container)
            └─ monitor session   (filesystem / process / network / env)
                 └─ MCP client    (stdio over docker exec or subprocess)
                      ├─ deterministic harness   (probe every tool)
                      └─ LLM driver              (Full mode only)
                 └─ detection engine            (YAML rules over timeline)
                      └─ verdict + renderer     (timeline / JSON / SARIF)
```

Every layer is an injection point - tests fake any boundary, `--dry-run` fakes the external ones (Docker, MCP, LLM) to exercise the rest of the pipeline.

---

## Security defaults

Every detonation runs the target in a container with:

- `network_mode='none'` (sinkholed; only `--allow-network` opts in to real egress)
- `read_only=True` root filesystem
- `cap_drop=['ALL']` + `security_opt=['no-new-privileges:true']`
- Resource caps: memory, CPU, pid count
- Source mounted read-only at `/src`
- Full destruction on session exit; nothing persists

---

## Requirements

- Python 3.11+
- Docker (Linux or macOS with Docker Desktop; Windows via WSL2). Optional - the `subprocess` MCP transport works without Docker.
- An LLM API key (Full mode only) - any provider [litellm](https://docs.litellm.ai/) supports, or local Ollama for air-gapped runs.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

## Links

- Website: https://nyuway.ai
- Static scanner: https://github.com/Nyuway-Cybersecurity/nyuwaymcpscanner
- Issues: https://github.com/Nyuway-Cybersecurity/nyuwaymcpsandbox/issues
- Roadmap: [ROADMAP.md](ROADMAP.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
