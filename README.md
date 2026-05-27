# nyuwaymcpsandbox

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-513%20passing-brightgreen)](#)
[![Rules](https://img.shields.io/badge/detection%20rules-9-blue)](#detection-rules)
[![Status](https://img.shields.io/badge/status-v1.0.0%20stable-brightgreen)](#)

**Open-source behavioral sandbox for Model Context Protocol (MCP) servers.**

Detonate any MCP server in a controlled, instrumented environment. Watch what it actually does at runtime — every network call, file access, environment variable read, subprocess spawn, tool invocation, and timing-based stealth signal. Verifiable behavioral evidence, not inferred intent.

```
$ nyuwaymcpsandbox detonate pypi:mcp-server-git --mcp-command "python -m mcp_server_git --repository ."

Verdict:  LOW  (score 20/100)              Duration: 00:02   Findings: 1
| 00:02 | . | Tool 'git_status' invoked
| 00:02 | X | Tool 'git_commit' invoked   [DETECTION: destructive_tool_invoked]
| 00:02 | X | Tool 'git_reset'  invoked   [DETECTION: destructive_tool_invoked]
```

> **v1.0.0 — first stable release.** Core pipeline working end-to-end on Linux, macOS, and Windows (Docker Desktop + WSL2). **513 unit tests passing**, **9 bundled detection rules**, **14 public MCP servers detonated** across Docker and subprocess modes. See the [GitHub releases page](https://github.com/Nyuway-Cybersecurity/nyuwaymcpsandbox/releases) for release notes.

---

## Why a behavioral sandbox?

Static scanners read source code. They catch what code _looks like_, not what code _does_. A whole class of malicious MCP behavior is invisible to static analysis:

- Runtime-triggered exfiltration that only fires on specific inputs
- HTTPS-encrypted data theft to endpoints computed at runtime
- Environment variable harvesting hidden inside otherwise benign-looking handlers
- Subprocess hijacking with dynamically constructed commands
- Tool poisoning that only manifests when a real LLM drives the server
- Stealthy beacon-style startup behaviour that hides behind protocol silence
- Destructive tool surfaces (`exec_in_pod`, `git_reset`, `kubectl_delete`) that look innocent in the source

nyuwaymcpsandbox runs the server in isolation and **observes behaviour directly**. The output is not inference — it is evidence captured from the running process.

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

| Mode | What runs | When to use |
|---|---|---|
| **`--mode fast`** | Deterministic harness only — container detonation, exercise every declared tool with synthesised inputs, capture all behaviour | CI pipelines, pre-deploy gates, no LLM cost |
| **`--mode full`** | `fast` + a live LLM driver that probes the server with a curated adversarial prompt library | Tool-poisoning and prompt-injection-triggered behaviour the deterministic harness alone cannot surface |

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

# Full mode inside the sandbox, with an LLM driver (Node.js server)
nyuwaymcpsandbox detonate npm:@modelcontextprotocol/server-everything \
  --mode full \
  --mcp-transport docker \
  --mcp-command "node dist/index.js" \
  --llm groq/llama-3.3-70b-versatile

# Full mode — browser-based MCP server (needs a playwright-capable image)
nyuwaymcpsandbox detonate npm:@executeautomation/playwright-mcp-server \
  --mode full \
  --mcp-transport docker \
  --mcp-command "node dist/index.js" \
  --container-image "mcr.microsoft.com/playwright:v1.57.0-noble" \
  --llm groq/llama-3.3-70b-versatile

# Full mode with Anthropic LLM
nyuwaymcpsandbox detonate github:owner/repo \
  --mode full \
  --mcp-transport docker \
  --mcp-command "python server.py" \
  --llm claude-sonnet-4-5 \
  --api-key $ANTHROPIC_API_KEY

# Air-gapped: local Ollama for the LLM driver
nyuwaymcpsandbox detonate ./my-server --mode full --llm local

# CI gate
nyuwaymcpsandbox detonate ./server --mode fast --fail-on high --output sarif > results.sarif
```

---

## See it in action

Real findings from public MCP servers run through the sandbox. Both runs use `--mode fast` (no LLM), so the only signal is what the deterministic harness observed.

### Example 1 — `mcp-server-git` flags state mutation

Running the official `pypi:mcp-server-git` server against this repository:

```
+----------------------------- nyuwaymcpsandbox - Behavioral Analysis ----------+
|   Target:  pypi:mcp-server-git                                                |
|     Mode:  fast                                                               |
|  Verdict:  LOW  (score 20/100)                                                |
| Duration:  00:02                                                              |
| Findings:  1                                                                  |
+-------------------------------------------------------------------------------+
                               Behavioral Timeline
+-------------------------------------------------------------------------------+
|  Time |   | Event                                                             |
|-------+---+-------------------------------------------------------------------|
| 00:00 | . | Container started, MCP server listening                           |
| 00:02 | . | MCP server listed tools                                           |
| 00:02 | . | Tool 'git_status' invoked                                         |
| 00:02 | . | Tool 'git_diff'   invoked                                         |
| 00:02 | X | Tool 'git_commit' invoked   [DETECTION: destructive_tool_invoked] |
| 00:02 | . | Tool 'git_add'    invoked                                         |
| 00:02 | X | Tool 'git_reset'  invoked   [DETECTION: destructive_tool_invoked] |
| 00:02 | . | Tool 'git_log'    invoked                                         |
| 00:02 | . | Tool 'git_branch' invoked                                         |
| 00:02 | . | Container stopped                                                 |
+-------------------------------------------------------------------------------+
| X | HIGH | destructive_tool_invoked | Destructive tool invoked by harness    |
+-------------------------------------------------------------------------------+
```

The server exposes 13 git tools. 11 are read-only and pass clean. `git_commit` and `git_reset` mutate repository state — the sandbox flags them so an operator can decide whether that capability is acceptable for the deployment context (a read-only RAG agent should never need write tools).

### Example 2 — `mcp-server-kubernetes` reveals stealth startup

The Kubernetes MCP server spent **106 seconds silently retrying connections** to a K8s API server (sinkholed by the sandbox) before answering `tools/list`. The sandbox catches both the protocol-level stealth and the destructive tool surface:

```
+----------------------------- nyuwaymcpsandbox - Behavioral Analysis ----------+
|   Target:  mcp-server-kubernetes                                              |
|     Mode:  fast                                                               |
|  Verdict:  LOW  (score 35/100)                                                |
| Duration:  01:57                                                              |
| Findings:  2                                                                  |
+-------------------------------------------------------------------------------+
| 00:00 | . | Container started                                                 |
| 01:46 | . | MCP server listed tools                                           |
| 01:46 | ! | Server delayed initialisation: 106.5s before tools/list           |
|       |   |    [DETECTION: pre_tool_network_activity]                         |
| 01:46 | X | Tool 'kubectl_apply'  invoked   [DETECTION: destructive_tool_…]   |
| 01:46 | X | Tool 'kubectl_delete' invoked   [DETECTION: destructive_tool_…]   |
| 01:47 | X | Tool 'exec_in_pod'    invoked   [DETECTION: destructive_tool_…]   |
| ...
+-------------------------------------------------------------------------------+
| X | HIGH    | destructive_tool_invoked  | (×15 destructive tools)             |
| ! | MEDIUM  | pre_tool_network_activity | Server delayed first MCP response   |
+-------------------------------------------------------------------------------+
```

The 106-second silent window is the protocol-level analogue of a C2 implant: long initial silence, then ordinary-looking traffic. In static analysis this is invisible — only a runtime sandbox surfaces it.

### Example 3 — `mcp-server-time` (benign baseline)

A boring server should look boring. Running `pypi:mcp-server-time`:

```
+----------------------------- nyuwaymcpsandbox - Behavioral Analysis ----------+
|   Target:  pypi:mcp-server-time                                               |
|  Verdict:  PASS  (score 0/100)                                                |
| Findings:  0                                                                  |
+-------------------------------------------------------------------------------+
| 00:00 | . | Container started                                                 |
| 00:01 | . | MCP server listed tools                                           |
| 00:01 | . | Tool 'get_current_time' invoked                                   |
| 00:01 | . | Tool 'convert_time'     invoked                                   |
| 00:02 | . | Container stopped                                                 |
+-------------------------------------------------------------------------------+
| Deploy. No suspicious behaviour observed during detonation.                   |
+-------------------------------------------------------------------------------+
```

No findings, no false positives. The same rules that flagged `mcp-server-git` and `mcp-server-kubernetes` stay silent here.

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

### Key flags

| Flag | Default | Purpose |
|---|---|---|
| `--mcp-command` | _(required for docker transport)_ | Command run inside the container via `docker exec` |
| `--mcp-arg` | — | Repeatable; passes args without shell parsing (safe for Windows paths) |
| `--container-image` | auto-detected | Override the base image. Use for servers that need a non-default runtime (e.g. browser servers). Auto-wires browser-safe container settings. |
| `--allow-network` | off | Grant real outbound egress (off by default; everything is sinkholed) |
| `--mode fast\|full` | `fast` | `fast` = deterministic harness only; `full` = adds LLM adversarial driver |
| `--llm <model>` | _(required for full mode)_ | Any litellm model identifier, or `local` for Ollama |
| `--fail-on low\|medium\|high\|critical` | off | Non-zero exit when any finding meets or exceeds the threshold |
| `--output timeline\|json\|sarif` | `timeline` | Output format |
| `--dry-run` | off | Runs the pipeline with in-memory fakes — no Docker, MCP, or LLM needed |

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

All capture monitors run in parallel during the detonation. Each implements the same `Monitor` Protocol so the wiring is uniform.

| Layer | Mechanism | What lands on the timeline |
|---|---|---|
| Container | `docker container.run` lifecycle | `container.started`, `container.stopped`, `container.error` |
| MCP protocol | Real stdio JSON-RPC client | `mcp.tool_list`, `mcp.tool_invocation` (with `duration_seconds`, result summary, error) |
| MCP timing signals | Harness-derived from tool-call latency | `mcp.delayed_initialization` (server stalled >=60s before `tools/list`), `mcp.slow_tool_response` (single call >=30s) |
| Filesystem | watchdog (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows) | `filesystem.write`, `filesystem.delete` |
| Process | `docker container.top()` polling | `process.spawn` (with argv + ppid), `process.exit` |
| Network (DNS) | `tcpdump` sidecar in the target's network namespace | `network.dns_lookup` |
| Environment | `sitecustomize.py` shim + `docker exec tail` (Python servers only in v1) | `environment.read` |
| LLM driver (Full mode only) | litellm + adversarial prompt library | `llm.prompt_sent`, `llm.response_received` |

Every event is causally linked via `triggered_by` so detection rules can express patterns like "outbound DNS lookup triggered by an MCP tool invocation triggered by an adversarial prompt."

---

## Detection rules

9 bundled rules ship in `nyuwaymcpsandbox/detection/builtin/`:

| Rule | Severity | Fires on |
|---|---|---|
| `shell_exec_in_tool` | HIGH | Subprocess spawn caused by an MCP tool invocation |
| `outbound_network_from_tool` | HIGH | Any outbound network event caused by an MCP tool invocation |
| `sensitive_file_read` | HIGH | MCP tool invocation whose name or arguments reference `/etc/passwd`, `/etc/shadow`, SSH keys, `~/.aws/credentials`, `~/.ssh/`, Windows credential paths |
| `destructive_tool_invoked` | HIGH | MCP tool whose name matches a destructive verb (`git_commit`, `git_reset`, `kubectl_delete`, `kubectl_apply`, helm chart lifecycle, `exec_in_pod`, `drop_table`, `force_*`, `purge_*`, etc.) |
| `credential_env_access` | MEDIUM | Read of an env var matching AWS_/AZURE_/GCP_/GITHUB_/OPENAI_/ANTHROPIC_/SLACK_/`*_SECRET`/`*_TOKEN`/`*_API_KEY` |
| `suspicious_dns_tld` | MEDIUM | DNS lookup for a domain on `.tk`/`.gq`/`.ml`/`.cf`/`.xyz`/`.top`/`.click`/`.loan`/`.work` |
| `file_write_outside_workdir` | MEDIUM | Write to `/etc`/`/usr`/`/var`/`/root`/`/home`/`/Users`/`/private`/`/Library`/Windows system paths caused by an MCP tool |
| `pre_tool_network_activity` | MEDIUM | Server takes 60+ seconds to answer `tools/list` after the container is ready (suggests background network retries or beaconing during the silent window) |
| `slow_tool_response` | LOW | A single MCP tool call takes 30+ seconds to return (reliability + DoS-vector signal) |

Rules are pure YAML, schema-validated, with both exact and regex payload matching plus dotted payload key paths. The two timing-based rules (`pre_tool_network_activity`, `slow_tool_response`) consume derived events the deterministic harness emits when it measures startup latency and per-call duration. See [`docs/detection-rules.md`](docs/detection-rules.md) (TBD) for the schema, or [`detection/rules.py`](nyuwaymcpsandbox/detection/rules.py) for the docstring.

---

## What this catches — and what it does not

We are deliberate about scope. A behavioral sandbox is one layer in a defence-in-depth strategy, not a silver bullet. This is what v1.0 covers honestly:

### What v1.0 catches

- **Subprocess execution** during tool invocations (`shell_exec_in_tool`)
- **Outbound network calls** triggered by tools — DNS, TCP, HTTP, HTTPS — including to suspicious TLDs (`outbound_network_from_tool`, `suspicious_dns_tld`)
- **Credential env-var reads** by Python MCP servers — AWS, Azure, GCP, GitHub, OpenAI, Anthropic, Slack, generic `*_SECRET`/`*_TOKEN`/`*_API_KEY` (`credential_env_access`)
- **Sensitive file reads** when the tool name and arguments point at `/etc/passwd`, SSH keys, AWS credentials, Windows credential paths (`sensitive_file_read`)
- **System path writes** outside the working directory (`file_write_outside_workdir`)
- **Destructive tool surfaces** — git mutations, kubectl deletes/applies, helm chart lifecycle, `exec_in_pod`, database drops, `force_*`/`purge_*` verbs (`destructive_tool_invoked`)
- **Stealth startup behaviour** — server takes 60+ seconds to answer `tools/list`, typically because it is retrying network connections you cannot see (`pre_tool_network_activity`)
- **Hanging tool calls** — single tool invocation takes 30+ seconds (`slow_tool_response`)
- **Tool-poisoning behavior under live LLM driving** (Full mode only) via an adversarial prompt library

### What v1.0 does NOT catch (yet)

- **Env-var reads by non-Python servers.** The `sitecustomize.py` shim only attaches to Python. Node, Go, and other-language servers bypass `credential_env_access`. Fix in v1.1: LD_PRELOAD-based `getenv` hook.
- **Filesystem read events.** watchdog does not surface `IN_ACCESS` uniformly across platforms; only `write` and `delete` are captured today. A malicious server reading credentials but never writing or exfiltrating during the scan window is invisible. Fix in v1.1: in-container inotify watcher.
- **In-container overlay writes.** The filesystem monitor watches the bind-mounted source on the host. Writes to the container's anonymous overlay (tmpfs, runtime state) are not seen.
- **Full packet capture.** The current sidecar only logs DNS. HTTPS host headers, HTTP request lines, and connection metadata require the v1.1 NFQUEUE + scapy work.
- **Multi-turn attacks.** The LLM driver is single-turn. Attacks that require a multi-turn conversation to manifest are out of scope until v2.0.
- **Static code analysis.** This tool runs the server. To inspect the source without execution, use [nyuwaymcpscanner](https://github.com/Nyuway-Cybersecurity/nyuwaymcpscanner) — the static counterpart.
- **Production runtime governance.** The sandbox is a pre-deployment gate. Continuous behavioural enforcement in production is the A2SP product (separate codebase).
- **Python MCP servers in Docker mode.** Until v1.1 ships a PyPI install layer, Python servers run via subprocess transport (no NetworkMonitor / EnvironmentMonitor / FilesystemMonitor coverage). Node servers, browser-capable servers, and `--container-image` overrides work in full Docker mode today.

A PASS verdict means **no rule fired against the captured timeline**. It does not mean the server is safe for every deployment context — only that, within the limits above, no malicious behaviour was observed.

What's planned next is summarised in the [GitHub releases page](https://github.com/Nyuway-Cybersecurity/nyuwaymcpsandbox/releases) and tracked via GitHub issues.

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

**Browser-capable containers** (`--container-image`): Chrome's startup process is incompatible with `read_only=True` and the default seccomp profile. When `--container-image` is set, the sandbox automatically adjusts to `read_only=False`, `seccomp=unconfined`, and `cap_add=SYS_PTRACE` while keeping network sinkholed, resource-capped, and destroyed on exit. The Docker container remains the outer isolation boundary.

---

## Requirements

- Python 3.11+
- Docker (Linux or macOS with Docker Desktop; Windows via WSL2). Optional - the `subprocess` MCP transport works without Docker.
- An LLM API key (Full mode only) - any provider [litellm](https://docs.litellm.ai/) supports, or local Ollama for air-gapped runs.

---

## Contributing

This is an open security tool — community contributions move the threat coverage forward.

- **New detection rules** — drop a YAML file into `nyuwaymcpsandbox/detection/builtin/`, add a unit test in `tests/test_detection_engine.py`, open a PR. See `detection/rules.py` for the schema.
- **New adversarial prompts** — extend `nyuwaymcpsandbox/drivers/prompts/adversarial_library.yaml`. We currently cover ~2 of ~12 documented MCP/OWASP-Agentic attack vectors; PRs welcome.
- **Real-world server reports** — file an issue with the server target, the detonation command, and the full timeline output. Findings against real public servers are how we discover new gaps (Phase 6 + Phase 7 in the activity log are entirely community-style testing turned into rules).
- **Bug reports** — please include the rendered timeline (`--output timeline`) and the raw JSON (`--output json`).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide (in progress).

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

## Links

- Website: https://nyuway.ai
- Static scanner: https://github.com/Nyuway-Cybersecurity/nyuwaymcpscanner
- Issues: https://github.com/Nyuway-Cybersecurity/nyuwaymcpsandbox/issues
- Releases: https://github.com/Nyuway-Cybersecurity/nyuwaymcpsandbox/releases
