# nyuwaymcpsandbox

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Open-source behavioral sandbox for Model Context Protocol (MCP) servers.**

Detonate any MCP server in a controlled, instrumented environment. Watch what it actually does at runtime - every network call, file access, environment variable read, subprocess spawn, and tool invocation. Verifiable behavioral evidence, not inferred intent.

> Status: pre-release. v1.0 in active development.

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

**Fast mode** - deterministic harness only. Container detonation, exercise every declared tool with synthetic inputs, capture all behavior. No LLM in the loop. Target: under 2 minutes per server. CI/CD friendly.

**Full mode** - deterministic harness plus a live LLM driver that probes the server with a curated adversarial prompt library. Catches tool poisoning and prompt-injection-triggered behavior that the deterministic harness cannot. Target: under 8 minutes per server.

---

## Quick start

```bash
# Install (coming soon)
pip install nyuwaymcpsandbox

# One-time setup: pull container images
nyuwaymcpsandbox setup

# Fast mode - deterministic, CI-friendly
nyuwaymcpsandbox detonate ./my-server --mode fast

# Full mode with a live LLM driver
nyuwaymcpsandbox detonate ./my-server --mode full --api-key sk-...

# Full mode air-gapped with local Ollama
nyuwaymcpsandbox detonate ./my-server --mode full --llm local

# CI gate
nyuwaymcpsandbox detonate ./server --mode fast --fail-on high
```

---

## What gets captured

| Layer | Events |
|---|---|
| Network | Outbound DNS, TCP/UDP connections, HTTP requests |
| Filesystem | All reads, writes, deletes, permission changes |
| Environment | Every environment variable read |
| Process | Every subprocess invocation |
| MCP protocol | Every tool call: input, output, latency, errors |
| LLM driver | Every prompt and response in Full mode |

---

## Requirements

- Python 3.11+
- Docker (Linux or macOS with Docker Desktop; Windows via WSL2)

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

## Links

- Website: https://nyuway.ai
- Static scanner: https://github.com/Nyuway-Cybersecurity/nyuwaymcpscanner
- Issues: https://github.com/Nyuway-Cybersecurity/nyuwaymcpsandbox/issues
