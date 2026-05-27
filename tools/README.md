# Research campaign tools

These files run the v1.1 real-world FP tuning campaign described in
`ROADMAP_internal.md` (Phase 2). They live in `tools/` so they ship
with the source distribution but are not imported by the runtime
package.

## Files

| File | Purpose |
|---|---|
| `dummy-creds-template.env` | Shape-valid-but-fake credentials for ~20 public MCP servers. Every value is fake. Letting the server *initialise* with these means we can observe what it tries to do (network calls, file reads, etc.) instead of crashing at startup. |
| `server_list.yaml` | 30-server curated list: 10 official + 15 community npm + 5 community PyPI. |
| `research_campaign.py` | Runner. Detonates each server, captures the JSON report, aggregates into a summary. Resumable. |

## Run the campaign

Prerequisites:

```bash
# One-time
pip install nyuwaymcpsandbox pyyaml
nyuwaymcpsandbox setup  # pulls python:3.12-slim, node:20-slim, nicolaka/netshoot
```

Set the Groq API key (or any litellm-supported provider):

```bash
export NYUWAY_LLM_API_KEY=gsk_...
```

Then:

```bash
python tools/research_campaign.py \
    --server-list tools/server_list.yaml \
    --env-file   tools/dummy-creds-template.env \
    --output-dir campaign_results/ \
    --llm groq/llama-3.3-70b-versatile
```

The script writes:

- `campaign_results/<server-id>.json` (full per-server report)
- `campaign_results/campaign_summary.json` (single aggregate file)

It is **resumable**: re-running skips any server already in the
summary with `status == "ok"`. To re-run one server, pass
`--only <id>` or delete its per-server JSON.

## Interpreting the results

`campaign_summary.json` has one entry per server with:

```json
{
  "id": "mcp-server-kubernetes",
  "verdict": "LOW",
  "score": 35,
  "findings": [
    {"rule_id": "destructive_tool_invoked", "severity": "high", "match_count": 15},
    {"rule_id": "pre_tool_network_activity", "severity": "medium", "match_count": 1}
  ],
  "tool_count": 25,
  "duration_seconds": 178.3,
  "status": "ok"
}
```

Aggregate analysis (which rules fire most often, per-tier counts, etc.)
is done in a follow-up notebook or query; the data shape is stable.

## Reading the dummy credentials

Every value in `dummy-creds-template.env` is fake by construction. Anyone
reading the file can confirm none of the values are real secrets.

The pattern: shape match the real credential format closely enough that
the server's input validation passes, but use obvious sentinels
("FakeTest...", "1234567890") so log scans cannot mistake them for live
credentials. Servers using these will fail their first real API call
with 401/403, which is exactly what we want to observe at the network
layer.

## Adding a server

1. Append a YAML entry to `server_list.yaml`.
2. Required: `id`, `source`, `mcp_command` or `mcp_args`.
3. Optional: `transport`, `mode`, `container_image`, `timeout`,
   `inject_credentials`, `allow_network`, `llm`, `api_key_env`.
4. Re-run the campaign; new servers are picked up automatically.
