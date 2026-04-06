# Service Discovery

SafeYolo identifies which agent is making each request using a file-based IP map maintained by the CLI.

## How It Works

1. CLI writes `~/.safeyolo/data/agent_map.json` when a VM starts (with its IP) and removes the entry when it stops
2. The `service_discovery` addon reads this file on each request (mtime-cached)
3. The addon resolves the client source IP to an agent name
4. Downstream addons (credential_guard, network_guard, etc.) use the agent name for per-agent policy evaluation

```
agent_map.json:
  {"test": {"ip": "192.168.68.2", "started": "2026-04-06T..."}}

Request from 192.168.68.2
    │
    ▼
service_discovery: IP lookup → "test"
    │
    ▼
flow.metadata["agent"] = "test"
    │
    ▼
credential_guard evaluates policy for agent "test"
```

## Agent Map Format

```json
{
  "test": {
    "ip": "192.168.68.2",
    "started": "2026-04-06T18:30:00Z"
  },
  "work": {
    "ip": "192.168.69.2",
    "started": "2026-04-06T18:35:00Z"
  }
}
```

The map is passed to mitmproxy via `--set agent_map_file=~/.safeyolo/data/agent_map.json`.

## Troubleshooting

### All requests show "unknown" principal

1. Check the agent map file exists and has entries: `cat ~/.safeyolo/data/agent_map.json`
2. Check the VM is running: `safeyolo status`
3. Check the agent's IP matches the map entry

### Agent map not updating

The CLI writes the map on `agent add/run` (start) and `agent stop/remove` (cleanup). If the VM crashes without cleanup, stale entries may remain. `safeyolo stop` cleans up all entries.
