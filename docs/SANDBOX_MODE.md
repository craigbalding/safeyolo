# Sandbox Mode

Sandbox Mode runs AI coding agents in isolated Linux sandboxes — hardware-backed microVMs on macOS, gVisor containers on Linux. Traffic either goes through the SafeYolo proxy or it doesn't leave at all; there is no other path out.

## Quick Start

```bash
safeyolo start
safeyolo agent add myproject claude-code ~/projects/myapp
```

The agent boots in its sandbox with CA trust and proxy configuration handled automatically.

## How It Works

The sandbox has **no external network interface**. The only egress path is a per-agent Unix socket bound to a host-side bridge, which routes through SafeYolo's mitmproxy:

```
Agent sandbox (loopback-only; no eth0)
    │
    │  HTTP_PROXY → in-guest forwarder → AF_UNIX or AF_VSOCK
    ▼
Per-agent bridge socket (one per agent, host-owned)
    │
    │  bridge stamps upstream TCP with a PROXY protocol v2 header
    │  carrying the agent's attribution IP; mitmproxy parses it
    │  via next_layer and attributes every request to the right agent
    ▼
SafeYolo mitmproxy (host process)
    │  addon chain: policy, credential guard, rate limits, audit
    ▼
Internet
```

If the agent unsets proxy env vars → no effect, because there is no other network path. Raw TCP → impossible (no external interface). DNS → no resolver reachable. The enforcement is **structural**, not policy-based — there are no firewall rules to misconfigure; there's simply nowhere else for traffic to go.

## Available Templates

```bash
safeyolo sandbox list
```

| Template | Description |
|----------|-------------|
| `claude-code` | Claude Code with Node.js, mise, git, gh |
| `openai-codex` | OpenAI Codex CLI with similar tooling |
| `byoa` | Bring Your Own Agent — bash shell for custom agent installation |

## Verification

From inside the agent:

```bash
# This works (goes through proxy):
curl https://httpbin.org/ip

# This is blocked (no external network interface):
curl --noproxy '*' https://ifconfig.co
# Error: Could not resolve host / Connection refused
```

## Security Properties

| Scenario | Result |
|----------|--------|
| Code respects HTTP_PROXY | Inspected by SafeYolo |
| Code unsets proxy vars | No egress path exists |
| Code uses hardcoded IPs | No external interface to route through |
| Code sends raw TCP/UDP | No external interface |
| Code tries DNS exfil | No resolver reachable |

## Persistence

Agent state persists across restarts: mise installs, shell history, config files.

- **macOS**: each agent has its own ext4 disk image at `~/.safeyolo/agents/<name>/rootfs.ext4`.
- **Linux**: agents share a single read-only EROFS image at `~/.safeyolo/share/rootfs-base.erofs`; gVisor's sentry provides a memory-backed writable overlay per sandbox, and per-agent persistent state lives under `~/.safeyolo/agents/<name>/` (config share, status share, agent metadata).

## Troubleshooting

**Agent can't reach the internet:**
- Check proxy is running: `safeyolo status`
- Check mitmproxy logs: `cat ~/.local/state/safeyolo/mitmproxy.log | tail -20`

**SSL errors:**
- The CA cert is injected via VirtioFS config share
- Check from agent: `echo $SSL_CERT_FILE`

**Agent binary not found:**
- First run installs via mise (may take a minute)
- Check status: the CLI shows "Installing <agent>..." during first boot
