# Sandbox Mode

Sandbox Mode runs AI coding agents in isolated Linux microVMs. Traffic either goes through the SafeYolo proxy or is blocked — bypass is impossible.

## Quick Start

```bash
safeyolo start
safeyolo agent add myproject claude-code ~/projects/myapp
```

The agent boots in a microVM with network isolation, CA trust, and proxy configuration handled automatically.

## How It Works

Each agent runs in a persistent Linux microVM (Apple Virtualization.framework) with a dedicated feth network pair:

1. **feth pair** creates an isolated network segment per VM
2. **pf rules** on the feth interface allow only the proxy port
3. **All other egress is blocked** — the VM cannot reach the internet directly
4. **HTTP_PROXY/HTTPS_PROXY** route traffic through SafeYolo's mitmproxy

```
Agent VM (192.168.68.2)
    │
    │  HTTP_PROXY=http://192.168.68.1:8090
    │
    ▼
feth pair (pf: allow :8090, block all else)
    │
    ▼
SafeYolo mitmproxy (host process)
    │  addon chain: policy, credential guard, rate limits, audit
    ▼
Internet
```

If the agent unsets proxy env vars, raw connections are blocked by pf. If the agent sends non-HTTP traffic, it's blocked by pf. The enforcement is at the network level, not the process level.

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

# This is blocked (pf drops it):
curl --noproxy '*' https://ifconfig.co
# Error: Could not resolve host / Connection refused
```

## Security Properties

| Scenario | Result |
|----------|--------|
| Code respects HTTP_PROXY | Inspected by SafeYolo |
| Code unsets proxy vars | Blocked by pf (no route) |
| Code uses hardcoded IPs | Blocked by pf |
| Code sends raw TCP/UDP | Blocked by pf |
| Code tries DNS exfil | Blocked (no DNS allowed from VM) |

## Persistence

Agent state persists across restarts: mise installs, shell history, config files. Each agent has its own ext4 disk image at `~/.safeyolo/agents/<name>/rootfs.ext4`.

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
