# Secure Mode

This guide explains how to deploy SafeYolo in **Secure Mode** where bypass is impossible - traffic either goes through the proxy or fails.

## Why Secure Mode?

Many autonomous coding agents will retry failed calls by changing network configuration - unsetting proxy variables, opening direct sockets, or using hardcoded IPs. Secure Mode avoids "policy by suggestion" by removing direct internet routing entirely.

**Quick Mode** (per-process env vars) is fine for interactive use, but provides no enforcement against agents that bypass proxy settings.

## Quick Start

```bash
# Ensure SafeYolo is running
safeyolo start

# Generate agent container template
safeyolo secure setup

# Run agent in isolated container
cd claude-code
docker compose run --rm claudecode
```

The generated template handles network isolation, CA certificate mounting, and proxy configuration automatically.

## How It Works

SafeYolo creates a Docker network marked `internal: true`:

1. **safeyolo-internal** (`172.31.0.0/24`)
   - No default gateway to internet
   - Agent containers live here
   - Direct connections get "no route to host"

2. **SafeYolo container** bridges between the internal network and internet
   - Only path to the internet is through SafeYolo at `172.31.0.10:8080`

```
┌─────────────────────────────────────────────────────────────┐
│  safeyolo-internal (no internet)                            │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Agent       │  │  App         │  │  Worker      │      │
│  │  Container   │  │  Container   │  │  Container   │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│         └────────────────►│◄────────────────┘               │
│                           │                                 │
│                           ▼                                 │
│                  ┌────────────────┐                         │
│                  │   SafeYolo     │                         │
│                  │  172.31.0.10   │                         │
│                  │    :8080       │                         │
│                  └────────┬───────┘                         │
│                           │                                 │
└───────────────────────────┼─────────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │   Internet    │
                    └───────────────┘
```

## Available Templates

```bash
safeyolo secure list
```

| Template | Description |
|----------|-------------|
| `claude-code` | Claude Code with Node.js, git, python3 |
| `openai-codex` | OpenAI Codex CLI with similar tooling |

## Generated Files

`safeyolo secure setup` creates:

```
./claude-code/
├── docker-compose.yml    # Network isolation + proxy config
└── README.md             # Usage instructions
```

The compose file includes:
- Internal network attachment
- Proxy environment variables
- CA certificate volume mount
- Common dev tools (git, curl, python3, jq)

## Verification

Test that bypass is impossible from inside the agent container:

```bash
# This works (goes through proxy):
curl https://httpbin.org/ip

# This fails (no route):
curl --noproxy '*' https://httpbin.org/ip
# Error: Could not resolve host / No route to host
```

## Security Properties

| Scenario | Result |
|----------|--------|
| Code respects `HTTP_PROXY` | Inspected by SafeYolo |
| Code ignores proxy vars | Connection fails (no route) |
| Code uses hardcoded IPs | Connection fails (no route) |
| Code tries DNS exfil | DNS fails (no resolver outside network) |
| Container-to-container | Works (same internal network) |

## When to Use Each Mode

**Use Secure Mode when:**
- Running autonomous AI agents
- Running untrusted or AI-generated code
- You need audit logs of all egress
- Credential protection must be enforced, not optional

**Quick Mode is acceptable when:**
- You control all code running in your shell
- Best-effort logging is sufficient
- Just testing SafeYolo functionality

## Authentication

Agents handle their own authentication. When you run the container:

- **Claude Code** - Prompts for API key or OAuth on first run
- **OpenAI Codex** - Prompts for API key or ChatGPT OAuth on first run

No `.env` file or pre-configuration required.

## Troubleshooting

**"No route to host" for legitimate requests:**
- Verify `HTTP_PROXY` is set in the container
- Check SafeYolo container is running: `docker ps | grep safeyolo`
- Verify network connectivity: `ping 172.31.0.10`

**SSL errors:**
- CA cert should be auto-mounted at `/certs/`
- Verify volume exists: `docker volume ls | grep safeyolo-certs`
- Check env vars: `echo $SSL_CERT_FILE`

**Container can't resolve DNS:**
- DNS resolution happens through the proxy
- Verify SafeYolo is running and healthy: `safeyolo status`
