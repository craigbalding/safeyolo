# SafeYolo

[![CI](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml)
[![Blackbox Tests](https://github.com/craigbalding/safeyolo/actions/workflows/blackbox.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/blackbox.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/craigbalding/safeyolo/badge)](https://scorecard.dev/viewer/?uri=github.com/craigbalding/safeyolo)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11693/badge)](https://www.bestpractices.dev/projects/11693)
[![CodeQL](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml)

**SafeYolo is a human-centric safety layer for AI agents.**

Most agent sandbox projects focus on host isolation: run the agent in a locked-down container, restrict the filesystem, limit network access.

That helps, but it doesn't solve the real problem.

Agents need to reach your external services — your email, your project tracker, your cloud APIs. But an agent with access to your inbox can read password reset emails, 2FA codes, and security notifications. An agent with a cloud API key may be able to create more keys — giving itself or an attacker silent, ongoing access. In error or if prompt-injected, these are paths to account takeover.

SafeYolo gives you scoped control over what your agents can access, so they get what they need to do their job and nothing more.

Built on the fantastic [mitmproxy](https://mitmproxy.org/) project.

## Quick Start

```bash
# Install from source
git clone https://github.com/craigbalding/safeyolo.git
cd safeyolo/cli && uv tool install -e .

# Initialize and start the proxy
safeyolo init
safeyolo start

# Run Claude Code in a secure sandbox
safeyolo agent add myproject claude-code ~/code
```

The last argument (`~/code`) is where your project files live on the host - the agent works on these files but runs in an isolated container where:

- **All traffic routes through SafeYolo proxy** - no direct internet access
- **API keys are protected** - credentials only reach their intended hosts
- **Everything is logged** - JSONL audit trail for review
- **Dev-ready containers** - agents install their own toolchains via mise — no root needed

## Key Features

- **One-command agent setup** — pre-configured templates for Claude Code and Codex
- **Scoped API access** — grant agents specific capabilities per service, block everything else
- **Credential isolation** — agents access your services without ever seeing your keys
- **Human-in-the-loop** — risky actions need your approval via `safeyolo watch`
- **Rate limiting** — prevent runaway loops from harming your IP reputation
- **Audit trail** — every request logged with decisions and correlation

## Multiple Agents

Run multiple agents with separate policies and isolated networks:

```bash
safeyolo agent add work claude-code ~/work
safeyolo agent add side-project claude-code ~/side-project
safeyolo agent add codex openai-codex ~/experiments

safeyolo agent run work       # Each agent gets isolated policy
```

## Templates

| Template | Agent |
|----------|-------|
| `claude-code` | Anthropic Claude Code CLI |
| `openai-codex` | OpenAI Codex CLI |

If you've already authenticated on your host (via `claude` or `codex`), credentials are mounted automatically.

## Controlling Agent Access

Grant agents access to specific services with specific capabilities. Your credentials stay in SafeYolo's vault — agents make requests, SafeYolo handles authentication.

```bash
# Authorize an agent to access Gmail with a specific capability
safeyolo agent authorize boris gmail --capability read_agent_folder --token-env GMAIL_TOKEN
```

`safeyolo watch` is your real-time control surface. When an agent needs access to a service, you see it here:

```
$ safeyolo watch

╭─ boris requests authenticated access 14:32:15 ────────────╮
│ Service      gmail                                        │
│ Capability   read_agent_folder                             │
│                                                           │
│ This will permanently bind a credential to this agent.    │
├───────────────────────────────────────────────────────────┤
│ [A]uthorize · [D]eny · [L]ater                            │
╰───────────────────────────────────────────────────────────╯
```

Within a granted capability, destructive or sensitive actions still need your approval — scoped to once, for the session, or permanently.

**Try it yourself:** Run `safeyolo demo` for a guided tour, with `safeyolo watch` in a second terminal.

---

## Try Mode (Evaluation Only)

For quick evaluation without container isolation, you can run SafeYolo as a local proxy:

```bash
safeyolo start
eval "$(safeyolo cert env)"
claude
```

**Limitation:** In Try Mode, agents can bypass the proxy by unsetting environment variables or opening direct sockets. Use Sandbox Mode (the default) for actual protection.

---

## Trust Model

**What SafeYolo does NOT do:**
- Eliminate prompt injection — but it reduces the blast radius by constraining what a compromised agent can access
- Defend against determined adversaries with arbitrary code execution on the host
- Replace application-layer auth

See [SECURITY.md](SECURITY.md) for the full security model, trust boundaries, and enforcement details.

---

## Requirements

- Python 3.10+
- Docker

## Status

SafeYolo is **pre-v1**. The CLI works from source (as shown above). PyPI package coming soon.

## Documentation

- [CLI Reference](cli/README.md)
- [Configuration](docs/CONFIGURATION.md)
- [Architecture & Addons](docs/ADDONS.md)
- [Security & Threat Model](SECURITY.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License. Built with [mitmproxy](https://mitmproxy.org/).
