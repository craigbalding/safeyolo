# SafeYolo

[![CI](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml)
[![Blackbox Tests](https://github.com/craigbalding/safeyolo/actions/workflows/blackbox.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/blackbox.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/craigbalding/safeyolo/badge)](https://scorecard.dev/viewer/?uri=github.com/craigbalding/safeyolo)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11693/badge)](https://www.bestpractices.dev/projects/11693)
[![CodeQL](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml)

**Secure sandbox for AI coding agents.** Run Claude Code or Codex with network isolation, credential protection, and audit logging.

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

- **One-command agent setup** - pre-configured templates for Claude Code and Codex
- **Credential routing** - OpenAI keys only reach `api.openai.com`, Anthropic keys only reach `api.anthropic.com`
- **Human-in-the-loop** - credentials to new destinations require one-time approval
- **Rate limiting** - prevent runaway loops from harming your IP reputation
- **Audit trail** - every request logged with decisions and correlation

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

## Approval Workflow

When SafeYolo blocks a credential heading to an unexpected destination:

1. Agent gets HTTP 428 with details
2. You see the event in `safeyolo watch`
3. Approve or deny interactively
4. Approved credentials are remembered

```
$ safeyolo watch

╭─ Credential Blocked 14:32:15 ─────────────────────────────╮
│ Credential   anthropic                                    │
│ Destination  api.example.com                              │
│ Reason       destination_mismatch                         │
├───────────────────────────────────────────────────────────┤
│ [A]pprove | [D]eny | [S]kip                               │
╰───────────────────────────────────────────────────────────╯
```

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

SafeYolo is a TLS-intercepting proxy. It can only protect credentials it can see.

**What SafeYolo provides:**
- Sandbox Mode runs agents in unprivileged containers with no direct internet
- No Docker socket in containers - all Docker operations run from the CLI on your host
- Credentials are fingerprinted (HMAC), never logged in cleartext
- Container security properties (non-root, no capabilities, seccomp) verified by [CI tests](tests/blackbox/)

**What SafeYolo does NOT do:**
- Defend against determined adversaries running arbitrary code
- Detect or prevent prompt injection
- Replace application-layer auth

**Don't trust pre-built images?** Build locally: `docker build -t safeyolo .` - digest-pinned base, minimal deps, runs non-root. See [SECURITY.md](SECURITY.md) for full container security details.

---

## Requirements

- Python 3.12+
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
