# OpenAI Codex (Secure Mode)

This agent runs OpenAI Codex CLI with network isolation. All traffic goes through SafeYolo.

## Quick Start

1. Copy `.env.example` to `.env` and add your OpenAI API key
2. Ensure SafeYolo is running: `safeyolo status`
3. Run: `docker compose run --rm codex`
4. Inside the container, run: `codex --sandbox danger-full-access`

## Why `--sandbox danger-full-access`?

Codex has its own sandboxing (Landlock on Linux, Seatbelt on macOS) that restricts network access.
Since SafeYolo already provides network isolation at the Docker level, we disable Codex's
internal sandbox to avoid conflicts. SafeYolo ensures all traffic is inspected regardless.

## Verify Isolation

From inside the container:

```bash
# This FAILS (no direct route):
curl --noproxy '*' -I https://example.com

# This WORKS (through SafeYolo):
curl -I https://example.com
```

## Included Tools

The container includes common development tools:
- Node.js 22 (for Codex CLI)
- git, curl, jq
- Python 3 with pip

## Troubleshooting

**"Cannot resolve host"**
SafeYolo might not be running. Check with `safeyolo status` and start with `safeyolo start`.

**Certificate errors**
The SafeYolo CA cert should be auto-mounted at `/certs/`. Verify the volume exists:
```bash
docker volume ls | grep safeyolo-certs
```

**Authentication issues**
Codex supports API key auth via `OPENAI_API_KEY`. If using ChatGPT account auth,
you may need to configure port forwarding for the OAuth callback on port 1455.
