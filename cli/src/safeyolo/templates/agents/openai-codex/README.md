# OpenAI Codex (Secure Mode)

This agent runs OpenAI Codex CLI with network isolation. All traffic goes through SafeYolo.

## Quick Start

1. Ensure SafeYolo is running: `safeyolo status`
2. Run: `docker compose run --rm codex`
3. Codex will prompt for authentication on first run (OAuth or API key)

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
Codex supports API key auth via `OPENAI_API_KEY` environment variable or OAuth.
For OAuth, port forwarding may be needed for the callback on port 1455.
