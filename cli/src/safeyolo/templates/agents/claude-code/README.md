# Claude Code (Sandbox Mode)

This agent runs Claude Code with network isolation. All traffic goes through SafeYolo.

## Quick Start

1. Ensure SafeYolo is running: `safeyolo status`
2. Run: `docker compose run --rm claude`
3. Claude Code will prompt for your API key on first run (OAuth or API key)

## Why `--dangerously-skip-permissions`?

Claude Code normally prompts for approval before running commands or making network requests.
Since SafeYolo already provides network isolation at the Docker level, we skip these prompts
to allow autonomous operation. SafeYolo ensures all traffic is inspected regardless.

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
- Node.js 22 (for Claude Code)
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

**Claude Code not installing**
The container needs internet access through SafeYolo. Ensure the proxy is running and healthy.
