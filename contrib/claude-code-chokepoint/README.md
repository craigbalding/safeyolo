# Claude Code Chokepoint Mode

Run Claude Code in a locked-down container where **bypass is impossible**. Traffic either goes through SafeYolo or fails - there is no direct internet path.

## How It Works

```
chokepoint-internal network (internal: true = no internet gateway)
┌────────────────────────────────────────────────────────┐
│                                                        │
│  ┌─────────────────┐         ┌─────────────────┐      │
│  │  Claude Code    │         │    SafeYolo     │      │
│  │  Container      │────────►│   172.31.0.10   │      │
│  │                 │  proxy  │                 │      │
│  └─────────────────┘         └────────┬────────┘      │
│                                       │               │
└───────────────────────────────────────┼───────────────┘
                                        │
                                        ▼ (only safeyolo)
                                   ┌─────────┐
                                   │ Internet│
                                   └─────────┘
```

The `internal: true` flag on the network means containers have no default route to the internet. The only way out is through SafeYolo's proxy.

## Quick Start

```bash
# 1. Copy env file and add your API key
cp .env.example .env
# Edit .env: add ANTHROPIC_API_KEY

# 2. Start SafeYolo (runs in background)
docker compose up -d safeyolo

# 3. Wait for SafeYolo to generate CA cert (~5 seconds)
sleep 5

# 4. Run Claude Code interactively
docker compose run --rm claude
# Then type: claude
```

## Verify Chokepoint Works

From inside the claude container, prove that bypass fails:

```bash
# This FAILS (no route to internet):
curl --noproxy '*' -I https://example.com
# Expected: "Could not resolve host" or timeout

# This WORKS (goes through SafeYolo):
curl -I https://example.com
# Expected: HTTP/2 200
```

If the first command succeeds, chokepoint mode is not working - check that the network has `internal: true`.

## What Gets Inspected

| Traffic | Behavior |
|---------|----------|
| HTTP | Full headers, URL, body visible to SafeYolo |
| HTTPS | Decrypted via MITM (client trusts SafeYolo CA) |
| Direct connections | **Fail** - no route to internet |
| DNS lookups | **Fail** - no resolver outside network |

## Mounting Your Project

By default, the current directory is mounted at `/workspace`. To use a different path:

```bash
PROJECT_DIR=/path/to/myproject docker compose run --rm claude
```

Or set it in `.env`:
```
PROJECT_DIR=/home/user/myproject
```

## CA Certificate Trust

The compose file sets these environment variables so common tools trust SafeYolo's CA:

```
NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem  # Node.js
SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem        # Python/OpenSSL
REQUESTS_CA_BUNDLE=/certs/mitmproxy-ca-cert.pem   # Python requests
```

If you use a different base image or tools that don't respect these variables, you may need to install the CA cert into the system trust store:

```bash
# Debian/Ubuntu
cp /certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/safeyolo.crt
update-ca-certificates

# Alpine
apk add --no-cache ca-certificates
cp /certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/safeyolo.crt
update-ca-certificates
```

## Accessing Host Services

If you need to reach services running on your host (e.g., `localhost:3000`):

**Docker Desktop (macOS/Windows):** Use `host.docker.internal`:
```bash
curl http://host.docker.internal:3000
```

**Linux:** Add the host alias to the compose service:
```yaml
claude:
  extra_hosts:
    - "host.docker.internal:host-gateway"
```

Then add `host.docker.internal` to `NO_PROXY`:
```yaml
environment:
  - NO_PROXY=localhost,127.0.0.1,host.docker.internal
```

## Customizing the Claude Container

The default uses `node:22-slim` with Claude Code installed at runtime. For faster startup, build a custom image:

```dockerfile
FROM node:22-slim
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*
RUN npm install -g @anthropic-ai/claude-code
```

Then update `docker-compose.yml`:
```yaml
claude:
  build: .
  # Remove the entrypoint/command that installs claude
```

## Viewing SafeYolo Logs

```bash
# Follow logs
docker compose logs -f safeyolo

# Or view the JSONL audit log
tail -f ./logs/safeyolo.jsonl | jq
```

## Cleanup

```bash
docker compose down -v  # -v removes volumes (including CA certs)
```
