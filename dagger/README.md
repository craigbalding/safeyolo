# SafeYolo Dagger Module

Build and deploy SafeYolo containers using [Dagger](https://dagger.io/).

## Prerequisites

- [Dagger CLI](https://docs.dagger.io/install) v0.19.9+
- [Bun](https://bun.sh/) v1.3.5+

## Quick Start

```bash
cd dagger
bun install
dagger call base
```

## Available Commands

### Build Containers

```bash
# Build base container (~200MB) - core addons only
dagger call base

# Build dev container - includes pytest and dev tools
dagger call dev
```

### Run Locally

```bash
# Run with default ports (8080 proxy, 9090 admin)
dagger call serve

# Run with custom ports
dagger call serve --proxy-port 9999 --admin-port 9091
```

### Export & Publish

```bash
# Export as tarball
dagger call export --target base

# Publish to container registry
dagger call publish --address ghcr.io/youruser/safeyolo
dagger call publish --address ghcr.io/youruser/safeyolo --target dev
```

### Mount Custom Directories

```bash
# Mount custom config
dagger call with-config --config ./my-config

# Mount data directory
dagger call with-data --data ./my-data
```

## What Gets Built

The module replicates the root `Dockerfile` build:

| Target | Size | Contents |
|--------|------|----------|
| `base` | ~200MB | Python 3.13 + mitmproxy + core addons |
| `dev` | ~300MB | Base + gcc + pytest |

### Included in Container

- `/app/addons/` - mitmproxy security addons
- `/app/config/` - Policy and credential rules
- `/app/pdp/` - Policy Decision Point library
- `/app/scripts/` - Startup scripts
- `/app/logs/` - Log output directory

### Exposed Ports

| Port | Purpose |
|------|---------|
| 8080 | HTTP proxy |
| 9090 | Admin API |

## Environment Variables

Override at runtime:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | 8080 | Proxy listen port |
| `ADMIN_PORT` | 9090 | Admin API port |
| `CERT_DIR` | /certs-private | TLS certificate directory |
| `LOG_DIR` | /app/logs | Log output directory |

## Development

```bash
# Type check
bun run tsc --noEmit

# Format
bun run prettier --write src/
```

## Comparison to Docker Compose

This Dagger module produces the same container as `docker-compose.yml`, but:

- **No network orchestration** - Dagger builds containers, doesn't manage networks
- **No volume persistence** - Use `withConfig()`/`withData()` for mounts
- **CI-friendly** - Integrates with GitHub Actions, GitLab CI, etc.

For local development with full networking, use:
```bash
docker compose up -d
```

For CI/CD pipelines and programmatic builds, use this Dagger module.

## License

Same as parent SafeYolo project.
