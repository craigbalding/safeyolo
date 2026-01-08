# SafeYolo Dagger Module

> Agent memory for SafeYolo Dagger module development

## Overview

This is a **Dagger v0.19.9** module written in **TypeScript** using **Bun 1.3.5** as the runtime. It replicates the build process defined in the root `Dockerfile` and `docker-compose.yml`.

## Project Structure

```
dagger/
├── dagger.json      # Dagger module config (engineVersion: v0.19.9)
├── package.json     # Bun dependencies (@dagger.io/dagger)
├── tsconfig.json    # TypeScript config (ESNext, bundler resolution)
└── src/
    └── index.ts     # Main module implementation
```

## Key Design Decisions

1. **Pinned base image**: Uses SHA256 digest for supply chain security
   ```
   python:3.13-slim@sha256:45ce78b0ad540b2bbb4eaac6f9cb91c9be5af45ab5f483929f407b4fb98c89dd
   ```

2. **Hash-verified dependencies**: Uses `--require-hashes` with `requirements/base.txt` and `requirements/dev.txt`

3. **Two build targets**:
   - `base()` - Core addons only (~200MB)
   - `dev()` - Adds gcc + pytest for development

4. **Source resolution**: Module sources from parent directory (`..`) to access root project files

## Available Functions

| Function | Description |
|----------|-------------|
| `base()` | Build base container |
| `dev()` | Build dev container with pytest |
| `serve(proxyPort?, adminPort?)` | Run proxy with exposed ports |
| `withConfig(dir)` | Mount custom config directory |
| `withData(dir)` | Mount data directory |
| `export(target?)` | Export container as tarball |
| `publish(address, target?)` | Push to container registry |

## Environment Variables

Set in container by default:
- `PROXY_PORT=8080`
- `ADMIN_PORT=9090`
- `CERT_DIR=/certs-private`
- `PUBLIC_CERT_DIR=/certs-public`
- `LOG_DIR=/app/logs`
- `CONFIG_DIR=/app/config`
- `PYTHONPATH=/app:/app/addons`

## Directory Layout in Container

```
/app/
├── addons/       # mitmproxy addon chain
├── config/       # Policy and credential rules
├── logs/         # JSONL logs
├── pdp/          # Policy Decision Point library
└── scripts/      # start-safeyolo.sh entrypoint
```

## Development Commands

```bash
# Install dependencies
bun install

# Build base container
dagger call base

# Build dev container
dagger call dev

# Run interactively
dagger call serve

# Publish to registry
dagger call publish --address ghcr.io/user/safeyolo --target base
```

## Relationship to docker-compose.yml

The Dagger module builds the same container as the `safeyolo` service in `docker-compose.yml`. However:

- **Networks**: Dagger doesn't manage networks (that's orchestration)
- **Volumes**: Use `withConfig()`, `withData()` to mount directories
- **certs-init**: Not replicated; certificate setup happens at runtime via `start-safeyolo.sh`

## Future Improvements

- [ ] Add `test()` function to run pytest suite
- [ ] Add caching for pip dependencies
- [ ] Add multi-arch build support (arm64)
- [ ] Add integration with CI (GitHub Actions)

## Files to Reference

When modifying this module, consult:
- `/Dockerfile` - Original build definition
- `/docker-compose.yml` - Service configuration
- `/scripts/start-safeyolo.sh` - Entrypoint logic
- `/requirements/base.txt` - Core dependencies
- `/requirements/dev.txt` - Dev dependencies
