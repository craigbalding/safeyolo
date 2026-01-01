# SafeYolo Docker Cheatsheet

## Build Targets (IMPORTANT)

The Dockerfile has three stages:

| Target | Purpose | Has pytest? | Copies code? |
|--------|---------|-------------|--------------|
| `base` | Shared dependencies | No | No - relies on volume mounts |
| `dev` | Testing & development | Yes | No - relies on volume mounts |
| `prod` | Production runtime | No | Yes - bakes code into image |

### What docker-compose.yml uses

```yaml
build:
  context: .
  target: base  # <-- Uses base stage for dev workflow
```

**Your current setup uses `base`** - code comes from volume mounts, not baked into image. This is correct for dev.

### When to use each target

| Scenario | Target | Command |
|----------|--------|---------|
| **Daily dev work** | `base` | `docker compose up -d` (default) |
| **Run tests** | `dev` | `docker build --target dev -t safeyolo:dev . && docker run --rm -v $(pwd):/app safeyolo:dev pytest tests/ -v` |
| **Deploy to prod** | `prod` | `docker build -t safeyolo:prod .` (default target) |

### Building specific targets

```bash
# Build dev image (has pytest)
docker build --target dev -t safeyolo:dev .

# Build prod image (code baked in, no volume mounts needed)
docker build --target prod -t safeyolo:prod .
# or just (prod is default):
docker build -t safeyolo:prod .

# Build base (what compose uses)
docker build --target base -t safeyolo:base .
```

### Why this matters

- **Forgot `--target dev`?** → `pytest: command not found`
- **Using prod image but expecting code changes?** → Changes won't appear (code is baked in)
- **Volume mounts not working?** → Check you're using `base` or `dev`, not `prod`

---

## Core Concepts

### Image vs Container
- **Image**: A snapshot/template (like a class). Built from Dockerfile. Immutable.
- **Container**: A running instance of an image (like an object). Has state, can be stopped/started.

### Key Commands Explained

| Command | What it does | When to use |
|---------|--------------|-------------|
| `docker build` | Creates an image from Dockerfile | Changed Dockerfile or requirements.txt |
| `docker run` | Creates AND starts a new container from an image | First time setup (compose handles this) |
| `docker start` | Starts an existing stopped container | Resume after `docker stop` |
| `docker stop` | Gracefully stops a running container | Pause work, container persists |
| `docker restart` | Stop + start (keeps same container) | Reload code that needs process restart |
| `docker rm` | Deletes a container | Clean slate, lose container state |

### The `-d` Flag (Detached)
- Without `-d`: Container runs in foreground, logs to terminal, Ctrl+C stops it
- With `-d`: Container runs in background, returns immediately, use `docker logs` to see output

### Docker Compose Additions

| Command | What it does |
|---------|--------------|
| `docker compose up` | Build (if needed) + create + start containers |
| `docker compose up -d` | Same but detached |
| `docker compose up --build` | Force rebuild image, then start |
| `docker compose down` | Stop + remove containers (keeps volumes/images) |
| `docker compose down -v` | Also remove volumes (lose data!) |

---

## Dev Lifecycle for SafeYolo

### What You Changed → What To Do

| Changed | Command | Why |
|---------|---------|-----|
| `addons/*.py` | `docker restart safeyolo` | Python files need process restart to reload |
| `scripts/*.sh` | `docker restart safeyolo` | Shell scripts re-read on start |
| `config/*` | `docker restart safeyolo` | Config re-read on start |
| `requirements.txt` | `docker compose up -d --build` | Need to rebuild image to install new packages |
| `Dockerfile` | `docker compose up -d --build` | Rebuild image (slow - downloads DeBERTa ~400MB) |
| `docker-compose.yml` | `docker compose up -d` | Compose re-reads and recreates if needed |

### Dev Iteration Loop

```bash
# 1. Edit code locally (addons/, scripts/, config/)
#    Files sync instantly via volume mounts

# 2. Restart to reload
docker restart safeyolo

# 3. Check it worked
docker logs --tail 20 safeyolo

# 4. Repeat
```

### Debugging

```bash
# Did my changes load?
docker exec safeyolo cat /app/addons/your_file.py

# What's happening inside?
docker exec -it safeyolo /bin/sh

# Watch logs in real-time
docker logs -f safeyolo

# Is the process actually running?
docker exec safeyolo ps aux
```

---

## Volume Mounts (live editing)

```
./addons  → /app/addons:ro    # addon code
./scripts → /app/scripts:ro   # startup scripts
./config  → /app/config:ro    # config files
./logs    → /app/logs         # logs (writable)
```

The `:ro` means read-only from container's perspective (can't write back). Files sync instantly from host, but Python/mitmproxy needs restart to reload.

---

## Startup Order

1. Start safeyolo first (owns the network):
   ```bash
   docker compose -f /projects/safeyolo/docker-compose.yml up -d
   ```

2. Then start other projects that join safeyolo-internal network

3. To check network membership:
   ```bash
   docker network inspect safeyolo-internal --format '{{range .Containers}}{{.Name}} {{end}}'
   ```

---

## Quick Reference

```bash
# Status
docker ps | grep safeyolo
docker logs -f safeyolo

# Restart after code changes
docker restart safeyolo

# Shell into container
docker exec -it safeyolo /bin/sh

# Rebuild (Dockerfile/requirements changes)
docker compose -f /projects/safeyolo/docker-compose.yml up -d --build

# Full teardown and restart
docker compose -f /projects/safeyolo/docker-compose.yml down && \
docker compose -f /projects/safeyolo/docker-compose.yml up -d

# Nuclear option (rebuild everything, lose volumes)
docker compose -f /projects/safeyolo/docker-compose.yml down -v && \
docker compose -f /projects/safeyolo/docker-compose.yml up -d --build
```

## Ports
- `8888` → Proxy (8080 inside)
- `9090` → Admin API

## ML Model (DeBERTa)

The image includes DeBERTa ONNX model for prompt injection detection (~400MB).

- **Downloaded at build time** - cached in image, no runtime fetch
- **Loaded on first request** - ~2-5s cold start on proxy startup
- **Inference**: ~15ms per request (local, no HTTP roundtrip)

Model: `protectai/deberta-v3-base-injection-onnx`

To verify model is loaded:
```bash
docker logs safeyolo | grep -i deberta
# Should see: "DeBERTa model loaded in Xms"
```

## Quick Health Checks
```bash
# Is it running?
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep safeyolo

# Recent logs
docker logs --tail 50 safeyolo

# Test proxy is responding
curl -x http://localhost:8888 http://httpbin.org/ip
```
