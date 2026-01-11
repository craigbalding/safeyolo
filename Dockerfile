# SafeYolo - Security Proxy for AI Coding Agents
#
# Build targets:
#   base - Core addons only (~200MB) - Default
#   dev  - Development/testing environment
#
# Examples:
#   docker build -t safeyolo .                    # Base (default)
#   docker build --target dev -t safeyolo:dev .   # Development
#
# Core addons:
#   - request_id: Unique request ID for event correlation
#   - policy_engine: Per-domain/client addon configuration
#   - network_guard: Access control + rate limiting (deny/budget)
#   - credential_guard: Block API keys to wrong hosts
#   - circuit_breaker: Fail-fast for unhealthy upstreams
#   - pattern_scanner: Fast regex for secrets/jailbreaks
#   - service_discovery: Docker container auto-discovery
#   - request_logger: JSONL structured logging
#   - metrics: Per-domain statistics
#   - admin_api: REST API for runtime control
#
# Extended/experimental addons available on 'experimental' branch:
#   - yara_scanner: Enterprise YARA pattern matching
#   - prompt_injection: ML-based injection detection (DeBERTa)

# ==============================================================================
# Base stage - Core addons only (~200MB)
# ==============================================================================
# Pinned to specific digest for supply chain security
# To update: docker pull python:3.13-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.13-slim
FROM python:3.13-slim@sha256:45ce78b0ad540b2bbb4eaac6f9cb91c9be5af45ab5f483929f407b4fb98c89dd AS base

# Install uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:0.9.24 /uv /usr/local/bin/uv

# Install minimal system dependencies
# - tmux: runs mitmproxy TUI in background
# Note: health checks use Python httpx (no curl needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tmux \
    && rm -rf /var/lib/apt/lists/*

# Install core Python dependencies (frozen = exact lockfile versions with hashes)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Add uv venv to PATH
ENV PATH="/.venv/bin:$PATH"

WORKDIR /app

# Copy PDP (Policy Decision Point) library
COPY pdp/ /app/pdp/
RUN chmod -R 644 /app/pdp/*.py && chmod 755 /app/pdp

# Copy addon framework
COPY addons/__init__.py /app/addons/
COPY addons/base.py /app/addons/
COPY addons/utils.py /app/addons/
COPY addons/budget_tracker.py /app/addons/
COPY addons/policy_loader.py /app/addons/
COPY addons/sensor_utils.py /app/addons/
# Detection module (pure detection logic, no mitmproxy deps)
COPY addons/detection/ /app/addons/detection/
# Copy addons in load order (see scripts/start-safeyolo.sh)
# Layer 0: Infrastructure
COPY addons/admin_shield.py /app/addons/
COPY addons/request_id.py /app/addons/
COPY addons/sse_streaming.py /app/addons/
COPY addons/policy_engine.py /app/addons/
# Layer 1: Network Policy
COPY addons/network_guard.py /app/addons/
COPY addons/circuit_breaker.py /app/addons/
# Layer 2: Security Inspection
COPY addons/credential_guard.py /app/addons/
COPY addons/pattern_scanner.py /app/addons/
# Layer 3: Observability
COPY addons/request_logger.py /app/addons/
COPY addons/metrics.py /app/addons/
COPY addons/admin_api.py /app/addons/
# Optional
COPY addons/service_discovery.py /app/addons/

# Copy configuration
COPY config/ /app/config/

# Copy scripts (dev: mount -v $(pwd):/app overrides these)
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

# Create directories (ownership set at runtime via docker-compose user:)
RUN mkdir -p /app/logs /certs

# Ports
EXPOSE 8080 8888 9090

# Environment defaults
ENV PROXY_PORT=8080
ENV ADMIN_PORT=9090
ENV CERT_DIR=/certs-private
ENV PUBLIC_CERT_DIR=/certs-public
ENV LOG_DIR=/app/logs
ENV CONFIG_DIR=/app/config
ENV PYTHONPATH=/app:/app/addons

# Non-root execution: use docker-compose.yml user: "${SAFEYOLO_UID}:${SAFEYOLO_GID}"
# This runs as the host user's UID/GID, so volume permissions just work.

# Start SafeYolo
CMD ["/app/scripts/start-safeyolo.sh"]

# ==============================================================================
# Dev stage - Development and testing
# ==============================================================================
FROM base AS dev

# Reinstall build deps for development
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install dev/test dependencies (venv already in PATH from base)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --group dev --no-install-project

# Mount point for source code (use -v $(pwd):/app)
WORKDIR /app

# Default to bash for interactive use
CMD ["bash"]

# ==============================================================================
# Default target is base (lightweight)
# ==============================================================================
FROM base
