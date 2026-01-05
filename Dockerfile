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
FROM python:3.13-slim AS base

# Install minimal system dependencies
# - curl: health checks in start script
# - tmux: runs mitmproxy TUI in background
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tmux \
    && rm -rf /var/lib/apt/lists/*

# Install core Python dependencies (no ML, no YARA)
COPY requirements/base.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app

# Copy addon framework
COPY addons/__init__.py /app/addons/
COPY addons/base.py /app/addons/
COPY addons/utils.py /app/addons/
COPY addons/budget_tracker.py /app/addons/
COPY addons/policy_loader.py /app/addons/
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
ENV CERT_DIR=/certs
ENV LOG_DIR=/app/logs
ENV CONFIG_DIR=/app/config

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

# Install dev/test dependencies (need both files since dev.txt references base.txt)
COPY requirements/base.txt requirements/dev.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/dev.txt

# Mount point for source code (use -v $(pwd):/app)
WORKDIR /app

# Default to bash for interactive use
CMD ["bash"]

# ==============================================================================
# Default target is base (lightweight)
# ==============================================================================
FROM base
