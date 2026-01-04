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
#   - credential_guard: Block API keys to wrong hosts
#   - rate_limiter: Per-domain rate limiting (GCRA)
#   - circuit_breaker: Fail-fast for unhealthy upstreams
#   - pattern_scanner: Fast regex for secrets/jailbreaks
#   - policy_engine: Per-domain/client addon configuration
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
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tmux \
    docker.io \
    # Network troubleshooting tools
    procps \
    net-tools \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install core Python dependencies (no ML, no YARA)
COPY requirements/base.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app

# Copy core addons
COPY addons/__init__.py /app/addons/
COPY addons/utils.py /app/addons/
COPY addons/admin_shield.py /app/addons/
COPY addons/request_id.py /app/addons/
COPY addons/credential_guard.py /app/addons/
COPY addons/rate_limiter.py /app/addons/
COPY addons/circuit_breaker.py /app/addons/
COPY addons/pattern_scanner.py /app/addons/
COPY addons/policy_engine.py /app/addons/
COPY addons/service_discovery.py /app/addons/
COPY addons/request_logger.py /app/addons/
COPY addons/metrics.py /app/addons/
COPY addons/admin_api.py /app/addons/
COPY addons/sse_streaming.py /app/addons/

# Copy configuration
COPY config/ /app/config/

# Copy scripts (dev: mount -v $(pwd):/app overrides these)
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

# Create directories
RUN mkdir -p /app/logs /certs

# Ports
EXPOSE 8080 8888 9090

# Environment defaults
ENV PROXY_PORT=8080
ENV ADMIN_PORT=9090
ENV CERT_DIR=/certs
ENV LOG_DIR=/app/logs
ENV CONFIG_DIR=/app/config

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
