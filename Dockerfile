# SafeYolo - Security Proxy for AI Coding Agents
#
# Build targets:
#   base     - Core addons only (~200MB) - RECOMMENDED for most users
#   extended - Adds ML + YARA scanning (~700MB) - Optional features
#   dev      - Development/testing environment
#
# Examples:
#   docker build -t safeyolo .                           # Base (default)
#   docker build --target extended -t safeyolo:full .    # With ML/YARA
#   docker build --target dev -t safeyolo:dev .          # Development
#
# Core addons (base):
#   - credential_guard: Block API keys to wrong hosts
#   - rate_limiter: Per-domain rate limiting (GCRA)
#   - circuit_breaker: Fail-fast for unhealthy upstreams
#   - pattern_scanner: Fast regex for secrets/jailbreaks (no YARA)
#   - policy: Per-domain/client addon configuration
#   - service_discovery: Docker container auto-discovery
#   - request_logger: JSONL structured logging
#   - metrics: Per-domain statistics
#   - admin_api: REST API for runtime control
#
# Extended addons (optional):
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
RUN pip install --no-cache-dir \
    mitmproxy \
    httpx \
    pyyaml \
    aiodocker

WORKDIR /app

# Copy core addons (excludes prompt_injection and yara_scanner if not needed)
COPY addons/__init__.py /app/addons/
COPY addons/utils.py /app/addons/
COPY addons/credential_guard.py /app/addons/
COPY addons/rate_limiter.py /app/addons/
COPY addons/circuit_breaker.py /app/addons/
COPY addons/pattern_scanner.py /app/addons/
COPY addons/policy.py /app/addons/
COPY addons/service_discovery.py /app/addons/
COPY addons/request_logger.py /app/addons/
COPY addons/metrics.py /app/addons/
COPY addons/admin_api.py /app/addons/
COPY addons/sse_streaming.py /app/addons/

# Copy configuration
COPY config/ /app/config/

# Copy startup script
COPY scripts/start-safeyolo.sh /app/start-safeyolo.sh
RUN chmod +x /app/start-safeyolo.sh

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
CMD ["/app/start-safeyolo.sh"]

# ==============================================================================
# Extended stage - Adds ML + YARA (~700MB)
# ==============================================================================
FROM base AS extended

# Install build dependencies for YARA
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Install ML + YARA dependencies
RUN pip install --no-cache-dir \
    yara-python \
    onnxruntime \
    transformers \
    huggingface_hub \
    numpy

# Download DeBERTa ONNX model at build time (~400MB cached in image)
RUN python -c "from transformers import AutoTokenizer; \
    AutoTokenizer.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')" \
    && python -c "from huggingface_hub import hf_hub_download; \
    hf_hub_download('protectai/deberta-v3-base-injection-onnx', 'model.onnx')"

# Copy extended addons
COPY addons/yara_scanner.py /app/addons/
COPY addons/prompt_injection.py /app/addons/

# Copy YARA rules
COPY config/yara_rules/ /app/config/yara_rules/

# Copy PIGuard ONNX model (exported via scripts/export_piguard_onnx_v2.py)
COPY models/piguard-onnx/ /app/models/piguard-onnx/

# Clean up build dependencies (keep libyara runtime)
RUN apt-get purge -y gcc && apt-get autoremove -y

# ==============================================================================
# Dev stage - Development and testing
# ==============================================================================
FROM extended AS dev

# Reinstall build deps for development
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install dev/test dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    ipython \
    onnxscript \
    "optimum[onnxruntime]" \
    && pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Download PIGuard model for testing (ungated, designed to reduce over-defense)
RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
    AutoTokenizer.from_pretrained('leolee99/PIGuard'); \
    AutoModelForSequenceClassification.from_pretrained('leolee99/PIGuard', trust_remote_code=True)"

# Mount point for source code (use -v $(pwd):/app)
WORKDIR /app

# Default to bash for interactive use
CMD ["bash"]

# ==============================================================================
# Default target is base (lightweight)
# ==============================================================================
FROM base
