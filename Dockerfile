# SafeYolo - Security Proxy for AI Coding Agents
#
# Build targets:
#   (default) - Production: hardened, no apt/dpkg, minimal attack surface
#   dev       - Development: has apt, gcc for building packages
#   base      - Intermediate: has apt but no gcc (rarely used directly)
#
# Examples:
#   docker build -t safeyolo .                    # Production (default)
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

# Merge system CA bundle into certifi so mitmproxy trusts both certifi roots
# and Debian system roots. Cross-signed chains (e.g. Cloudflare → SSL.com →
# Comodo "AAA Certificate Services") may chain to roots present in only one
# bundle. Merging both prevents upstream TLS failures when either bundle
# drops a root the other still carries.
RUN CERTIFI_BUNDLE=$(/.venv/bin/python3 -c "import certifi; print(certifi.where())") && \
    cat /etc/ssl/certs/ca-certificates.crt >> "$CERTIFI_BUNDLE"

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
COPY addons/policy_compiler.py /app/addons/
COPY addons/policy_loader.py /app/addons/
COPY addons/yaml_roundtrip.py /app/addons/
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
COPY addons/flow_store.py /app/addons/
COPY addons/flow_recorder.py /app/addons/
COPY addons/request_logger.py /app/addons/
COPY addons/metrics.py /app/addons/
COPY addons/admin_api.py /app/addons/
# Agent identity (stamps flow.metadata["agent"] for all layers)
COPY addons/service_discovery.py /app/addons/
# Layer 0.5: Service Gateway (credential injection for agents)
COPY addons/vault.py /app/addons/
COPY addons/service_loader.py /app/addons/
COPY addons/service_gateway.py /app/addons/
# Builtin service definitions (user overrides via /safeyolo/services/)
COPY config/services/ /app/services/

# Note: Configuration is mounted from host at runtime (~/.safeyolo/ -> /safeyolo/)
# No baked-in config - 'safeyolo init' creates the config directory

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
ENV CONFIG_DIR=/safeyolo
ENV LOG_DIR=/app/logs
ENV PYTHONPATH=/app:/app/addons
# Cache dir for uv, pytest, ruff etc. (HOME=/ is not writable by non-root)
ENV XDG_CACHE_HOME=/tmp/.cache

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

# Install dev/test dependencies into existing /.venv (not /app/.venv)
# Base stage set WORKDIR /app, so we must switch back to / where the venv lives
WORKDIR /
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --group dev --no-install-project

WORKDIR /app

# Default to bash for interactive use
CMD ["bash"]

# ==============================================================================
# Production stage - Hardened for deployment
# ==============================================================================
FROM base

# Remove packages not needed at runtime (reduces attack surface)
# Can't use apt-get purge (dpkg needs diff, apt needs keyring) so delete directly
# You have Python and tmux. What more could you possibly need?
RUN rm -rf /var/lib/dpkg /var/lib/apt /var/cache/apt /var/log/apt \
    # Package management
    && rm -f /usr/bin/apt* /usr/bin/dpkg* \
    && rm -f /usr/sbin/dpkg* \
    # Security risks - container escape / privilege escalation
    && rm -f /usr/sbin/chroot /usr/bin/chroot \
    && rm -f /usr/bin/nsenter /usr/bin/unshare \
    && rm -f /usr/bin/su /usr/bin/newgrp /usr/bin/sg \
    && rm -f /usr/bin/setpriv /usr/bin/runcon /usr/bin/chcon \
    # Auth/user management (container runs as fixed UID)
    && rm -f /usr/bin/login /usr/bin/passwd /usr/bin/adduser /usr/bin/deluser \
    && rm -f /usr/bin/chage /usr/bin/chfn /usr/bin/chsh /usr/bin/expiry /usr/bin/gpasswd \
    && rm -f /usr/sbin/adduser /usr/sbin/deluser /usr/sbin/addgroup /usr/sbin/delgroup \
    && rm -f /usr/sbin/useradd /usr/sbin/userdel /usr/sbin/usermod \
    && rm -f /usr/sbin/groupadd /usr/sbin/groupdel /usr/sbin/groupmod \
    && rm -f /usr/sbin/chpasswd /usr/sbin/chgpasswd /usr/sbin/newusers \
    && rm -f /usr/sbin/pwck /usr/sbin/pwconv /usr/sbin/pwunconv \
    && rm -f /usr/sbin/grpck /usr/sbin/grpconv /usr/sbin/grpunconv \
    && rm -f /usr/sbin/vigr /usr/sbin/vipw /usr/sbin/mkhomedir_helper \
    && rm -f /usr/sbin/add-shell /usr/sbin/remove-shell /usr/sbin/update-shells \
    && rm -f /usr/sbin/shadowconfig /usr/sbin/pwhistory_helper \
    && rm -f /usr/sbin/pam* /usr/sbin/unix_chkpwd /usr/sbin/unix_update /usr/sbin/faillock \
    && rm -f /usr/sbin/update-passwd \
    # System exploration (not needed at runtime)
    && rm -f /usr/bin/lscpu /usr/bin/lsmem /usr/bin/lsblk /usr/bin/lsipc \
    && rm -f /usr/bin/lslocks /usr/bin/lslogins /usr/bin/lsns \
    && rm -f /bin/dmesg /usr/bin/dmesg \
    && rm -f /usr/bin/ldd \
    # Debian config system
    && rm -f /usr/bin/debconf* /usr/sbin/dpkg-preconfigure /usr/sbin/dpkg-reconfigure \
    && rm -f /usr/bin/deb-systemd-helper /usr/bin/deb-systemd-invoke \
    && rm -f /usr/sbin/service /usr/sbin/start-stop-daemon \
    && rm -f /usr/sbin/invoke-rc.d /usr/sbin/update-rc.d /usr/sbin/policy-rc.d \
    # Filesystem utilities (read-only root)
    && rm -f /bin/mount /bin/umount /usr/bin/mount /usr/bin/umount /usr/bin/mountpoint \
    && rm -f /usr/sbin/mkfs* /usr/sbin/mkswap /usr/sbin/swapon /usr/sbin/swapoff /usr/sbin/swaplabel \
    && rm -f /usr/sbin/fsck* /usr/sbin/fsfreeze /usr/sbin/fstrim /usr/sbin/fstab-decode \
    && rm -f /usr/sbin/losetup /usr/sbin/blkid /usr/sbin/blk* /usr/sbin/blockdev \
    && rm -f /usr/sbin/findfs /usr/sbin/wipefs /usr/sbin/zramctl \
    && rm -f /usr/sbin/pivot_root /usr/sbin/switch_root \
    # Shell utilities (not needed at runtime)
    && rm -f /usr/bin/find /usr/bin/xargs /usr/bin/locate \
    && rm -f /usr/bin/diff /usr/bin/diff3 /usr/bin/sdiff /usr/bin/cmp \
    # Misc utilities not needed
    && rm -f /usr/bin/wall /usr/bin/write /usr/bin/mesg \
    && rm -f /usr/bin/script /usr/bin/scriptlive /usr/bin/scriptreplay \
    && rm -f /usr/bin/who /usr/bin/users /usr/bin/pinky /usr/bin/last \
    && rm -f /usr/sbin/agetty /usr/sbin/getty /usr/sbin/sulogin /usr/sbin/nologin \
    && rm -f /usr/sbin/runuser /usr/sbin/killall5
