# SafeYolo Agent Base Image
# Pre-installs dev tools and mise for polyglot language support
#
# Agent CLI installed at runtime via mise (see mise.toml)
# Languages: Install with `mise install python@3.12` etc.

FROM node:22-slim

# Pinned mise version with checksums
ARG MISE_VERSION=2026.1.1
ARG MISE_SHA256_X64=e35fd46d51f27829f4aefe60c9a8e92a68534de5ad07568b5f034144d1d3cf0c
ARG MISE_SHA256_ARM64=dcd7006e84d3557284a7c87b99abdce4a465900f67609e99b39c757006a361dd

# Install core dev tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    jq \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install mise with checksum verification
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) ARCH=x64; CHECKSUM="${MISE_SHA256_X64}" ;; \
        arm64) ARCH=arm64; CHECKSUM="${MISE_SHA256_ARM64}" ;; \
        *) echo "Unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${ARCH}.tar.gz" -o mise.tar.gz; \
    echo "${CHECKSUM}  mise.tar.gz" | sha256sum -c -; \
    tar -xzf mise.tar.gz; \
    mv mise/bin/mise /usr/local/bin/mise; \
    rm -rf mise.tar.gz mise/; \
    mise --version

# Add mise activation to global profile (interactive shells)
RUN echo 'eval "$(mise activate bash)"' >> /etc/bash.bashrc

# Enable mise for non-interactive shells (bash -c "command")
# BASH_ENV is sourced before running scripts/commands
RUN echo 'eval "$(mise activate bash)"' > /etc/mise-activate.sh
ENV BASH_ENV=/etc/mise-activate.sh

# Intercept package managers - guide agents to use mise instead
# (Container runs as non-root, so apt would fail anyway)
RUN printf '%s\n' \
    '#!/bin/bash' \
    'echo "Error: Package manager not available (non-root container)"' \
    'echo ""' \
    'echo "Use mise to install languages and tools:"' \
    'echo "  mise install go@latest"' \
    'echo "  mise install python@3.12"' \
    'echo "  mise install rust@latest"' \
    'echo ""' \
    'echo "List available versions: mise ls-remote go"' \
    'exit 1' \
    > /usr/local/bin/apt-get && chmod +x /usr/local/bin/apt-get \
    && cp /usr/local/bin/apt-get /usr/local/bin/apt \
    && cp /usr/local/bin/apt-get /usr/local/bin/yum \
    && cp /usr/local/bin/apt-get /usr/local/bin/dnf \
    && cp /usr/local/bin/apt-get /usr/local/bin/apk

CMD ["bash"]
