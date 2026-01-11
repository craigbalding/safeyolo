# Sinkhole server - captures all test traffic for inspection
#
# TLS certificates are mounted from ./certs/ (signed by test CA).
# This mirrors production where upstreams have CA-signed certificates.
FROM python:3.12-slim@sha256:a75662dfec8d90bd7161c91050be2e0a9b21d284f3b7a7253d5db25f7d583fb3

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.9.24 /uv /usr/local/bin/uv

WORKDIR /app

# Install dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

# Add uv venv to PATH
ENV PATH="/app/.venv/bin:$PATH"

# Copy server code
COPY *.py .

# Expose ports: 8080 HTTP, 443 HTTPS, 9999 control API
EXPOSE 8080 443 9999

# Run the sinkhole server
CMD ["python", "server.py"]
