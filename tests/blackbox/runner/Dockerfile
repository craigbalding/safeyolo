# Test runner - pytest-based black box test suite
#
# Build context is repo root (for workspace lockfile access)
FROM python:3.12-slim@sha256:a75662dfec8d90bd7161c91050be2e0a9b21d284f3b7a7253d5db25f7d583fb3

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.9.24 /uv /usr/local/bin/uv

# Install dependencies to /opt (not affected by /app volume mount)
COPY pyproject.toml uv.lock /opt/deps/
COPY cli/pyproject.toml /opt/deps/cli/
COPY tests/blackbox/runner/pyproject.toml /opt/deps/tests/blackbox/runner/
COPY tests/blackbox/sinkhole/pyproject.toml /opt/deps/tests/blackbox/sinkhole/
RUN cd /opt/deps && uv sync --frozen --package safeyolo-blackbox-runner
ENV PATH="/opt/deps/.venv/bin:$PATH"

WORKDIR /app

# Copy test code
COPY tests/blackbox/runner/*.py ./

# Default: run all tests with verbose output
# -p no:cacheprovider: disable cache (volume is read-only)
CMD ["pytest", "-v", "--tb=short", "--timeout=60", "-p", "no:cacheprovider"]
