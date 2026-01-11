FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:5d248948bebce11d057fca6db1f35245f5f67a7d670550a33f493985f67719c8

# Install uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:0.9.24 /uv /usr/local/bin/uv

# Copy project
COPY . $SRC/safeyolo
WORKDIR $SRC/safeyolo

# Copy build script to expected location
COPY .clusterfuzzlite/build.sh $SRC/

# Install dependencies needed for fuzzing (detection module only)
COPY .clusterfuzzlite/pyproject.toml .clusterfuzzlite/uv.lock /tmp/fuzz/
RUN cd /tmp/fuzz && uv export --frozen --no-hashes | uv pip install --system -r -
