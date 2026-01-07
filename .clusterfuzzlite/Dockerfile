FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:5d248948bebce11d057fca6db1f35245f5f67a7d670550a33f493985f67719c8

# Copy project
COPY . $SRC/safeyolo
WORKDIR $SRC/safeyolo

# Copy build script to expected location
COPY .clusterfuzzlite/build.sh $SRC/

# Install dependencies needed for fuzzing (detection module only)
RUN pip3 install pyyaml yarl
