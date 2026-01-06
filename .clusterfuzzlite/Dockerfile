FROM gcr.io/oss-fuzz-base/base-builder-python

# Copy project
COPY . $SRC/safeyolo
WORKDIR $SRC/safeyolo

# Copy build script to expected location
COPY .clusterfuzzlite/build.sh $SRC/

# Install dependencies needed for fuzzing
RUN pip3 install mitmproxy pyyaml
