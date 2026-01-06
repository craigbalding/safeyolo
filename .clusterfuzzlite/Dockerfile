FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:b00aa383709c30306257890b9fd23c5fff7079510bab86ba7e332ab5e04c27a4

# Copy project
COPY . $SRC/safeyolo
WORKDIR $SRC/safeyolo

# Copy build script to expected location
COPY .clusterfuzzlite/build.sh $SRC/

# Install dependencies needed for fuzzing (pinned with hashes)
RUN pip3 install --require-hashes -r requirements/fuzz.txt
