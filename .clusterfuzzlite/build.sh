#!/bin/bash -eu

# Build script for ClusterFuzzLite
# Builds Atheris fuzz targets for SafeYolo

cd $SRC/safeyolo

# Install the project in development mode
pip3 install -e .

# Copy fuzz targets to output
for fuzzer in fuzz/fuzz_*.py; do
    fuzzer_name=$(basename "$fuzzer" .py)
    cp "$fuzzer" "$OUT/$fuzzer_name"
    chmod +x "$OUT/$fuzzer_name"
done
