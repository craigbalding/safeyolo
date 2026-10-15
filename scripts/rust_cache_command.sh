#!/usr/bin/env bash
set -euo pipefail

# rust-cache v2.9.2 hashes every installed toolchain. These jobs compile with
# RUSTUP_TOOLCHAIN, exported before the cache action. Report that compiler only
# to its inventory query; keep its normal compiler, flags and lockfile hashing.
if [[ $# -eq 4 && $1 == rustup && $2 == toolchain && $3 == list && $4 == --quiet ]]; then
  printf '%s\n' "${RUSTUP_TOOLCHAIN:?Set RUSTUP_TOOLCHAIN before restoring the Rust cache}"
else
  exec "$@"
fi
