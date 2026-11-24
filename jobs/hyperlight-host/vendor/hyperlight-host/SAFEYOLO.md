# Build metadata without a wall-clock timestamp

Source: the Apache-2.0-licensed crates.io `hyperlight-host` 0.19.0 package,
upstream commit `a03088470d822b538d2525ef9a5ae9e29daea1e8`.
The published archive SHA-256 is
`48ed7feb4bdb2ea3fe07de299f9fb1cbc4246c91991d6ccc2a29eb387f7c7625`.
The upstream library, build script, tests, examples and benches are retained.
Standalone debugger and host performance-tuning scripts are omitted.
`LICENSE` and `NOTICE` contain the upstream texts also shipped in
SafeYolo's `jobs/licenses` directory.
Repository hooks normalize trailing whitespace in comments and README text.

The patch removes built's `chrono` feature from both manifests and removes
the sole `BUILT_TIME_UTC` log line in `src/lib.rs`. Builds no longer generate
or log that informational timestamp. The `build-metadata` feature and built's
`git2` feature remain enabled by the current Unikraft consumer. Package,
compiler, target, profile and available Git metadata still use the existing
build script. A local checkout can supply Git metadata from its containing
repository; a source archive can have no Git metadata.

Optional crashdump filenames now use Jiff's local clock and retain the
`hl_core_YYYYMMDD_THHMMSS.mmm.elf` form. Development tracing selects the local
`../tracing-forest` patch, which retains timestamped context trees using
maintained `time`. The standalone lockfile includes these optional and
development dependencies; it is separate from SafeYolo's selected normal/build
feature graph. The patch does not change backend selection, the guest ABI, or the helper's
identity format.
Upstream integration tests require their own guest fixtures and tools; the
SafeYolo helper's focused tests do not require those fixtures or a guest boot.

The standalone `Cargo.lock` is locally refreshed from the published archive.
It selects libz-sys 1.1.33 and rustix 1.1.6 to address the patchable advisories
in those selections. The source, license and notice remain those identified
above. The optional and development date consumers no longer require chrono.
It also selects url 2.5.9 and form_urlencoded 1.2.3 to address the nested
`blob:` origin stack overflow in RUSTSEC-2026-0592.
SafeYolo's helper dependencies use `jobs/hyperlight-host/Cargo.lock`, separately
from this standalone lock.
